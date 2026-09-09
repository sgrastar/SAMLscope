package com.samlscope.runner.outbox;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;
import com.samlscope.runner.OutboundPolicy;

class OutboundDispatcherTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String CASE_ID = "case-outbox";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Dispatcher test", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
    }

    @Test
    void unsafeUnknownDeliveryIsNeverResent() {
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING, Map.of(), null, NOW);
        repository.recoverSendingAsUnknownDelivery(NOW);
        var sends = new AtomicInteger();
        var dispatcher = dispatcher((runId, ignored, credential) -> {
            sends.incrementAndGet();
            return success();
        }, Optional.empty());

        var result = dispatcher.dispatch(action.actionId());

        assertEquals(OutboundDispatcher.State.UNKNOWN_DELIVERY, result.state());
        assertEquals(0, sends.get());
        assertEquals("UNKNOWN_DELIVERY", result.incidents().getFirst().kind());
    }

    @Test
    void safeUnknownDeliveryMayBeRetriedByRunnerPolicy() {
        var action = persist(OutboundKind.METADATA_FETCH, false);
        repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING, Map.of(), null, NOW);
        repository.recoverSendingAsUnknownDelivery(NOW);
        var sends = new AtomicInteger();
        var dispatcher = dispatcher((runId, ignored, credential) -> {
            sends.incrementAndGet();
            return success();
        }, Optional.empty());

        assertEquals(OutboundDispatcher.State.SENT, dispatcher.dispatch(action.actionId()).state());
        assertEquals(1, sends.get());
        assertEquals(OutboxStatus.SENT, repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void credentialsBlockAfterRestartAndNeverReachPersistentStorage() throws Exception {
        var action = persist(OutboundKind.ECP_SOAP, true);
        var blocked = dispatcher((runId, ignored, credential) -> success(), Optional.empty());
        assertEquals(OutboundDispatcher.State.BLOCKED_ON_CREDENTIAL, blocked.dispatch(action.actionId()).state());

        var secret = "ephemeral-only-secret".getBytes(StandardCharsets.UTF_8);
        var sent = dispatcher((runId, ignored, credential) -> {
            assertArrayEquals(secret, credential);
            return success();
        }, Optional.of(secret));
        assertEquals(OutboundDispatcher.State.SENT, sent.dispatch(action.actionId()).state());

        var persisted = new String(readAll(directory), StandardCharsets.ISO_8859_1);
        assertEquals(false, persisted.contains(new String(secret, StandardCharsets.UTF_8)));
    }

    @Test
    void sendFailureBecomesSuiteUncertainty() {
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        var dispatcher = dispatcher((runId, ignored, credential) -> {
            throw new java.io.IOException("connection reset after write");
        }, Optional.empty());

        var result = dispatcher.dispatch(action.actionId());

        assertEquals(OutboundDispatcher.State.UNKNOWN_DELIVERY, result.state());
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void replayRejectionAfterDispatchNeverBecomesATargetVerdict() {
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        var dispatcher = dispatcher(
                (runId, ignored, credential) -> new OutboundSender.SendResult(
                        true, Map.of("saml_status", "Requester"), "tx-replay"),
                Optional.empty());

        var result = dispatcher.dispatch(action.actionId());

        assertEquals(OutboundDispatcher.State.UNKNOWN_DELIVERY, result.state());
        assertEquals("UNKNOWN_DELIVERY", result.incidents().getFirst().kind());
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void inboundResponseConfirmsDeliveryWithoutResending() {
        var sends = new java.util.concurrent.atomic.AtomicInteger();
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        assertTrue(repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, NOW));
        repository.recoverSendingAsUnknownDelivery(NOW.plusSeconds(1));
        var dispatcher = dispatcher((runId, ignored, credential) -> {
            sends.incrementAndGet();
            return success();
        }, Optional.empty());

        var result = dispatcher.confirmInboundDelivery(action.actionId(), "tx-response");

        assertEquals(OutboundDispatcher.State.SENT, result.state());
        assertEquals(0, sends.get());
        var stored = repository.findOutbox(action.actionId()).orElseThrow();
        assertEquals(OutboxStatus.SENT, stored.status());
        assertEquals("tx-response", stored.transcriptEntryId());
    }

    @Test
    void browserFrontChannelIsPersistedAsUnknownUntilInboundAndCannotBeReplayed() {
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        var dispatcher = dispatcher((runId, ignored, credential) -> success(), Optional.empty());

        var handedOff = dispatcher.dispatchFrontChannel(action.actionId(), ignored -> "tx-front-channel");

        assertEquals(action.actionId(), handedOff.action().actionId());
        assertArrayEquals(action.payload(), handedOff.action().payload());
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                repository.findOutbox(action.actionId()).orElseThrow().status());
        assertThrows(IllegalStateException.class,
                () -> dispatcher.dispatchFrontChannel(action.actionId(), ignored -> "tx-replay"));
        dispatcher.confirmInboundDelivery(action.actionId(), "tx-response");
        assertEquals(OutboxStatus.SENT,
                repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void failedBrowserHandoffBecomesUnknownAndCannotBeRetried() {
        var action = persist(OutboundKind.AUTHN_REQUEST, false);
        var dispatcher = dispatcher((runId, ignored, credential) -> success(), Optional.empty());

        assertThrows(IllegalStateException.class, () -> dispatcher.dispatchFrontChannel(
                action.actionId(), ignored -> { throw new IllegalStateException("render failed"); }));

        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                repository.findOutbox(action.actionId()).orElseThrow().status());
        assertThrows(IllegalStateException.class,
                () -> dispatcher.dispatchFrontChannel(action.actionId(), ignored -> "tx-replay"));
    }

    private OutboundAction persist(OutboundKind kind, boolean credential) {
        var state = new CaseState("send", Map.of());
        var action = new OutboundAction(
                ActionIds.derive(RUN_ID, CASE_ID, state.phase(), 0), kind,
                "<Envelope/>".getBytes(StandardCharsets.UTF_8),
                URI.create("https://target.example/endpoint"), credential);
        repository.apply(-1, new CaseExecution(
                RUN_ID, CASE_ID, 0, CaseExecutionStatus.RUNNING, state, null, null, NOW), List.of(action));
        return action;
    }

    private OutboundDispatcher dispatcher(OutboundSender sender, Optional<byte[]> credential) {
        return new OutboundDispatcher(
                repository,
                sender,
                (runId, actionId) -> credential.map(byte[]::clone),
                new OutboundPolicy(true),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private OutboundSender.SendResult success() {
        return new OutboundSender.SendResult(false, Map.of("status", 200), "tx-1");
    }

    private byte[] readAll(java.nio.file.Path root) throws Exception {
        var output = new java.io.ByteArrayOutputStream();
        try (var paths = Files.walk(root)) {
            for (var path : paths.filter(Files::isRegularFile).toList()) {
                output.write(Files.readAllBytes(path));
            }
        }
        return output.toByteArray();
    }
}
