package com.samlscope.runner.outbox;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.OutboundPolicy;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class EcpProbeServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;
    private InMemoryEphemeralCredentialProvider credentials;

    @BeforeEach
    void setUp() {
        var json = new JsonCodec();
        var database = new SqliteDatabase(directory);
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "ECP probe", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
        credentials = new InMemoryEphemeralCredentialProvider();
    }

    @Test
    void persistsOnlyTheEnvelopeAndConsumesTheCredentialThroughTheDispatcher() {
        var secret = "alice:secret".getBytes(StandardCharsets.UTF_8);
        var sender = (OutboundSender) (runId, action, credential) -> {
            assertEquals(RUN, runId);
            assertArrayEquals(secret, credential);
            assertTrue(new String(action.payload(), StandardCharsets.UTF_8).contains("Envelope"));
            return new OutboundSender.SendResult(false, Map.of("status", 200), "tx-response");
        };
        var dispatcher = new OutboundDispatcher(
                repository, sender, credentials, new OutboundPolicy(true),
                Clock.fixed(NOW, ZoneOffset.UTC));
        var service = new EcpProbeService(
                repository, credentials, dispatcher, Clock.fixed(NOW, ZoneOffset.UTC));

        var result = service.execute(
                RUN, URI.create("https://idp.example/ecp"),
                "<Envelope/>".getBytes(StandardCharsets.UTF_8), secret);

        assertEquals(OutboundDispatcher.State.SENT, result.dispatchState());
        assertEquals(OutboxStatus.SENT, result.outboxStatus());
        assertEquals("tx-response", result.responseTranscriptId());
        assertTrue(credentials.credentialFor(RUN, result.actionId()).isEmpty());
        var action = repository.findOutbox(result.actionId()).orElseThrow().action();
        assertEquals(true, action.requiresEphemeralCredential());
        assertEquals(false, new String(action.payload(), StandardCharsets.UTF_8).contains("secret"));
    }

    @Test
    void requiresEveryApprovedEcpFixtureToBeSentBeforeTheMilestoneCanStart() {
        var secret = "alice:secret".getBytes(StandardCharsets.UTF_8);
        var sender = (OutboundSender) (runId, action, credential) ->
                new OutboundSender.SendResult(false, Map.of("status", 200), "tx-" + action.actionId());
        var dispatcher = new OutboundDispatcher(
                repository, sender, credentials, new OutboundPolicy(true),
                Clock.fixed(NOW, ZoneOffset.UTC));
        var service = new EcpProbeService(
                repository, credentials, dispatcher, Clock.fixed(NOW, ZoneOffset.UTC));

        assertEquals(7, EcpProbeService.requiredFixtureIds().size());
        assertFalse(EcpProbeService.allRequiredFixturesSent(repository, RUN));
        service.execute(RUN, URI.create("https://idp.example/ecp"),
                "<Envelope/>".getBytes(StandardCharsets.UTF_8), secret);
        assertFalse(EcpProbeService.allRequiredFixturesSent(repository, RUN));

        for (var fixtureId : EcpProbeService.requiredFixtureIds()) {
            service.execute(RUN, fixtureId, URI.create("https://idp.example/ecp"),
                    "<Envelope/>".getBytes(StandardCharsets.UTF_8), secret);
        }

        assertTrue(EcpProbeService.allRequiredFixturesSent(repository, RUN));
        assertTrue(EcpProbeService.requiredFixtureIds().stream()
                .map(fixtureId -> EcpProbeService.actionId(RUN, fixtureId))
                .allMatch(actionId -> repository.findOutbox(actionId)
                        .map(entry -> entry.status() == OutboxStatus.SENT)
                        .orElse(false)));
    }
}
