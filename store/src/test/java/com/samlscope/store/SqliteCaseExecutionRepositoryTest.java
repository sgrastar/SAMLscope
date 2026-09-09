package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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

class SqliteCaseExecutionRepositoryTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String CASE_ID = "IIP-G03-a-idp-01";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");

    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS",
                "Outbox test",
                FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP,
                        "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL,
                Map.of(),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                NOW,
                NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        repository = new SqliteCaseExecutionRepository(database, json);
    }

    @Test
    void persistsStateAndSendIntentAtomicallyAndIdempotently() {
        var state = new CaseState("send", Map.of("attempt", 1));
        var execution = running(state);
        var action = action(state, new byte[] {1, 2, 3}, OutboundKind.AUTHN_REQUEST, false);

        assertTrue(repository.apply(-1, execution, List.of(action)));
        assertFalse(repository.apply(-1, execution, List.of(action)));

        assertEquals(execution, repository.find(RUN_ID, CASE_ID).orElseThrow());
        assertEquals(1, repository.listOutbox(RUN_ID).size());
        assertEquals(OutboxStatus.PENDING, repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void listsOnlyTheRequestedRunsExecutionsInStableCaseOrder() {
        var later = running(CaseState.initial());
        var earlier = new CaseExecution(
                RUN_ID, "IIP-G02-a-idp-01", 0, CaseExecutionStatus.RUNNING,
                CaseState.initial(), null, null, NOW);
        assertTrue(repository.apply(-1, later, List.of()));
        assertTrue(repository.apply(-1, earlier, List.of()));

        assertEquals(List.of("IIP-G02-a-idp-01", CASE_ID),
                repository.list(RUN_ID).stream().map(CaseExecution::caseId).toList());
        assertTrue(repository.list("run_99999999999999999999999999").isEmpty());
    }

    @Test
    void rejectsAnActionIdCollisionAndRollsBackTheStateChange() {
        var initial = new CaseState("send", Map.of("attempt", 1));
        var action = action(initial, new byte[] {1}, OutboundKind.AUTHN_REQUEST, false);
        assertTrue(repository.apply(-1, running(initial), List.of(action)));

        var changed = new CaseState("send", Map.of("attempt", 2));
        var collision = new OutboundAction(
                action.actionId(), action.kind(), new byte[] {9}, action.target(), false);
        assertThrows(StoreException.class, () -> repository.apply(
                0, running(1, changed), List.of(collision)));

        assertEquals(initial, repository.find(RUN_ID, CASE_ID).orElseThrow().state());
        assertEquals(List.of(1), bytes(repository.findOutbox(action.actionId()).orElseThrow().action().payload()));
    }

    @Test
    void recoversEveryInFlightSendAsUnknownDelivery() {
        var state = new CaseState("send", Map.of());
        var action = action(state, new byte[] {1}, OutboundKind.AUTHN_REQUEST, false);
        repository.apply(-1, running(state), List.of(action));
        assertTrue(repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, NOW.plusSeconds(1)));

        assertEquals(1, repository.recoverSendingAsUnknownDelivery(NOW.plusSeconds(2)));
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,
                repository.findOutbox(action.actionId()).orElseThrow().status());
    }

    @Test
    void compareAndSetPreventsConcurrentOutboxTransitions() {
        var state = new CaseState("send", Map.of());
        var action = action(state, new byte[] {1}, OutboundKind.METADATA_FETCH, false);
        repository.apply(-1, running(state), List.of(action));

        assertTrue(repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, NOW.plusSeconds(1)));
        assertFalse(repository.transitionOutbox(
                action.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, NOW.plusSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> repository.transitionOutbox(
                action.actionId(), OutboxStatus.SENDING, OutboxStatus.BLOCKED_ON_CREDENTIAL,
                Map.of(), null, NOW.plusSeconds(1)));
    }

    @Test
    void staleCaseRevisionCannotAdvanceStateOrInsertActions() {
        var initial = new CaseState("first", Map.of());
        assertTrue(repository.apply(-1, running(initial), List.of()));
        var winner = new CaseState("winner", Map.of());
        assertTrue(repository.apply(0, running(1, winner), List.of()));
        var stale = new CaseState("stale", Map.of());
        var staleAction = action(stale, new byte[] {7}, OutboundKind.AUTHN_REQUEST, false);

        assertFalse(repository.apply(0, running(1, stale), List.of(staleAction)));

        assertEquals(winner, repository.find(RUN_ID, CASE_ID).orElseThrow().state());
        assertTrue(repository.findOutbox(staleAction.actionId()).isEmpty());
    }

    private CaseExecution running(CaseState state) {
        return running(0, state);
    }

    private CaseExecution running(long revision, CaseState state) {
        return new CaseExecution(
                RUN_ID, CASE_ID, revision, CaseExecutionStatus.RUNNING, state, null, null, NOW);
    }

    private OutboundAction action(
            CaseState state, byte[] payload, OutboundKind kind, boolean credential) {
        return new OutboundAction(
                ActionIds.derive(RUN_ID, CASE_ID, state.phase(), 0),
                kind,
                payload,
                URI.create("https://target.example/endpoint"),
                credential);
    }

    private List<Integer> bytes(byte[] value) {
        var result = new java.util.ArrayList<Integer>();
        for (var item : value) result.add((int) item);
        return result;
    }
}
