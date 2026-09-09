package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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

class OutboxIncidentProjectionTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T05:00:00Z");

    @TempDir java.nio.file.Path directory;

    @Test
    void reconstructsOnlyDurableUnknownDeliveryIncidents() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = plan();
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        var repository = new SqliteCaseExecutionRepository(database, json);
        var unknown = action("action-unknown");
        var pending = action("action-pending");
        repository.apply(-1, execution("IIP-G03-a-idp-01"), List.of(unknown, pending));
        repository.transitionOutbox(
                unknown.actionId(), OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, NOW.plusSeconds(1));
        repository.transitionOutbox(
                unknown.actionId(), OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                Map.of("exception_type", "java.io.IOException"), null, NOW.plusSeconds(2));

        var incidents = new OutboxIncidentProjection(repository).incidents(RUN_ID);

        assertEquals(1, incidents.size());
        assertEquals("UNKNOWN_DELIVERY", incidents.getFirst().kind());
        assertEquals("IIP-G03-a-idp-01", incidents.getFirst().caseId());
        assertEquals("action-unknown", incidents.getFirst().actionId());
    }

    private CaseExecution execution(String caseId) {
        return new CaseExecution(
                RUN_ID, caseId, 0, CaseExecutionStatus.RUNNING,
                new CaseState("send", Map.of()), null, null, NOW);
    }

    private OutboundAction action(String id) {
        return new OutboundAction(
                id, OutboundKind.AUTHN_REQUEST, new byte[] {1}, URI.create("https://idp.example/sso"), false);
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Outbox incident test", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
