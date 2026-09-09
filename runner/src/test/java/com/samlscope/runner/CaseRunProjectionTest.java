package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
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

class CaseRunProjectionTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    @TempDir java.nio.file.Path directory;
    private SqliteCaseExecutionRepository repository;

    @BeforeEach
    void setUp() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Projection", FunctionalProfile.BROWSER_SSO_IDP,
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
    void projectsFinishedAndPendingRegisteredCasesInStableOrder() {
        persist(finished("IIP-SSO01-aa-idp-01", Outcome.SATISFIED));
        persist(running("IIP-SSO01-ab-idp-01"));
        persist(finished("IIP-G03-a-idp-01", Outcome.VIOLATED));
        var projection = new CaseRunProjection(repository, registry(
                "IIP-SSO01-aa-idp-01", "IIP-SSO01-ab-idp-01", "IIP-G03-a-idp-01"));

        var result = projection.completed(RUN_ID);

        assertEquals(List.of("IIP-G03-a-idp-01", "IIP-SSO01-aa-idp-01", "IIP-SSO01-ab-idp-01"),
                result.stream().map(value -> value.id()).toList());
        assertEquals(List.of("IIP-G03.a", "IIP-SSO01.aa", "IIP-SSO01.ab"),
                result.stream().map(value -> value.obligationKey()).toList());
        assertEquals(List.of(Outcome.VIOLATED, Outcome.SATISFIED, Outcome.NOT_VERIFIED),
                result.stream().map(value -> value.outcome().outcome()).toList());
        assertEquals("case_in_progress", result.get(2).outcome().notVerifiedReason());
    }

    @Test
    void failsClosedWhenPersistenceContainsAnUnregisteredCase() {
        persist(finished("IIP-G03-a-idp-01", Outcome.SATISFIED));

        assertThrows(IllegalArgumentException.class,
                () -> new CaseRunProjection(repository, registry()).completed(RUN_ID));
    }

    private void persist(CaseExecution execution) {
        repository.apply(-1, execution, List.of());
    }

    private CaseExecution finished(String id, Outcome outcome) {
        return new CaseExecution(RUN_ID, id, 0, CaseExecutionStatus.FINISHED,
                CaseState.initial(), null, CaseOutcome.of(outcome, "test", List.of()), NOW);
    }

    private CaseExecution running(String id) {
        return new CaseExecution(RUN_ID, id, 0, CaseExecutionStatus.RUNNING,
                new CaseState("running", Map.of()), null, null, NOW);
    }

    private TestCaseRegistry registry(String... ids) {
        return new TestCaseRegistry(java.util.Arrays.stream(ids).map(id -> new TestCase() {
            @Override public String id() { return id; }
            @Override public TargetRole role() { return TargetRole.IDP; }
            @Override public com.samlscope.core.caseexec.CaseStep start(
                    com.samlscope.core.caseexec.CaseContext context) { throw new UnsupportedOperationException(); }
            @Override public com.samlscope.core.caseexec.CaseStep resume(
                    com.samlscope.core.caseexec.CaseContext context,
                    com.samlscope.core.caseexec.CaseState state,
                    com.samlscope.core.caseexec.CaseEvent event) { throw new UnsupportedOperationException(); }
        }).toList());
    }
}
