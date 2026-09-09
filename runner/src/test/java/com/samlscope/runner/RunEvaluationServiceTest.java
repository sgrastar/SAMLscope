package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.CoverageCatalog.Obligation;
import com.samlscope.core.evaluation.CoverageCatalog.ProfileScope;
import com.samlscope.core.evaluation.CoverageCatalog.Testability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.evaluation.SuiteIncident;
import com.samlscope.core.evaluation.Verdict;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class RunEvaluationServiceTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T05:00:00Z");

    @TempDir java.nio.file.Path directory;

    @Test
    void loadsTheRunAndPlanAndDelegatesAllDeterminationToEvaluator() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = plan();
        plans.save(plan);
        runs.save(new TestRun(
                RUN_ID, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        var catalog = new CoverageCatalog(List.of(
                obligation("REQ.a", Rfc2119Level.MUST, TargetRole.IDP, ProfileScope.CORE),
                obligation("REQ.b", Rfc2119Level.SHOULD, TargetRole.IDP, ProfileScope.FULL),
                obligation("REQ.c", Rfc2119Level.MUST, TargetRole.SP, ProfileScope.CORE)));
        var incident = new SuiteIncident("NOTICE", "case-a", null, "test incident");
        var service = new RunEvaluationService(
                catalog, plans, runs,
                ignored -> List.of(
                        CaseRun.completed(
                                "case-a", "REQ.a", CaseOutcome.of(Outcome.SATISFIED, "a", List.of())),
                        CaseRun.completed(
                                "case-b", "REQ.b", CaseOutcome.of(Outcome.VIOLATED, "b", List.of()))),
                (run, sourcePlan) -> List.of(),
                ignored -> List.of(incident),
                ignored -> FunctionalCaseFixtures.forCases(
                        FunctionalProfile.BROWSER_SSO_IDP, catalog,
                        Map.of("case-a", "REQ.a", "case-b", "REQ.b")));

        var result = service.evaluate(RUN_ID);

        assertEquals(Conformance.CONFORMANT_WITH_WARNINGS, result.conformance());
        assertEquals(2, result.obligations().size());
        assertEquals(Verdict.PASS, result.obligations().get(0).verdict());
        assertEquals(Verdict.WARNING, result.obligations().get(1).verdict());
        assertEquals(List.of(incident), result.suiteIncidents());
        assertThrows(IllegalArgumentException.class, () -> service.evaluate("missing"));
    }

    private Obligation obligation(
            String key, Rfc2119Level level, TargetRole role, ProfileScope scope) {
        return new Obligation(
                key, "REQ", level, List.of(role), null, Testability.AUTOMATED, scope);
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Evaluation service test", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }
}
