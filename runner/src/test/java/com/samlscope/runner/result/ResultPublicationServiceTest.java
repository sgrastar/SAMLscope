package com.samlscope.runner.result;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.RunEvaluationService;
import com.samlscope.runner.FunctionalCaseFixtures;
import com.samlscope.store.FileRunArtifactRepository;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class ResultPublicationServiceTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-29T15:00:00Z");

    @TempDir java.nio.file.Path directory;

    @Test
    void evaluatesOnceAndPersistsTheExactPublicBytesWithoutUserHints() throws Exception {
        var database = new SqliteDatabase(directory);
        var plans = new SqlitePlanRepository(database, new JsonCodec());
        var runs = new SqliteRunRepository(database, new JsonCodec());
        var plan = plan();
        var run = new TestRun(RUN_ID, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED,
                Map.of(), NOW, NOW.plusSeconds(1));
        plans.save(plan);
        runs.save(run);
        var catalog = new CoverageCatalog(List.of(new CoverageCatalog.Obligation(
                "REQ.a", "REQ", Rfc2119Level.MUST, List.of(TargetRole.IDP), null,
                CoverageCatalog.Testability.AUTOMATED, CoverageCatalog.ProfileScope.CORE)));
        var caseRun = CaseRun.completed("REQ-a-idp-01", "REQ.a",
                CaseOutcome.of(Outcome.SATISFIED, "ok", List.of()));
        var evaluation = new RunEvaluationService(
                catalog, plans, runs, ignored -> List.of(caseRun), (ignoredRun, ignoredPlan) -> List.of(),
                ignored -> List.of(), ignored -> FunctionalCaseFixtures.forCases(
                        FunctionalProfile.BROWSER_SSO_IDP, catalog,
                        Map.of("REQ-a-idp-01", "REQ.a")));
        var repository = new FileRunArtifactRepository(directory);
        var service = new ResultPublicationService(
                catalog, evaluation, (sourceRun, sourcePlan, cases, result) -> context(),
                new ResultJsonWriter(), repository,
                new ReportHtmlWriter("license".getBytes(), "scope".getBytes(),
                        "{\"sources\":[],\"unresolved_sources\":[]}".getBytes()));

        var generated = service.generate(RUN_ID);

        assertArrayEquals(generated, service.require(RUN_ID));
        var report = new String(service.requireReport(RUN_ID), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(true, report.startsWith("<!doctype html>"));
        assertFalse(report.contains("private@example.test"));
        assertEquals(1, new ResultJsonWriter().mapper().readTree(generated).at("/summary/cases/total").asInt());
        assertFalse(new String(generated, java.nio.charset.StandardCharsets.UTF_8).contains("private@example.test"));
        assertThrows(IllegalArgumentException.class, () -> service.require("run_00000000000000000000000000"));
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Publication", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), new TestPlan.Parameters(180, 300, "private@example.test"),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private ResultDocumentContext context() {
        return new ResultDocumentContext(
                new ResultDocumentContext.Suite("SAMLscope", "0.1.0", digest('a'), "self-hosted"),
                new ResultDocumentContext.EvaluationComponents(digest('b'), digest('c'), digest('d'), "1", "1"),
                new ResultDocumentContext.ProfileSpec("IIP", "1.1", LocalDate.parse("2019-12-18"), "Core scope."),
                new ResultDocumentContext.TargetDeclaration("Example", "operator", digest('e')),
                Map.of("REQ", "https://example.test/spec#REQ"),
                Map.of("REQ-a-idp-01", "https://example.test/cases/REQ-a-idp-01"), List.of());
    }

    private String digest(char value) {
        return "sha256:" + String.valueOf(value).repeat(64);
    }
}
