package com.samlscope.runner.result;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.Evaluator;
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
import com.samlscope.runner.FunctionalCaseFixtures;

class DefaultResultContextProviderTest {
    @Test
    void derivesTraceableUrlsAndMetadataDigestFromTheEvaluatedSnapshot() {
        var plan = plan();
        var run = new TestRun("run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.COMPLETED,
                Reachability.CONFIRMED, Map.of(), Instant.EPOCH, Instant.EPOCH);
        var catalog = new CoverageCatalog(List.of(new CoverageCatalog.Obligation(
                "REQ.a", "REQ", Rfc2119Level.MUST, List.of(TargetRole.IDP), null,
                CoverageCatalog.Testability.AUTOMATED, CoverageCatalog.ProfileScope.CORE)));
        var caseRun = CaseRun.completed("REQ-a-idp-01", "REQ.a",
                CaseOutcome.of(Outcome.SATISFIED, "ok", List.of()));
        var result = Evaluator.evaluateFunctionalCases(
                FunctionalCaseFixtures.forCases(FunctionalProfile.BROWSER_SSO_IDP, catalog,
                        Map.of("REQ-a-idp-01", "REQ.a")),
                catalog, List.of(), List.of(caseRun), List.of());
        var provider = new DefaultResultContextProvider(
                new ResultDocumentContext.Suite("SAMLscope", "0.1", digest('a'), "self-hosted"),
                new ResultDocumentContext.EvaluationComponents(digest('b'), digest('c'), digest('d'), "1", "1"),
                URI.create("https://docs.example/requirements"), URI.create("https://docs.example/cases"),
                snapshotRun -> {
                    assertEquals(run.id(), snapshotRun.id());
                    return "<md/>".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                });

        var context = provider.context(run, plan, List.of(caseRun), result);

        assertEquals("https://docs.example/requirements#REQ", context.requirementSpecUrls().get("REQ"));
        assertEquals("https://docs.example/cases#REQ-a-idp-01",
                context.caseDefinitionUrls().get("REQ-a-idp-01"));
        assertEquals(EvaluationArtifactDigests.digestBytes("<md/>".getBytes()), context.target().metadataDigest());
        assertThrows(IllegalStateException.class, () -> new DefaultResultContextProvider(
                context.suite(), context.evaluationComponents(), URI.create("https://docs.example/requirements"),
                URI.create("https://docs.example/cases"), ignored -> new byte[0])
                .context(run, plan, List.of(caseRun), result));
    }

    private TestPlan plan() {
        return new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example IdP", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Instant.EPOCH, Instant.EPOCH);
    }

    private String digest(char value) { return "sha256:" + String.valueOf(value).repeat(64); }
}
