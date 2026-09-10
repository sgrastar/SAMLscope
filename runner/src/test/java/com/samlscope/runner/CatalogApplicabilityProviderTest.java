package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.EffectiveResult;
import com.samlscope.core.evaluation.ApplicabilityInput;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.CoverageCatalog.Obligation;
import com.samlscope.core.evaluation.CoverageCatalog.ProfileScope;
import com.samlscope.core.evaluation.CoverageCatalog.Testability;
import com.samlscope.core.evaluation.PredicateCatalog;
import com.samlscope.core.evaluation.PredicateCatalog.ConflictPolicy;
import com.samlscope.core.evaluation.PredicateKind;
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

class CatalogApplicabilityProviderTest {
    private static final Instant NOW = Instant.parse("2026-08-29T12:00:00Z");

    @Test
    void evaluatesOnlySelectedConditionalObligationsAndReadsSharedInputOnce() {
        var coverage = new CoverageCatalog(List.of(
                obligation("REQ.a", TargetRole.IDP, ProfileScope.CORE, "feature"),
                obligation("REQ.b", TargetRole.IDP, ProfileScope.FULL, "feature"),
                obligation("REQ.c", TargetRole.SP, ProfileScope.CORE, "feature"),
                obligation("REQ.d", TargetRole.IDP, ProfileScope.CORE, null)));
        var calls = new AtomicInteger();
        var provider = new CatalogApplicabilityProvider(
                coverage,
                new PredicateCatalog(List.of(definition("feature", PredicateKind.CAPABILITY_BASED))),
                (definition, run, plan) -> {
                    calls.incrementAndGet();
                    return new ApplicabilityInput(false, true, List.of("transcript:1"), null);
                }, ignored -> FunctionalCaseFixtures.forObligations(
                        FunctionalProfile.BROWSER_SSO_IDP, coverage, "REQ.a", "REQ.b"));

        var evaluations = provider.evaluations(run(), plan());

        assertEquals(2, evaluations.size());
        assertEquals(List.of("REQ.a", "REQ.b"),
                evaluations.stream().map(value -> value.obligationKey()).toList());
        assertEquals(1, calls.get());
        assertEquals(EffectiveResult.TRUE, evaluations.get(0).effectiveResult());
        assertEquals(true, evaluations.get(0).conflict());
    }

    @Test
    void representsMissingKnowledgeAsUnknownInsteadOfInventingFalse() {
        var coverage = new CoverageCatalog(List.of(
                obligation("REQ.a", TargetRole.IDP, ProfileScope.CORE, "feature")));
        var provider = new CatalogApplicabilityProvider(
                coverage,
                new PredicateCatalog(List.of(definition("feature", PredicateKind.CAPABILITY_BASED))),
                (definition, run, plan) -> new ApplicabilityInput(null, null, List.of(), null),
                ignored -> FunctionalCaseFixtures.forObligations(
                        FunctionalProfile.BROWSER_SSO_IDP, coverage, "REQ.a"));

        var evaluation = provider.evaluations(run(), plan()).get(0);

        assertEquals(EffectiveResult.UNKNOWN, evaluation.effectiveResult());
    }

    @Test
    void failsClosedWhenCoverageReferencesUnknownPredicateOrInputProviderReturnsNull() {
        var coverage = new CoverageCatalog(List.of(
                obligation("REQ.a", TargetRole.IDP, ProfileScope.CORE, "missing")));
        assertThrows(IllegalArgumentException.class, () -> new CatalogApplicabilityProvider(
                coverage, new PredicateCatalog(List.of(definition("other", PredicateKind.CLAIM_BASED))),
                (definition, run, plan) -> new ApplicabilityInput(null, null, List.of(), null),
                ignored -> FunctionalCaseFixtures.forObligations(
                        FunctionalProfile.BROWSER_SSO_IDP, coverage, "REQ.a")));

        var provider = new CatalogApplicabilityProvider(
                coverage,
                new PredicateCatalog(List.of(definition("missing", PredicateKind.CLAIM_BASED))),
                (definition, run, plan) -> null,
                ignored -> FunctionalCaseFixtures.forObligations(
                        FunctionalProfile.BROWSER_SSO_IDP, coverage, "REQ.a"));
        assertThrows(NullPointerException.class, () -> provider.evaluations(run(), plan()));
    }

    private Obligation obligation(String key, TargetRole role, ProfileScope scope, String condition) {
        return new Obligation(
                key, "REQ", Rfc2119Level.MUST, List.of(role), condition, Testability.AUTOMATED, scope);
    }

    private PredicateCatalog.Definition definition(String key, PredicateKind kind) {
        return new PredicateCatalog.Definition(
                key, kind, List.of("declared.feature"), List.of("observed.feature"),
                ConflictPolicy.INCONSISTENT, null);
    }

    private TestPlan plan() {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Applicability", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private TestRun run() {
        return new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", "plan_0123456789ABCDEFGHJKMNPQRS",
                RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }
}
