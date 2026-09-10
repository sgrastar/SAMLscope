package com.samlscope.core.evaluation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.Basis;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.EffectiveResult;
import com.samlscope.core.evaluation.CoverageCatalog.Obligation;
import com.samlscope.core.evaluation.CoverageCatalog.ProfileScope;
import com.samlscope.core.evaluation.CoverageCatalog.Testability;
import com.samlscope.core.evaluation.RunResult.Completeness;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.plan.TargetRole;

class EvaluatorTest {
    @Test
    void keepsShouldViolationOutOfFailAndSurfacesWarning() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.SHOULD, Testability.AUTOMATED, ProfileScope.CORE, null));

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(), List.of(
                completed("case-a", "REQ.a", Outcome.SATISFIED),
                completed("case-b", "REQ.b", Outcome.VIOLATED)), List.of());

        assertEquals(Conformance.CONFORMANT_WITH_WARNINGS, result.conformance());
        assertEquals(Completeness.COMPLETE, result.completeness());
        assertEquals(Verdict.WARNING, result.obligations().get(1).verdict());
    }

    @Test
    void unresolvedShouldMakesCompletenessIncompleteButNotConformanceIndeterminate() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.SHOULD, Testability.AUTOMATED, ProfileScope.CORE, null));

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(), List.of(
                completed("case-a", "REQ.a", Outcome.SATISFIED),
                CaseRun.completed("case-b", "REQ.b", CaseOutcome.notVerified("timeout", "case.timeout"))), List.of());

        assertEquals(Conformance.CONFORMANT, result.conformance());
        assertEquals(Completeness.INCOMPLETE, result.completeness());
    }

    @Test
    void conflictIsInjectedIndependentlyAndFailStillWins() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "feature"));
        var applicability = new ApplicabilityEvaluation(
                "REQ.a", "feature", PredicateKind.CAPABILITY_BASED, false, true,
                EffectiveResult.TRUE, true, Basis.OBSERVED, List.of("metadata:feature"), null);

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(applicability),
                List.of(completed("case-a", "REQ.a", Outcome.VIOLATED)), List.of());

        assertEquals(Verdict.FAIL, result.obligations().getFirst().verdict());
        assertEquals(Conformance.NON_CONFORMANT, result.conformance());
    }

    @Test
    void falseConditionalObligationIsNotApplicableAndMustNotExecute() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "feature"));
        var applicability = new ApplicabilityEvaluation(
                "REQ.a", "feature", PredicateKind.CAPABILITY_BASED, false, false,
                EffectiveResult.FALSE, false, Basis.OBSERVED, List.of("probe:negative"), null);

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(applicability), List.of(), List.of());
        assertEquals(Verdict.NOT_APPLICABLE, result.obligations().getFirst().verdict());
        assertEquals(Conformance.CONFORMANT, result.conformance());

        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                catalog,
                List.of(applicability),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)),
                List.of()));
    }

    @Test
    void unknownApplicabilityCannotBeSilentlyExcluded() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "feature"));
        var unknown = new ApplicabilityEvaluation(
                "REQ.a", "feature", PredicateKind.CAPABILITY_BASED, false, null,
                EffectiveResult.UNKNOWN, false, Basis.DECLARED, List.of(), null);

        var result = Evaluator.evaluateSelectedObligations(
                catalog, List.of(unknown), List.of(), List.of());

        assertEquals(Verdict.NOT_VERIFIED, result.obligations().getFirst().verdict());
        assertEquals(Conformance.INDETERMINATE, result.conformance());
        assertEquals(Completeness.INCOMPLETE, result.completeness());
        assertEquals(1, result.coverage().obligationsTotal());
        assertEquals(1, result.coverage().obligationsApplicable());
        assertEquals(1, result.coverage().mustApplicable());
        assertEquals(1, result.coverage().applicabilityFromDeclarationOnly());
        assertEquals(1, result.coverage().mustUnresolved());
    }

    @Test
    void rejectsMissingMismatchedOrUnconditionalApplicabilityInputs() {
        var conditional = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "feature"));
        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                conditional, List.of(), List.of(), List.of()));

        var wrongPredicate = new ApplicabilityEvaluation(
                "REQ.a", "other", PredicateKind.CAPABILITY_BASED, true, null,
                EffectiveResult.TRUE, false, Basis.DECLARED, List.of(), null);
        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                conditional, List.of(wrongPredicate), List.of(), List.of()));

        var unconditional = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));
        var injectedExclusion = new ApplicabilityEvaluation(
                "REQ.a", "classification", PredicateKind.CLASSIFICATION_BASED, false, null,
                EffectiveResult.FALSE, false, Basis.DECLARATION_ONLY_EXCLUSION, List.of(),
                new ApplicabilityInput.ExclusionDeclaration(
                        "Injected exclusion", "operator", Instant.parse("2026-08-29T00:00:00Z")));
        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                unconditional, List.of(injectedExclusion), List.of(), List.of()));
    }

    @Test
    void declarationOnlyExclusionIsVisibleInTheConformanceEnum() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "classification"));
        var exclusionDeclaration = new ApplicabilityInput.ExclusionDeclaration(
                "Target is a classified proxy", "operator", Instant.parse("2026-08-29T00:00:00Z"));
        var exclusion = new ApplicabilityEvaluation(
                "REQ.b", "classification", PredicateKind.CLASSIFICATION_BASED, false, null,
                EffectiveResult.FALSE, false, Basis.DECLARATION_ONLY_EXCLUSION,
                List.of("attestation:proxy"), exclusionDeclaration);

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(exclusion),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)), List.of());

        assertEquals(Conformance.CONFORMANT_WITH_DECLARED_EXCLUSIONS, result.conformance());
        assertEquals(1, result.coverage().excludedByDeclaration());
        assertEquals(1, result.coverage().applicabilityFromDeclarationOnly());
        assertEquals(1, result.scopeQualifications().size());
        assertEquals(List.of("REQ.b"), result.scopeQualifications().getFirst().excludedObligations());
        assertEquals("Target is a classified proxy", result.scopeQualifications().getFirst().reason());
        assertEquals(false, result.scopeQualifications().getFirst().verified());
    }

    @Test
    void groupsExclusionScopeMechanicallyAndRejectsConflictingDeclarations() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "classification"),
                obligation("REQ.c", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, "classification"));
        var first = new ApplicabilityInput.ExclusionDeclaration(
                "Target is in the excluded class", "operator", Instant.parse("2026-08-29T00:00:00Z"));
        var second = new ApplicabilityInput.ExclusionDeclaration(
                "Different reason", "operator", Instant.parse("2026-08-29T00:00:00Z"));
        var exclusionB = exclusion("REQ.b", first);
        var exclusionC = exclusion("REQ.c", first);

        var result = Evaluator.evaluateSelectedObligations(
                catalog, List.of(exclusionB, exclusionC),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)), List.of());
        assertEquals(List.of("REQ.b", "REQ.c"),
                result.scopeQualifications().getFirst().excludedObligations());

        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                catalog, List.of(exclusionB, exclusion("REQ.c", second)),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)), List.of()));
    }

    @Test
    void notObservableMustIsOutsideTheConformanceDenominator() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.MUST, Testability.NOT_OBSERVABLE, ProfileScope.CORE, null));

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)), List.of());

        assertEquals(Conformance.CONFORMANT, result.conformance());
        assertEquals(1, result.coverage().mustObservable());
        assertEquals(1, result.coverage().mustNotObservable());
        assertEquals(1.0, result.coverage().verifiedRatio());
    }

    @Test
    void reportsEveryRequiredCoverageDenominatorFromSelectedApplicableObligations() {
        var catalog = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.MUST, Testability.ATTESTED, ProfileScope.CORE, null),
                obligation("REQ.c", Rfc2119Level.MUST, Testability.NOT_OBSERVABLE, ProfileScope.CORE, null),
                obligation("REQ.d", Rfc2119Level.SHOULD, Testability.AUTOMATED, ProfileScope.CORE, "feature"));
        var notApplicable = new ApplicabilityEvaluation(
                "REQ.d", "feature", PredicateKind.CAPABILITY_BASED, false, false,
                EffectiveResult.FALSE, false, Basis.OBSERVED, List.of("probe:negative"), null);

        var result = Evaluator.evaluateSelectedObligations(
                catalog,
                List.of(notApplicable),
                List.of(
                        completed("case-a", "REQ.a", Outcome.SATISFIED),
                        completed("case-b", "REQ.b", Outcome.SATISFIED)),
                List.of());

        assertEquals(4, result.coverage().obligationsTotal());
        assertEquals(3, result.coverage().obligationsApplicable());
        assertEquals(3, result.coverage().mustApplicable());
        assertEquals(2, result.coverage().mustObservable());
        assertEquals(2, result.coverage().mustResolved());
        assertEquals(0, result.coverage().mustUnresolved());
        assertEquals(1, result.coverage().mustNotObservable());
        assertEquals(1, result.coverage().attestedObligations());
        assertEquals(0, result.coverage().applicabilityFromDeclarationOnly());
        assertEquals(0, result.coverage().excludedByDeclaration());
        assertEquals(1.0, result.coverage().verifiedRatio());
    }

    @Test
    void evaluatesOnlyTheExplicitlySelectedObligations() {
        var source = catalog(
                obligation("REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null),
                obligation("REQ.b", Rfc2119Level.SHOULD, Testability.AUTOMATED, ProfileScope.FULL, null));
        var selected = catalog(source.obligations().getFirst());

        var result = Evaluator.evaluateSelectedObligations(selected, List.of(),
                List.of(completed("case-a", "REQ.a", Outcome.SATISFIED)), List.of());

        assertEquals(List.of("REQ.a"), result.obligations().stream().map(RunResult.ObligationResult::key).toList());
    }

    @Test
    void suiteErrorIsNotMisreportedAsATargetViolation() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));

        var result = Evaluator.evaluateSelectedObligations(catalog, List.of(),
                List.of(CaseRun.suiteError("case-a", "REQ.a", "runner crashed")),
                List.of(new SuiteIncident("INTERNAL_ERROR", "case-a", null, "runner crashed")));

        assertEquals(Verdict.ERROR, result.obligations().getFirst().verdict());
        assertEquals(Conformance.INDETERMINATE, result.conformance());
        assertEquals(Completeness.INCOMPLETE, result.completeness());
    }

    @Test
    void unknownDeliveryRemainsSuiteUncertaintyRatherThanTargetFailure() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));
        var incident = new SuiteIncident("UNKNOWN_DELIVERY", "case-a", "action-1", "delivery unknown");
        var caseRun = CaseRun.completed(
                "case-a",
                "REQ.a",
                CaseOutcome.notVerified("delivery_unknown", "outbox.delivery-unknown"));

        var result = Evaluator.evaluateSelectedObligations(
                catalog, List.of(), List.of(caseRun), List.of(incident));

        assertEquals(Verdict.NOT_VERIFIED, result.obligations().getFirst().verdict());
        assertEquals(Conformance.INDETERMINATE, result.conformance());
        assertEquals(0, result.coverage().verdictCounts().get(Verdict.FAIL));
        assertEquals(List.of(incident), result.suiteIncidents());
    }

    @Test
    void rejectsUnknownDeliveryThatWasTransferredIntoATargetViolation() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));
        var incident = new SuiteIncident("UNKNOWN_DELIVERY", "case-a", "action-1", "delivery unknown");

        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                catalog,
                List.of(),
                List.of(completed("case-a", "REQ.a", Outcome.VIOLATED)),
                List.of(incident)));
    }

    @Test
    void acceptsViolationProvenByADifferentConfirmedActionInTheSameScenario() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));
        var incident = new SuiteIncident("UNKNOWN_DELIVERY", "case-a", "action-1", "delivery unknown");
        var outcome = new CaseOutcome(
                Outcome.VIOLATED, null, "test", "test",
                List.of(new EvidenceRef("test", "evidence:action-2")),
                Map.of("violating_action_ids", List.of("action-2")));

        var result = Evaluator.evaluateSelectedObligations(
                catalog,
                List.of(),
                List.of(CaseRun.completed("case-a", "REQ.a", outcome)),
                List.of(incident));

        assertEquals(Verdict.FAIL, result.obligations().getFirst().verdict());
        assertEquals(List.of(incident), result.suiteIncidents());
    }

    @Test
    void rejectsViolationProvenByTheSameUnknownAction() {
        var catalog = catalog(obligation(
                "REQ.a", Rfc2119Level.MUST, Testability.AUTOMATED, ProfileScope.CORE, null));
        var incident = new SuiteIncident("UNKNOWN_DELIVERY", "case-a", "action-1", "delivery unknown");
        var outcome = new CaseOutcome(
                Outcome.VIOLATED, null, "test", "test",
                List.of(new EvidenceRef("test", "evidence:action-1")),
                Map.of("violating_action_ids", List.of("action-1")));

        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateSelectedObligations(
                catalog,
                List.of(),
                List.of(CaseRun.completed("case-a", "REQ.a", outcome)),
                List.of(incident)));
    }

    private static CaseRun completed(String id, String obligation, Outcome outcome) {
        return CaseRun.completed(id, obligation, CaseOutcome.of(
                outcome, "test", List.of(new EvidenceRef("test", "evidence:" + id))));
    }

    private static ApplicabilityEvaluation exclusion(
            String obligation, ApplicabilityInput.ExclusionDeclaration declaration) {
        return new ApplicabilityEvaluation(
                obligation, "classification", PredicateKind.CLASSIFICATION_BASED, false, null,
                EffectiveResult.FALSE, false, Basis.DECLARATION_ONLY_EXCLUSION,
                List.of("attestation:classification"), declaration);
    }

    private static CoverageCatalog catalog(Obligation... obligations) {
        return new CoverageCatalog(List.of(obligations));
    }

    private static Obligation obligation(
            String key,
            Rfc2119Level level,
            Testability testability,
            ProfileScope profileScope,
            String condition) {
        return new Obligation(key, key.substring(0, key.indexOf('.')), level,
                List.of(TargetRole.IDP), condition, testability, profileScope);
    }

}
