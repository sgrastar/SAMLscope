package com.samlscope.core.evaluation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.Basis;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.EffectiveResult;
import com.samlscope.core.evaluation.CoverageCatalog.Obligation;
import com.samlscope.core.evaluation.CoverageCatalog.ProfileScope;
import com.samlscope.core.evaluation.CoverageCatalog.Testability;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.plan.TargetRole;

class RunResultInvariantValidatorTest {
    @Test
    void acceptsCanonicalEvaluatorOutput() {
        var fixture = fixture();
        assertDoesNotThrow(() -> RunResultInvariantValidator.validateSelectedObligations(
                fixture.catalog(), fixture.result()));
    }

    @Test
    void rejectsAConformantLabelWithAnUnresolvedMust() {
        var fixture = fixture();
        var corrupt = copy(fixture.result(), Conformance.CONFORMANT, fixture.result().coverage(),
                fixture.result().applicability(), fixture.result().scopeQualifications());
        assertThrows(IllegalStateException.class, () -> RunResultInvariantValidator.validateSelectedObligations(
                fixture.catalog(), corrupt));
    }

    @Test
    void rejectsIncorrectCoverageArithmetic() {
        var fixture = fixture();
        var source = fixture.result().coverage();
        var corruptCoverage = new RunResult.CoverageMetrics(
                source.obligationsTotal(), source.obligationsApplicable(), source.mustApplicable(),
                source.mustObservable(), source.mustResolved() + 1, source.mustUnresolved(),
                source.mustNotObservable(), source.attestedObligations(),
                source.applicabilityFromDeclarationOnly(), source.excludedByDeclaration(), source.verifiedRatio(),
                source.verdictCounts());
        var corrupt = copy(fixture.result(), fixture.result().conformance(), corruptCoverage,
                fixture.result().applicability(), fixture.result().scopeQualifications());
        assertThrows(IllegalStateException.class, () -> RunResultInvariantValidator.validateSelectedObligations(
                fixture.catalog(), corrupt));
    }

    @Test
    void rejectsMissingConditionalApplicabilityAndInventedScopeQualification() {
        var fixture = fixture();
        var missing = copy(fixture.result(), fixture.result().conformance(), fixture.result().coverage(),
                List.of(), fixture.result().scopeQualifications());
        assertThrows(IllegalStateException.class, () -> RunResultInvariantValidator.validateSelectedObligations(
                fixture.catalog(), missing));

        var qualification = new RunResult.ScopeQualification(
                "declared_exclusion", "invented", List.of("REQ.a"), "invented", "operator",
                Instant.parse("2026-08-29T00:00:00Z"), false);
        var invented = copy(fixture.result(), fixture.result().conformance(), fixture.result().coverage(),
                fixture.result().applicability(), List.of(qualification));
        assertThrows(IllegalStateException.class, () -> RunResultInvariantValidator.validateSelectedObligations(
                fixture.catalog(), invented));
    }

    private Fixture fixture() {
        var catalog = new CoverageCatalog(List.of(new Obligation(
                "REQ.a", "REQ", Rfc2119Level.MUST, List.of(TargetRole.IDP), "feature",
                Testability.AUTOMATED, ProfileScope.CORE)));
        var unknown = new ApplicabilityEvaluation(
                "REQ.a", "feature", PredicateKind.CAPABILITY_BASED, false, null,
                EffectiveResult.UNKNOWN, false, Basis.DECLARED, List.of(), null);
        return new Fixture(catalog, Evaluator.evaluateSelectedObligations(
                catalog, List.of(unknown), List.of(), List.of()));
    }

    private RunResult copy(
            RunResult source,
            Conformance conformance,
            RunResult.CoverageMetrics coverage,
            List<ApplicabilityEvaluation> applicability,
            List<RunResult.ScopeQualification> qualifications) {
        return new RunResult(
                conformance, source.completeness(), source.obligations(), source.requirements(), coverage,
                applicability, qualifications, source.suiteIncidents());
    }

    private record Fixture(CoverageCatalog catalog, RunResult result) {}
}
