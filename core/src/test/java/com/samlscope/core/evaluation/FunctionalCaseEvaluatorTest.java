package com.samlscope.core.evaluation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.profile.FunctionalCaseDefinition;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetRole;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionalCaseEvaluatorTest {
    @Test
    void missingSiblingCaseRemainsNotVerified() {
        var coverage = coverage();
        var cases = cases();
        var definition = definition(cases, coverage);
        var observed = CaseRun.completed("case-a", "owner-a",
                CaseOutcome.of(Outcome.SATISFIED, "observed", List.of()));

        var result = Evaluator.evaluateFunctionalCases(
                definition, coverage, List.of(), List.of(observed), List.of());

        assertEquals(Verdict.NOT_VERIFIED, result.obligations().getFirst().verdict());
        assertEquals(RunResult.Completeness.INCOMPLETE, result.completeness());
        assertEquals(List.of("case-a", "case-b"), result.obligations().getFirst().caseIds());
    }

    @Test
    void rejectsOutcomeOutsideProfileCaseSet() {
        var coverage = coverage();
        var definition = definition(cases(), coverage);
        var foreign = CaseRun.completed("foreign", "owner-a",
                CaseOutcome.of(Outcome.SATISFIED, "observed", List.of()));

        assertThrows(IllegalArgumentException.class, () -> Evaluator.evaluateFunctionalCases(
                definition, coverage, List.of(), List.of(foreign), List.of()));
    }

    private static FunctionalCaseDefinition definition(
            CaseDefinitionCatalog cases, CoverageCatalog coverage) {
        return new FunctionalCaseDefinition(
                "browser-sso-idp-v1", FunctionalProfile.BROWSER_SSO_IDP,
                Map.of("tests/cases.yaml", "sha256:" + "3".repeat(64)),
                cases.cases().stream().map(value ->
                        new FunctionalCaseDefinition.CaseReference(value.id(), value.caseDigest())).toList(),
                Set.of(), cases, coverage);
    }

    private static CaseDefinitionCatalog cases() {
        return new CaseDefinitionCatalog(List.of(
                approvedCase("case-a", "sha256:" + "1".repeat(64)),
                approvedCase("case-b", "sha256:" + "2".repeat(64))));
    }

    private static CaseDefinitionCatalog.CaseDefinition approvedCase(String id, String digest) {
        return new CaseDefinitionCatalog.CaseDefinition(
                id, "owner-a", TargetRole.IDP,
                CaseDefinitionCatalog.ExecutionMode.AUTOMATED,
                CaseDefinitionCatalog.Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(),
                List.of(new CaseDefinitionCatalog.Control(
                        "positive", CaseDefinitionCatalog.ControlKind.POSITIVE,
                        "fixture", "control", "control_failed")),
                "counterexample", List.of(),
                new CaseDefinitionCatalog.Requirements(List.of(), "none"),
                false, null, digest);
    }

    private static CoverageCatalog coverage() {
        return new CoverageCatalog(List.of(new CoverageCatalog.Obligation(
                "owner-a", "requirement-a", Rfc2119Level.MUST,
                List.of(TargetRole.IDP), null, CoverageCatalog.Testability.AUTOMATED,
                CoverageCatalog.ProfileScope.CORE)));
    }
}
