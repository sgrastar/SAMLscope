package com.samlscope.core.evaluation;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.Basis;
import com.samlscope.core.evaluation.Rfc2119Level.LevelClass;
import com.samlscope.core.evaluation.RunResult.Completeness;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.evaluation.RunResult.ObligationResult;

/** Independently checks the cross-field invariants of an authoritative Run result. */
public final class RunResultInvariantValidator {
    private RunResultInvariantValidator() {}

    public static void validateSelectedObligations(CoverageCatalog catalog, RunResult result) {
        Objects.requireNonNull(catalog, "catalog");
        Objects.requireNonNull(result, "result");
        var selected = new LinkedHashMap<String, CoverageCatalog.Obligation>(catalog.byKey());
        var obligations = uniqueObligations(result.obligations());
        require(selected.keySet().equals(obligations.keySet()), "Result obligation set does not match selected profile");
        for (var entry : obligations.entrySet()) {
            var source = selected.get(entry.getKey());
            var value = entry.getValue();
            require(source.requirementId().equals(value.requirementId()), "Requirement mismatch: " + entry.getKey());
            require(source.level() == value.level(), "Level mismatch: " + entry.getKey());
        }

        validateApplicability(selected, obligations, result.applicability());
        validateRequirements(obligations.values(), result.requirements());
        validateCoverage(selected, obligations.values(), result);
        validateScopeQualifications(result);
    }

    private static Map<String, ObligationResult> uniqueObligations(List<ObligationResult> values) {
        var result = new LinkedHashMap<String, ObligationResult>();
        for (var value : values) {
            require(value != null, "Null obligation result");
            require(result.put(value.key(), value) == null, "Duplicate obligation result: " + value.key());
        }
        return result;
    }

    private static void validateApplicability(
            Map<String, CoverageCatalog.Obligation> selected,
            Map<String, ObligationResult> obligations,
            List<ApplicabilityEvaluation> values) {
        var expected = new LinkedHashSet<String>();
        for (var obligation : selected.values()) {
            if (obligation.condition() != null) expected.add(obligation.key());
        }
        var actual = new LinkedHashMap<String, ApplicabilityEvaluation>();
        for (var value : values) {
            require(value != null, "Null applicability evaluation");
            require(actual.put(value.obligationKey(), value) == null,
                    "Duplicate applicability result: " + value.obligationKey());
            var source = selected.get(value.obligationKey());
            require(source != null && source.condition() != null,
                    "Applicability does not refer to a selected conditional obligation: " + value.obligationKey());
            require(source.condition().equals(value.predicate()),
                    "Applicability predicate mismatch: " + value.obligationKey());
            if (value.conflict()) {
                require(obligations.get(value.obligationKey()).verdict().severity() >= Verdict.INCONSISTENT.severity(),
                        "Applicability conflict did not enter aggregation: " + value.obligationKey());
            }
        }
        require(expected.equals(actual.keySet()), "Conditional applicability set is incomplete");
    }

    private static void validateRequirements(
            java.util.Collection<ObligationResult> obligations,
            List<RunResult.RequirementResult> values) {
        var grouped = new LinkedHashMap<String, List<ObligationResult>>();
        for (var obligation : obligations) {
            grouped.computeIfAbsent(obligation.requirementId(), ignored -> new ArrayList<>()).add(obligation);
        }
        var actual = new LinkedHashMap<String, RunResult.RequirementResult>();
        for (var value : values) {
            require(value != null, "Null requirement result");
            require(actual.put(value.id(), value) == null, "Duplicate requirement result: " + value.id());
        }
        require(grouped.keySet().equals(actual.keySet()), "Requirement result set does not match obligations");
        for (var entry : grouped.entrySet()) {
            var value = actual.get(entry.getKey());
            var expectedKeys = entry.getValue().stream().map(ObligationResult::key).toList();
            require(expectedKeys.equals(value.obligationKeys()), "Requirement obligation list mismatch: " + entry.getKey());
            Verdict expectedVerdict = null;
            for (var obligation : entry.getValue()) {
                expectedVerdict = expectedVerdict == null
                        ? obligation.verdict()
                        : Verdict.moreSevere(expectedVerdict, obligation.verdict());
            }
            require(expectedVerdict == value.verdict(), "Requirement verdict mismatch: " + entry.getKey());
        }
    }

    private static void validateCoverage(
            Map<String, CoverageCatalog.Obligation> selected,
            java.util.Collection<ObligationResult> obligations,
            RunResult result) {
        var counts = new EnumMap<Verdict, Integer>(Verdict.class);
        for (var verdict : Verdict.values()) counts.put(verdict, 0);
        for (var obligation : obligations) counts.merge(obligation.verdict(), 1, Integer::sum);

        var applicableMust = obligations.stream()
                .filter(value -> value.verdict() != Verdict.NOT_APPLICABLE)
                .filter(value -> value.level().levelClass() == LevelClass.MUST_CLASS)
                .toList();
        var applicable = obligations.stream()
                .filter(value -> value.verdict() != Verdict.NOT_APPLICABLE)
                .toList();
        var mustNotObservable = count(applicableMust, Verdict.NOT_OBSERVABLE);
        var mustObservable = applicableMust.size() - mustNotObservable;
        var mustResolved = (int) applicableMust.stream().filter(value -> switch (value.verdict()) {
            case PASS, WARNING, FAIL -> true;
            default -> false;
        }).count();
        var mustUnresolved = (int) applicableMust.stream()
                .filter(value -> unresolved(value.verdict()))
                .count();
        var exclusions = (int) result.applicability().stream()
                .filter(value -> value.basis() == Basis.DECLARATION_ONLY_EXCLUSION)
                .count();
        var declarationOnly = (int) result.applicability().stream()
                .filter(value -> value.basis() != Basis.OBSERVED)
                .count();
        var attested = (int) applicable.stream()
                .filter(value -> selected.get(value.key()).testability() == CoverageCatalog.Testability.ATTESTED)
                .count();
        var ratio = mustObservable == 0 ? 1.0 : (double) mustResolved / mustObservable;
        var coverage = result.coverage();
        require(coverage.obligationsTotal() == obligations.size(), "obligationsTotal is inconsistent");
        require(coverage.obligationsApplicable() == applicable.size(), "obligationsApplicable is inconsistent");
        require(coverage.mustApplicable() == applicableMust.size(), "mustApplicable is inconsistent");
        require(coverage.mustObservable() == mustObservable, "mustObservable is inconsistent");
        require(coverage.mustResolved() == mustResolved, "mustResolved is inconsistent");
        require(coverage.mustUnresolved() == mustUnresolved, "mustUnresolved is inconsistent");
        require(coverage.mustNotObservable() == mustNotObservable, "mustNotObservable is inconsistent");
        require(coverage.attestedObligations() == attested, "attestedObligations is inconsistent");
        require(coverage.applicabilityFromDeclarationOnly() == declarationOnly,
                "applicabilityFromDeclarationOnly is inconsistent");
        require(coverage.excludedByDeclaration() == exclusions, "excludedByDeclaration is inconsistent");
        require(Double.compare(coverage.verifiedRatio(), ratio) == 0, "verifiedRatio is inconsistent");
        require(coverage.verdictCounts().equals(counts), "Verdict counts are inconsistent");

        var expectedConformance = expectedConformance(obligations, exclusions);
        require(result.conformance() == expectedConformance, "Run conformance is inconsistent");
        var expectedCompleteness = obligations.stream()
                .filter(value -> value.verdict() != Verdict.NOT_APPLICABLE)
                .filter(value -> value.verdict() != Verdict.NOT_OBSERVABLE)
                .anyMatch(value -> unresolved(value.verdict()))
                ? Completeness.INCOMPLETE : Completeness.COMPLETE;
        require(result.completeness() == expectedCompleteness, "Run completeness is inconsistent");
    }

    private static Conformance expectedConformance(
            java.util.Collection<ObligationResult> obligations,
            int declarationExclusions) {
        if (obligations.stream().anyMatch(value -> value.verdict() == Verdict.FAIL)) {
            return Conformance.NON_CONFORMANT;
        }
        if (obligations.stream()
                .filter(value -> value.verdict() != Verdict.NOT_APPLICABLE)
                .filter(value -> value.verdict() != Verdict.NOT_OBSERVABLE)
                .filter(value -> value.level().levelClass() == LevelClass.MUST_CLASS)
                .anyMatch(value -> unresolved(value.verdict()))) {
            return Conformance.INDETERMINATE;
        }
        if (declarationExclusions > 0) return Conformance.CONFORMANT_WITH_DECLARED_EXCLUSIONS;
        if (obligations.stream().anyMatch(value -> value.verdict() == Verdict.WARNING)) {
            return Conformance.CONFORMANT_WITH_WARNINGS;
        }
        return Conformance.CONFORMANT;
    }

    private static void validateScopeQualifications(RunResult result) {
        record Expected(ApplicabilityInput.ExclusionDeclaration declaration, Set<String> obligations) {}
        var expected = new LinkedHashMap<String, Expected>();
        for (var value : result.applicability()) {
            if (value.basis() == Basis.DECLARATION_ONLY_EXCLUSION) {
                var current = expected.get(value.predicate());
                if (current == null) {
                    var obligations = new LinkedHashSet<String>();
                    obligations.add(value.obligationKey());
                    expected.put(value.predicate(), new Expected(value.exclusion(), obligations));
                } else {
                    require(current.declaration().equals(value.exclusion()),
                            "One predicate has inconsistent exclusion declarations: " + value.predicate());
                    current.obligations().add(value.obligationKey());
                }
            }
        }
        var actual = new LinkedHashSet<String>();
        for (var value : result.scopeQualifications()) {
            require(actual.add(value.predicate()),
                    "Duplicate scope qualification: " + value.predicate());
            require(!value.verified(), "Declaration-only exclusion cannot be verified");
            var source = expected.get(value.predicate());
            require(source != null, "Scope qualification has no declared exclusion: " + value.predicate());
            require(source.obligations().equals(Set.copyOf(value.excludedObligations())),
                    "Scope qualification obligation set is inconsistent: " + value.predicate());
            require(source.declaration().reason().equals(value.reason()),
                    "Scope qualification reason is inconsistent: " + value.predicate());
            require(source.declaration().attestedBy().equals(value.attestedBy()),
                    "Scope qualification attester is inconsistent: " + value.predicate());
            require(source.declaration().attestedAt().equals(value.attestedAt()),
                    "Scope qualification time is inconsistent: " + value.predicate());
        }
        require(expected.keySet().equals(actual), "Scope qualifications do not match declared exclusions");
    }

    private static int count(List<ObligationResult> values, Verdict verdict) {
        return (int) values.stream().filter(value -> value.verdict() == verdict).count();
    }

    private static boolean unresolved(Verdict verdict) {
        return switch (verdict) {
            case NOT_VERIFIED, INDETERMINATE, INCONSISTENT, ERROR -> true;
            default -> false;
        };
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
