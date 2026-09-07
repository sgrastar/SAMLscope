package com.samlscope.runner.result;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.Basis;
import com.samlscope.core.evaluation.ApplicabilityEvaluation.EffectiveResult;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.evaluation.PredicateKind;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.evaluation.RunResult.Completeness;
import com.samlscope.core.evaluation.RunResult.Conformance;
import com.samlscope.core.evaluation.Verdict;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;

/** Stable public result schema v1. Values are assembled exclusively from Evaluator output and Run inputs. */
public record ResultDocument(
        String schemaVersion,
        RunView run,
        SuiteView suite,
        EvaluationBundleView evaluationBundle,
        ProfileView profile,
        TargetView target,
        ConfigurationView configuration,
        List<ApplicabilityView> applicability,
        List<AdvisoryView> advisories,
        List<SuiteIncidentView> suiteIncidents,
        SummaryView summary,
        EvidenceSummaryView evidenceSummary,
        CoverageView coverage,
        List<RequirementView> requirements,
        List<UnresolvedView> unresolved,
        List<NotObservableView> notObservable,
        String conformanceStatement) {

    public ResultDocument {
        text(schemaVersion, "schemaVersion");
        if (!"1".equals(schemaVersion)) throw new IllegalArgumentException("Unsupported result schema version");
        java.util.Objects.requireNonNull(run, "run");
        java.util.Objects.requireNonNull(suite, "suite");
        java.util.Objects.requireNonNull(evaluationBundle, "evaluationBundle");
        java.util.Objects.requireNonNull(profile, "profile");
        java.util.Objects.requireNonNull(target, "target");
        java.util.Objects.requireNonNull(configuration, "configuration");
        applicability = List.copyOf(applicability == null ? List.of() : applicability);
        advisories = List.copyOf(advisories == null ? List.of() : advisories);
        suiteIncidents = List.copyOf(suiteIncidents == null ? List.of() : suiteIncidents);
        java.util.Objects.requireNonNull(summary, "summary");
        java.util.Objects.requireNonNull(evidenceSummary, "evidenceSummary");
        java.util.Objects.requireNonNull(coverage, "coverage");
        requirements = List.copyOf(requirements == null ? List.of() : requirements);
        unresolved = List.copyOf(unresolved == null ? List.of() : unresolved);
        notObservable = List.copyOf(notObservable == null ? List.of() : notObservable);
        text(conformanceStatement, "conformanceStatement");
    }

    public record RunView(
            String id,
            Instant startedAt,
            Instant finishedAt,
            Conformance conformance,
            Completeness completeness,
            List<ScopeQualificationView> scopeQualifications) {
        public RunView { scopeQualifications = List.copyOf(scopeQualifications); }
    }

    public record ScopeQualificationView(
            String kind,
            String predicate,
            List<String> excludedObligations,
            String reason,
            String attestedBy,
            Instant attestedAt,
            boolean verified) {
        public ScopeQualificationView {
            excludedObligations = List.copyOf(excludedObligations);
            if (verified) throw new IllegalArgumentException("Declared exclusions cannot be verified");
        }
    }

    public record SuiteView(String name, String version, String imageDigest, String executionMode) {}

    public record EvaluationBundleView(String digest, EvaluationComponentsView components) {}

    public record EvaluationComponentsView(
            String coverageYaml,
            String testDefinitions,
            String specsYaml,
            String outcomeMappingVersion,
            String aggregationPolicyVersion) {}

    public record ProfileView(String id, SpecView spec, String levelDefinitionNote) {}

    public record SpecView(String document, String version, LocalDate date) {}

    public record TargetView(
            String declaredProduct,
            String declaredBy,
            boolean verified,
            String entityId,
            String metadataDigest,
            TargetRole role,
            TargetKind kind) {
        public TargetView {
            if (verified) throw new IllegalArgumentException("Phase 1 target declarations are not verified");
        }
    }

    public record ConfigurationView(
            MetadataDeliveryKind suiteMetadataDelivery,
            com.samlscope.core.run.Reachability reachability,
            Map<String, Boolean> declaredFeatures,
            ParametersView parameters) {
        public ConfigurationView { declaredFeatures = Map.copyOf(declaredFeatures); }
    }

    /** Deliberately excludes TestPlan.Parameters.testUserHint, which must never be published. */
    public record ParametersView(int clockSkewToleranceSeconds, int metadataRefreshWaitSeconds,
            com.samlscope.core.plan.TestPlan.RequestSigningMode requestSigningMode) {
        public ParametersView(int clockSkewToleranceSeconds, int metadataRefreshWaitSeconds) {
            this(clockSkewToleranceSeconds, metadataRefreshWaitSeconds,
                    com.samlscope.core.plan.TestPlan.RequestSigningMode.OPTIONAL);
        }
    }

    public record ApplicabilityView(
            String obligation,
            String predicate,
            PredicateKind predicateKind,
            Boolean declared,
            Boolean observed,
            EffectiveResult effectiveResult,
            boolean conflict,
            Basis basis,
            List<EvidenceView> evidence) {
        public ApplicabilityView { evidence = List.copyOf(evidence); }
    }

    public record EvidenceView(String kind, String reference) {}

    public record AdvisoryView(
            String code,
            String obligation,
            String severity,
            String messageEn,
            boolean affectsVerdict) {
        public AdvisoryView {
            if (affectsVerdict) throw new IllegalArgumentException("Advisories must not affect verdicts");
        }
    }

    public record SuiteIncidentView(String kind, String caseId, String actionId, String note) {}

    public record SummaryView(CountView requirements, CountView obligations, CountView cases) {}

    public record EvidenceSummaryView(
            int externallyVerified,
            int selfAttested,
            int notVerified,
            double externallyVerifiedRatio,
            double selfAttestedRatio) {}

    public record CountView(int total, Map<String, Integer> verdicts) {
        public CountView { verdicts = Map.copyOf(verdicts); }
    }

    public record CoverageView(
            int obligationsTotal,
            int obligationsApplicable,
            int mustApplicable,
            int mustObservable,
            int mustResolved,
            int mustUnresolved,
            int mustNotObservable,
            int attestedObligations,
            int applicabilityFromDeclarationOnly,
            int excludedByDeclaration,
            double verifiedRatio) {}

    public record RequirementView(
            String id,
            Verdict verdict,
            String specUrl,
            List<ObligationView> obligations,
            List<CaseView> cases) {
        public RequirementView {
            obligations = List.copyOf(obligations);
            cases = List.copyOf(cases);
        }
    }

    public record ObligationView(String key, Rfc2119Level level, TargetRole role, Verdict verdict) {}

    public record CaseView(
            String id,
            String obligation,
            Outcome outcome,
            Verdict verdict,
            String mode,
            String reasonCode,
            String reason,
            boolean attested,
            String evidenceClass,
            List<EvidenceView> evidence,
            String definitionUrl) {
        public CaseView { evidence = List.copyOf(evidence); }
    }

    public record UnresolvedView(
            String obligation,
            Rfc2119Level level,
            Verdict verdict,
            List<String> reasons,
            String howToResolve) {
        public UnresolvedView { reasons = List.copyOf(reasons); }
    }

    public record NotObservableView(String obligation, Rfc2119Level level, String reason) {}

    private static void text(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }
}
