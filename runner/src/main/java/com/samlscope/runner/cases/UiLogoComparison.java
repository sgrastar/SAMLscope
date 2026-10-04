package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Internal comparison of adapter-verified browser evidence, not an external evidence DTO. */
final class UiLogoComparison {
    static final String CASE_ID = "IIP-MD05-f9-idp-01";
    enum Condition { PREFERRED_AVAILABLE, PREFERRED_UNAVAILABLE }
    enum Selection { LOCALIZED, DEFAULT, UNOBSERVED }

    /**
     * The collector must derive the condition from original metadata and verified language preparation.
     * stableInputs binds the target, policy, SP, browser settings, image bytes and dimensions, and page
     * selectors, excluding only the localized candidate's language. It must not be supplied by a user.
     * Evidence order: metadata fetch, prepared metadata, outbound request, retained browser observation.
     */
    record Sample(String runId, String entityId, Condition condition, String stableInputs,
                  String metadataHash, String defaultImageHash, String localizedImageHash,
                  Instant requestedAt, Instant observedAt, Selection selection, List<EvidenceRef> evidence) {
        Sample {
            Objects.requireNonNull(condition); Objects.requireNonNull(selection);
            Objects.requireNonNull(requestedAt); Objects.requireNonNull(observedAt);
            evidence = List.copyOf(evidence);
        }
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> collectionIssues) {
        var issues = new LinkedHashSet<>(collectionIssues);
        var conditions = new EnumMap<Condition, Sample>(Condition.class);
        var refs = new HashSet<EvidenceRef>();
        for (var sample : samples) {
            if (conditions.put(sample.condition(), sample) != null) issues.add("duplicate_condition");
            if (sample.runId() == null || sample.runId().isBlank()
                    || sample.entityId() == null || sample.entityId().isBlank()) issues.add("identity_unavailable");
            if (!hash(sample.stableInputs()) || !hash(sample.metadataHash())
                    || !hash(sample.defaultImageHash()) || !hash(sample.localizedImageHash())) {
                issues.add("input_fingerprint_unavailable");
            }
            if (Objects.equals(sample.defaultImageHash(), sample.localizedImageHash())) issues.add("indistinguishable_logos");
            if (!sample.requestedAt().isBefore(sample.observedAt())) issues.add("observation_chronology_unproven");
            var kinds = sample.evidence().stream().map(EvidenceRef::kind).toList();
            if (!kinds.equals(List.of("transcript", "transcript", "transcript", "browser-observation"))) {
                issues.add("incomplete_provenance");
            }
            if (sample.evidence().stream().anyMatch(e -> !refs.add(e))) issues.add("reused_evidence");
        }
        var preferred = conditions.get(Condition.PREFERRED_AVAILABLE);
        var fallback = conditions.get(Condition.PREFERRED_UNAVAILABLE);
        if (preferred == null || fallback == null) issues.add("missing_condition");
        if (preferred != null && fallback != null) {
            if (!Objects.equals(preferred.runId(), fallback.runId())
                    || !Objects.equals(preferred.entityId(), fallback.entityId())) issues.add("mixed_experiment");
            if (!Objects.equals(preferred.stableInputs(), fallback.stableInputs())
                    || !Objects.equals(preferred.defaultImageHash(), fallback.defaultImageHash())
                    || !Objects.equals(preferred.localizedImageHash(), fallback.localizedImageHash())) issues.add("uncontrolled_input_changed");
            if (Objects.equals(preferred.metadataHash(), fallback.metadataHash())) issues.add("language_input_not_changed");
            if (!preferred.observedAt().isBefore(fallback.requestedAt())) issues.add("overlapping_or_reordered_conditions");
            // Selecting a preferred-language logo is MAY; the default fallback is SHOULD.
            // A visible default in the preferred condition therefore remains permitted.
            if (preferred.selection() == Selection.UNOBSERVED || fallback.selection() != Selection.DEFAULT) {
                issues.add("selection_difference_unproven");
            }
        }
        boolean satisfied = issues.isEmpty();
        String code = satisfied ? "browser.ui-logo.language-fallback-observed" : "browser.ui-logo.evidence-incomplete";
        // Missing setup/visibility or uncontrolled policy is uncertainty, not a target violation.
        return new CaseOutcome(satisfied ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                satisfied ? null : "ui_logo_comparison_unproven", code, code,
                samples.stream().flatMap(s -> s.evidence().stream()).distinct().toList(),
                Map.of("evidence_issues", List.copyOf(issues), "observed_conditions", conditions.keySet().stream().map(Enum::name).toList()));
    }

    private static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
}
