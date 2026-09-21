package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Compares adapter-verified native UI observations. Absence is never proof of nonuse. */
final class UiDisplayComparison {
    static final String CASE_ID = "IIP-MD05-fj-idp-01";
    enum Condition { ALL, SERVICE, ENTITY }
    enum Selection { DISPLAY, SERVICE, ENTITY, HOSTNAME, UNOBSERVED }
    record Sample(String runId, String entityId, Condition condition, String stableInputs,
                  String metadataHash, String serviceName, Instant requestedAt, Instant observedAt,
                  Selection selection, List<EvidenceRef> evidence) {
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
        var fingerprints = new HashSet<String>();
        var identities = new HashSet<List<String>>();
        var hashes = new HashSet<String>();
        var services = new HashSet<String>();
        for (var sample : samples) {
            if (conditions.put(sample.condition(), sample) != null) issues.add("duplicate_condition");
            if (sample.runId() == null || sample.runId().isBlank() || sample.entityId() == null || sample.entityId().isBlank()) {
                issues.add("identity_unavailable");
            } else identities.add(List.of(sample.runId(), sample.entityId()));
            if (!hash(sample.stableInputs()) || !hash(sample.metadataHash())) issues.add("input_fingerprint_unavailable");
            fingerprints.add(sample.stableInputs()); hashes.add(sample.metadataHash());
            if (sample.condition() != Condition.ENTITY) {
                if (sample.serviceName() == null || sample.serviceName().isBlank()) issues.add("service_candidate_unavailable");
                else services.add(sample.serviceName());
            } else if (sample.serviceName() != null) issues.add("unexpected_service_candidate");
            if (!sample.requestedAt().isBefore(sample.observedAt())) issues.add("observation_chronology_unproven");
            if (!sample.evidence().stream().map(EvidenceRef::kind).toList().equals(
                    List.of("transcript", "transcript", "transcript", "browser-observation"))) issues.add("incomplete_provenance");
            if (sample.evidence().stream().anyMatch(e -> !refs.add(e))) issues.add("reused_evidence");
            if (sample.selection() == Selection.UNOBSERVED) issues.add("selection_unobserved_" + sample.condition().name().toLowerCase(Locale.ROOT));
            if ((sample.condition() != Condition.ALL && sample.selection() == Selection.DISPLAY)
                    || (sample.condition() == Condition.ENTITY && sample.selection() == Selection.SERVICE)) issues.add("absent_candidate_selected");
        }
        if (conditions.size() != Condition.values().length) issues.add("missing_condition");
        if (identities.size() != 1) issues.add("mixed_experiment");
        if (fingerprints.size() != 1 || services.size() != 1) issues.add("uncontrolled_input_changed");
        if (hashes.size() != Condition.values().length) issues.add("condition_input_not_changed");
        Sample previous = null;
        for (var condition : Condition.values()) {
            var sample = conditions.get(condition);
            if (sample != null) {
                if (previous != null && !previous.observedAt().isBefore(sample.requestedAt())) issues.add("overlapping_or_reordered_conditions");
                previous = sample;
            }
        }
        boolean expected = samples.stream().allMatch(sample -> switch (sample.condition()) {
            case ALL -> sample.selection() == Selection.DISPLAY;
            case SERVICE -> sample.selection() == Selection.SERVICE;
            case ENTITY -> sample.selection() == Selection.ENTITY || sample.selection() == Selection.HOSTNAME;
        });
        // A known lower-priority candidate is a measurable difference, but absence/unknown
        // content and unsupported templates remain NOT_VERIFIED. Evaluator applies SHOULD.
        var outcome = !issues.isEmpty() ? Outcome.NOT_VERIFIED : expected ? Outcome.SATISFIED : Outcome.VIOLATED;
        var code = "browser.ui-display." + (!issues.isEmpty() ? "evidence-incomplete" : expected ? "precedence-observed" : "precedence-different");
        return new CaseOutcome(outcome, outcome == Outcome.NOT_VERIFIED ? "ui_display_comparison_unproven" : null,
                code, code, samples.stream().flatMap(s -> s.evidence().stream()).distinct().toList(),
                Map.of("evidence_issues", List.copyOf(issues), "observed_conditions", conditions.keySet().stream().map(Enum::name).toList()));
    }
    private static boolean hash(String value) { return value != null && value.matches("[0-9a-f]{64}"); }
}
