package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Entity-ID policy comparison of collector-verified exchanges; no public evidence DTO. */
final class RelyingPartyAttributeComparison {
    static final String CASE_ID = "IIP-IDP02-a-idp-01";
    enum Condition { FIRST, SECOND, FIRST_REPEAT }

    /**
     * Collector verifies signatures, response correlation, audience/recipient and native preparation.
     * stableInputs excludes only the two RP identities and their necessary endpoint/key bindings.
     * Policy and driver login-input bindings remain fixed; neither a confirmation nor arbitrary hashes
     * submitted by a user qualify. Markers describe only Suite-owned released attributes, not values.
     */
    record Sample(String experiment, Condition condition, String entityId, String policyFingerprint,
                  String loginInputFingerprint, String stableInputs, String metadataFingerprint,
                  String attributeInputFingerprint, Instant requestedAt, Instant receivedAt,
                  Set<String> markers, List<EvidenceRef> evidence) {
        Sample {
            Objects.requireNonNull(condition); Objects.requireNonNull(requestedAt);
            Objects.requireNonNull(receivedAt); markers = Set.copyOf(markers); evidence = List.copyOf(evidence);
        }
    }

    static CaseOutcome evaluate(List<Sample> samples, List<String> collectionIssues) {
        var issues = new LinkedHashSet<>(collectionIssues);
        var byCondition = new EnumMap<Condition, Sample>(Condition.class);
        var references = new HashSet<EvidenceRef>();
        for (var sample : samples) {
            if (byCondition.put(sample.condition(), sample) != null) issues.add("duplicate_condition");
            if (sample.experiment() == null || sample.experiment().isBlank()
                    || sample.entityId() == null || sample.entityId().isBlank()) issues.add("experiment_binding_unavailable");
            for (var fingerprint : Arrays.asList(sample.policyFingerprint(), sample.loginInputFingerprint(),
                    sample.stableInputs(), sample.metadataFingerprint(), sample.attributeInputFingerprint())) {
                if (fingerprint == null || !fingerprint.matches("[0-9a-f]{64}")) issues.add("input_fingerprint_unavailable");
            }
            if (!sample.requestedAt().isBefore(sample.receivedAt())) issues.add("exchange_chronology_unproven");
            if (sample.evidence().size() != 2 || sample.evidence().stream().anyMatch(ref ->
                    !"transcript".equals(ref.kind()) || ref.reference() == null || ref.reference().isBlank()
                    || !references.add(ref))) issues.add("exchange_provenance_unproven");
            Set<String> expected = sample.condition() == Condition.SECOND
                    ? Set.of("anchor", "second") : Set.of("anchor", "first");
            if (!sample.markers().equals(expected)) issues.add("entity_specific_release_unobserved");
        }
        var missing = Arrays.stream(Condition.values()).filter(c -> !byCondition.containsKey(c)).toList();
        if (!missing.isEmpty()) issues.add("missing_condition");
        if (!samples.isEmpty()) {
            var first = samples.getFirst();
            for (var sample : samples) {
                if (!Objects.equals(first.experiment(), sample.experiment())) issues.add("mixed_experiments");
                if (!Objects.equals(first.policyFingerprint(), sample.policyFingerprint())) issues.add("policy_changed");
                if (!Objects.equals(first.loginInputFingerprint(), sample.loginInputFingerprint())) issues.add("login_input_changed");
                if (!Objects.equals(first.stableInputs(), sample.stableInputs())) issues.add("uncontrolled_input_changed");
                if (!Objects.equals(first.attributeInputFingerprint(), sample.attributeInputFingerprint())) issues.add("attribute_input_changed");
            }
        }
        var first = byCondition.get(Condition.FIRST);
        var second = byCondition.get(Condition.SECOND);
        var repeat = byCondition.get(Condition.FIRST_REPEAT);
        if (first != null && second != null) {
            if (Objects.equals(first.entityId(), second.entityId())) issues.add("distinct_relying_parties_unproven");
            if (Objects.equals(first.metadataFingerprint(), second.metadataFingerprint())) issues.add("distinct_metadata_unproven");
            if (!first.receivedAt().isBefore(second.requestedAt())) issues.add("overlapping_or_reordered_exchanges");
        }
        if (first != null && repeat != null) {
            if (!Objects.equals(first.entityId(), repeat.entityId())
                    || !Objects.equals(first.metadataFingerprint(), repeat.metadataFingerprint())) issues.add("repeat_input_changed");
        }
        if (second != null && repeat != null && !second.receivedAt().isBefore(repeat.requestedAt())) {
            issues.add("overlapping_or_reordered_exchanges");
        }
        boolean satisfied = issues.isEmpty();
        String code = satisfied ? "configuration.relying-party-attributes.difference-observed"
                : "configuration.relying-party-attributes.evidence-incomplete";
        // No capability failure is inferred from missing configuration or absent attributes.
        return new CaseOutcome(satisfied ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                satisfied ? null : "relying_party_attribute_comparison_unproven", code, code,
                samples.stream().flatMap(s -> s.evidence().stream()).distinct().toList(),
                Map.of("evidence_issues", List.copyOf(issues), "missing_conditions", missing.stream().map(Enum::name).toList()));
    }
}
