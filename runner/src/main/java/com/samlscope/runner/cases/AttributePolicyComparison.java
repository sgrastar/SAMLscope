package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.*;
import com.samlscope.core.evaluation.*;

/** Compares already verified experiment samples. Raw transcript collection is a separate trust boundary. */
final class AttributePolicyComparison {
    static final String ENTITY = "IIP-IDP03-a-idp-01";
    static final String REQUESTED = "IIP-IDP04-a-idp-01";
    static final String INDEX = "IIP-IDP04-b-idp-01";
    enum Condition { BASELINE, ENTITY_PRESENT, ENTITY_ABSENT, REQUESTED_REQUIRED,
        REQUESTED_OPTIONAL, REQUESTED_ABSENT, INDEX_ZERO, INDEX_ONE, INDEX_ZERO_REPEAT }

    /**
     * Fingerprints must come from verified preparation and signed originals, never UI assertions.
     * stableInputFingerprint excludes only the deliberate input under comparison; it retains other inputs.
     * loginInputFingerprint is ephemeral and must not be copied to CaseOutcome details.
     * It binds fixed driver login inputs, not independently authenticated principal identity.
     */
    record Sample(String experiment, Condition condition, String policyFingerprint,
                  String loginInputFingerprint, String entityId, String metadataFingerprint,
                  String stableInputFingerprint, Instant issued, Instant received,
                  Set<String> markers, List<EvidenceRef> evidence) {
        Sample {
            Objects.requireNonNull(condition);
            Objects.requireNonNull(issued);
            Objects.requireNonNull(received);
            markers = Set.copyOf(markers);
            evidence = List.copyOf(evidence);
        }
    }

    static List<Condition> required(String id) {
        return switch (id) {
            case ENTITY -> List.of(Condition.BASELINE, Condition.ENTITY_PRESENT, Condition.ENTITY_ABSENT);
            case REQUESTED -> List.of(Condition.BASELINE, Condition.REQUESTED_REQUIRED,
                    Condition.REQUESTED_OPTIONAL, Condition.REQUESTED_ABSENT);
            case INDEX -> List.of(Condition.BASELINE, Condition.INDEX_ZERO, Condition.INDEX_ONE, Condition.INDEX_ZERO_REPEAT);
            default -> throw new IllegalArgumentException("Unsupported attribute policy case");
        };
    }

    private static Set<String> expected(Condition condition) {
        return switch (condition) {
            case BASELINE, ENTITY_ABSENT, REQUESTED_ABSENT -> Set.of("anchor");
            case ENTITY_PRESENT -> Set.of("anchor", "entity");
            case REQUESTED_REQUIRED, INDEX_ZERO, INDEX_ZERO_REPEAT -> Set.of("anchor", "required", "optional");
            case REQUESTED_OPTIONAL -> Set.of("anchor", "optional");
            case INDEX_ONE -> Set.of("anchor", "surname");
        };
    }

    static CaseOutcome evaluate(String id, List<Sample> input, List<String> collectionIssues) {
        var required = required(id);
        var samples = input.stream().filter(s -> required.contains(s.condition())).toList();
        var issues = new ArrayList<>(collectionIssues);
        var byCondition = new EnumMap<Condition, Sample>(Condition.class);
        var usedEvidence = new HashSet<EvidenceRef>();
        for (var sample : samples) {
            if (byCondition.put(sample.condition(), sample) != null) issues.add("duplicate_condition:" + sample.condition());
            if (sample.experiment() == null || sample.experiment().isBlank()
                    || sample.entityId() == null || sample.entityId().isBlank()) issues.add("experiment_binding_unavailable");
            if (!fingerprint(sample.policyFingerprint()) || !fingerprint(sample.loginInputFingerprint())
                    || !fingerprint(sample.metadataFingerprint()) || !fingerprint(sample.stableInputFingerprint())) {
                issues.add("preparation_or_input_fingerprint_unavailable");
            }
            if (sample.received().isBefore(sample.issued())) issues.add("response_precedes_request");
            // Collector supplies the unique request and response refs for this exchange, in that order.
            if (sample.evidence().size() != 2 || sample.evidence().stream().anyMatch(e ->
                    !"transcript".equals(e.kind()) || e.reference() == null || e.reference().isBlank()
                            || !usedEvidence.add(e))) issues.add("ambiguous_exchange_evidence");
        }
        var missing = required.stream().filter(c -> !byCondition.containsKey(c)).toList();
        if (!samples.isEmpty()) {
            var first = samples.getFirst();
            for (var sample : samples) {
                if (!Objects.equals(first.experiment(), sample.experiment())) issues.add("mixed_experiments");
                if (!Objects.equals(first.policyFingerprint(), sample.policyFingerprint())) issues.add("policy_changed");
                if (!Objects.equals(first.loginInputFingerprint(), sample.loginInputFingerprint())) issues.add("login_input_changed");
                if (!Objects.equals(first.entityId(), sample.entityId())) issues.add("relying_party_changed");
            }
        }
        var comparisons = required.stream().filter(c -> c != Condition.BASELINE).map(byCondition::get)
                .filter(Objects::nonNull).toList();
        if (!comparisons.isEmpty()) {
            var first = comparisons.getFirst();
            for (var sample : comparisons) {
                if (!Objects.equals(first.stableInputFingerprint(), sample.stableInputFingerprint())) {
                    issues.add("uncontrolled_input_changed");
                }
                if (INDEX.equals(id) && !Objects.equals(first.metadataFingerprint(), sample.metadataFingerprint())) {
                    issues.add("indexed_metadata_changed");
                }
            }
        }
        for (int index = 1; index < required.size(); index++) {
            var previous = byCondition.get(required.get(index - 1));
            var next = byCondition.get(required.get(index));
            if (previous != null && next != null && !previous.received().isBefore(next.issued())) {
                issues.add("overlapping_or_reordered_comparisons");
            }
        }
        var mismatches = samples.stream().filter(s -> !expected(s.condition()).equals(s.markers()))
                .map(s -> s.condition().name()).distinct().toList();
        boolean satisfied = missing.isEmpty() && issues.isEmpty() && mismatches.isEmpty();
        var code = satisfied ? "configuration.attribute-policy.comparison-observed"
                : "configuration.attribute-policy.evidence-incomplete";
        var details = new LinkedHashMap<String, Object>();
        details.put("required_conditions", required.stream().map(Enum::name).toList());
        details.put("missing_conditions", missing.stream().map(Enum::name).toList());
        details.put("evidence_issues", issues.stream().distinct().toList());
        details.put("unobserved_policy_differences", mismatches);
        // Capability/setup failure or an unproven cause is not a target violation.
        return new CaseOutcome(satisfied ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                satisfied ? null : "attribute_policy_comparison_unproven", code, code,
                samples.stream().flatMap(s -> s.evidence().stream()).distinct().toList(), details);
    }

    private static boolean fingerprint(String value) {
        return value != null && value.matches("[0-9a-f]{64}");
    }
}
