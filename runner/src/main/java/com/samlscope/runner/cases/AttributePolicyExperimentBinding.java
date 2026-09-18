package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.cases.AttributePolicyComparison.Condition;

/** Joins verified preparation to exact protocol references, never by time proximity or variant alone. */
final class AttributePolicyExperimentBinding {
    /**
     * Internal adapter output, not a public submission DTO. An adapter must verify preparation,
     * account/session provenance and controlled-input equivalence before constructing this value.
     * A UI confirmation, caller-supplied hash, or the anchor attribute alone does not qualify.
     */
    record ExchangePreparation(Condition condition, String requestReference, String responseReference,
                               String policyFingerprint, String principalFingerprint, String stableInputFingerprint) {}
    record Preparation(String runId, String experimentId, List<ExchangePreparation> exchanges) {
        Preparation { exchanges = List.copyOf(exchanges); }
    }

    static CaseOutcome evaluate(String id, AttributePolicyProtocolEvidence.Collected protocol,
                                Optional<Preparation> preparation) {
        var issues = new ArrayList<>(protocol.issues());
        var samples = new ArrayList<AttributePolicyComparison.Sample>();
        var required = AttributePolicyComparison.required(id);
        if (preparation.isEmpty()) {
            issues.add("verified_preparation_unavailable");
            return AttributePolicyComparison.evaluate(id, samples, issues);
        }
        var prepared = preparation.orElseThrow();
        if (!Objects.equals(protocol.runId(), prepared.runId()) || prepared.experimentId() == null
                || prepared.experimentId().isBlank()) {
            issues.add("preparation_scope_mismatch");
            return AttributePolicyComparison.evaluate(id, samples, issues);
        }
        var byRequest = new HashMap<String, AttributePolicyProtocolEvidence.Observation>();
        for (var observation : protocol.observations()) {
            if (observation.evidence().size() != 4
                    || observation.evidence().stream().anyMatch(e -> !"transcript".equals(e.kind()))) {
                issues.add("protocol_provenance_incomplete");
                continue;
            }
            var request = observation.evidence().get(2).reference();
            if (byRequest.put(request, observation) != null) issues.add("ambiguous_protocol_request");
        }
        var usedRequests = new HashSet<String>();
        var inputFingerprints = new HashSet<String>();
        var provenance = new LinkedHashSet<EvidenceRef>();
        for (var binding : prepared.exchanges()) {
            if (!required.contains(binding.condition())) continue;
            if (!usedRequests.add(binding.requestReference())) {
                issues.add("preparation_reuses_request");
                continue;
            }
            var observation = byRequest.get(binding.requestReference());
            if (observation == null || !Objects.equals(binding.responseReference(), observation.evidence().get(3).reference())) {
                issues.add("prepared_exchange_unobserved");
                continue;
            }
            if (!matches(binding.condition(), observation.variant(), observation.selector())) {
                issues.add("prepared_condition_mismatch");
                continue;
            }
            inputFingerprints.add(observation.attributes().attributeInputFingerprint());
            provenance.addAll(observation.evidence());
            samples.add(new AttributePolicyComparison.Sample(prepared.experimentId(), binding.condition(),
                    binding.policyFingerprint(), binding.principalFingerprint(), observation.entityId(),
                    observation.metadataFingerprint(), binding.stableInputFingerprint(), observation.issued(),
                    observation.received(), observation.attributes().markers(), observation.evidence().subList(2, 4)));
        }
        if (inputFingerprints.size() > 1) issues.add("attribute_input_changed");
        var outcome = AttributePolicyComparison.evaluate(id, samples, issues);
        return new CaseOutcome(outcome.outcome(), outcome.notVerifiedReason(), outcome.reasonCode(),
                outcome.reasonMessageKey(), List.copyOf(provenance), outcome.details());
    }

    private static boolean matches(Condition condition, String variant, String selector) {
        return switch (condition) {
            case BASELINE -> "control".equals(variant) && selector.isEmpty();
            case ENTITY_PRESENT -> "attribute-policy-entity-present".equals(variant) && selector.isEmpty();
            case ENTITY_ABSENT -> "attribute-policy-entity-absent".equals(variant) && selector.isEmpty();
            case REQUESTED_REQUIRED -> "attribute-policy-requested-required".equals(variant) && selector.isEmpty();
            case REQUESTED_OPTIONAL -> "attribute-policy-requested-optional".equals(variant) && selector.isEmpty();
            case REQUESTED_ABSENT -> "attribute-policy-requested-absent".equals(variant) && selector.isEmpty();
            case INDEX_ZERO, INDEX_ZERO_REPEAT -> "attribute-policy-indexed".equals(variant) && "0".equals(selector);
            case INDEX_ONE -> "attribute-policy-indexed".equals(variant) && "1".equals(selector);
        };
    }
}
