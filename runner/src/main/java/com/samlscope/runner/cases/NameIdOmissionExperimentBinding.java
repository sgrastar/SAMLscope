package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;

/** Trusted native-adapter preparation bound to exact cryptographically observed original exchanges. */
final class NameIdOmissionExperimentBinding {
    record ExchangePreparation(NameIdOmissionComparison.Condition condition, String metadataReference,
            String requestReference, String responseReference, String loginInputFingerprint,
            String stableInputFingerprint) {}
    record Preparation(String runId, String experimentId, List<ExchangePreparation> exchanges) {
        Preparation { exchanges=List.copyOf(exchanges); }
    }

    static CaseOutcome evaluate(NameIdOmissionProtocolEvidence.Collected protocol, Optional<Preparation> preparation) {
        var issues=new ArrayList<>(protocol.issues());
        var samples=new ArrayList<NameIdOmissionComparison.Sample>();
        var provenance=new LinkedHashSet<EvidenceRef>();
        if(preparation.isEmpty()) {
            issues.add("verified_preparation_unavailable");
            return NameIdOmissionComparison.evaluate(samples,issues);
        }
        var prepared=preparation.orElseThrow();
        if(!Objects.equals(protocol.runId(),prepared.runId()) || prepared.experimentId()==null || prepared.experimentId().isBlank()) {
            issues.add("preparation_scope_mismatch");return NameIdOmissionComparison.evaluate(samples,issues);
        }
        if(prepared.exchanges().size()!=2 || protocol.observations().size()!=2) issues.add("ambiguous_experiment_size");
        if(protocol.observations().stream().map(NameIdOmissionProtocolEvidence.Observation::metadataHash).distinct().count()!=1) {
            issues.add("imported_metadata_changed");
        }
        if(protocol.observations().stream().map(NameIdOmissionProtocolEvidence.Observation::requestFingerprint).distinct().count()!=1) {
            issues.add("protocol_request_input_changed");
        }
        var byRequest=new HashMap<String,NameIdOmissionProtocolEvidence.Observation>();
        for(var observation:protocol.observations()) {
            if(observation.evidence().size()!=4 || observation.evidence().stream().anyMatch(e->!"transcript".equals(e.kind()))) {
                issues.add("protocol_provenance_incomplete");continue;
            }
            if(byRequest.put(observation.evidence().get(2).reference(),observation)!=null) issues.add("ambiguous_protocol_request");
        }
        var used=new HashSet<String>();
        for(var binding:prepared.exchanges()) {
            var observed=byRequest.get(binding.requestReference());
            if(!used.add(binding.requestReference()) || observed==null
                    || !Objects.equals(binding.metadataReference(),observed.evidence().get(1).reference())
                    || !Objects.equals(binding.responseReference(),observed.evidence().get(3).reference())
                    || binding.condition()!=observed.condition()) {
                issues.add("prepared_exchange_unobserved");continue;
            }
            provenance.addAll(observed.evidence());
            samples.add(new NameIdOmissionComparison.Sample(prepared.experimentId(),binding.condition(),observed.entityId(),
                binding.loginInputFingerprint(),binding.stableInputFingerprint(),observed.issued(),observed.received(),
                observed.presence(),observed.evidence().subList(2,4)));
        }
        var result=NameIdOmissionComparison.evaluate(samples,issues);
        return new CaseOutcome(result.outcome(),result.notVerifiedReason(),result.reasonCode(),result.reasonMessageKey(),
            List.copyOf(provenance),result.details());
    }
}
