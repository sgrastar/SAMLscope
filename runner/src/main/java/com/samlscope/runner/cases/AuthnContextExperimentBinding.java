package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.core.evaluation.*;

/** Only trusted native preparation selects conditions; originals supply request and response values. */
final class AuthnContextExperimentBinding {
    record Exchange(String condition,String metadataReference,String requestReference,String responseReference) {}
    record Preparation(String runId,String caseId,AuthnContextComparison.Preparation nativeContext,List<Exchange> exchanges, List<Exchange> availabilityControls) {
        Preparation { exchanges=List.copyOf(exchanges); availabilityControls=availabilityControls==null?List.of():List.copyOf(availabilityControls); }
        List<Exchange> allExchanges() { var all=new ArrayList<>(exchanges);all.addAll(availabilityControls);return List.copyOf(all); }
    }
    static CaseOutcome evaluate(AuthnContextProtocolEvidence.Collected protocol,Preparation preparation) {
        var issues=new ArrayList<>(protocol.issues());var samples=new ArrayList<AuthnContextComparison.Sample>();
        var evidence=new LinkedHashSet<EvidenceRef>();
        if(preparation==null || preparation.nativeContext()==null) {
            return AuthnContextComparison.evaluate("",null,samples,List.of("verified_preparation_unavailable"));
        }
        var prepared=preparation.nativeContext();
        if(!Objects.equals(protocol.runId(),preparation.runId())) issues.add("preparation_scope_mismatch");
        if(protocol.observations().size()!=preparation.allExchanges().size()) issues.add("prepared_exchange_count_differs");
        if(protocol.observations().stream().map(AuthnContextProtocolEvidence.Observation::metadataHash).distinct().count()!=1) issues.add("metadata_changed");
        if(protocol.observations().stream().map(AuthnContextProtocolEvidence.Observation::requestFingerprint).distinct().count()!=1) issues.add("uncontrolled_request_input_changed");
        var byRequest=new HashMap<String,AuthnContextProtocolEvidence.Observation>();
        for(var observation:protocol.observations()) {
            if(observation.evidence().size()!=4 || observation.evidence().stream().anyMatch(e->!"transcript".equals(e.kind()))) {
                issues.add("protocol_provenance_incomplete");continue;
            }
            if(byRequest.put(observation.evidence().get(2).reference(),observation)!=null) issues.add("ambiguous_request");
        }
        var used=new HashSet<String>();
        for(var binding:preparation.exchanges()) {
            var observed=byRequest.get(binding.requestReference());
            if(observed==null || !used.add(binding.requestReference()) || !Objects.equals(binding.condition(),observed.condition())
                    || !Objects.equals(binding.metadataReference(),observed.evidence().get(1).reference())
                    || !Objects.equals(binding.responseReference(),observed.evidence().get(3).reference())) {
                issues.add("prepared_exchange_unobserved");continue;
            }
            evidence.addAll(observed.evidence());
            samples.add(new AuthnContextComparison.Sample(observed.condition(),prepared.experiment(),observed.entityId(),
                prepared.loginFingerprint(),prepared.configurationFingerprint(),observed.request(),observed.issued(),observed.received(),
                observed.response(),observed.evidence().subList(2,4)));
        }
        var requiredControls=new HashSet<String>();
        if ("IIP-SSO01-gc-idp-01".equals(preparation.caseId())) {
            for (var kind:com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.ReferenceKind.values())
                for (var rank:List.of("low","medium")) requiredControls.add((kind.name().equals("CLASS")?"class-":"declaration-")+rank);
        }
        var seenControls=new HashSet<String>();
        for(var binding:preparation.availabilityControls()) {
            var observed=byRequest.get(binding.requestReference());
            if (observed==null || !used.add(binding.requestReference()) || !seenControls.add(binding.condition())
                    || !requiredControls.contains(binding.condition()) || !Objects.equals(binding.condition(),observed.condition())
                    || !Objects.equals(binding.metadataReference(),observed.evidence().get(1).reference())
                    || !Objects.equals(binding.responseReference(),observed.evidence().get(3).reference())) {
                issues.add("availability_control_unbound");continue;
            }
            evidence.addAll(observed.evidence());
            var kind=observed.request().kind();var nativeContext=prepared.contexts().get(kind);
            if (nativeContext==null) {issues.add("availability_control_native_context_missing");continue;}
            String prefix=kind.name().equals("CLASS")?"class-":"declaration-";
            String expected=binding.condition().endsWith("-low")?nativeContext.references().low():nativeContext.references().medium();
            var returned=kind.name().equals("CLASS")?observed.response().classReference():observed.response().declarationReference();
            if (!binding.condition().startsWith(prefix)
                    || observed.request().comparison()!=com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.Comparison.EXACT
                    || !observed.request().references().equals(List.of(expected))
                    || observed.response().kind()!=AuthnContextResponseEvidence.ResponseKind.SUCCESS
                    || !returned.equals(Optional.of(expected))) issues.add("availability_control_not_observed");
        }
        if (!seenControls.equals(requiredControls)) issues.add("availability_controls_incomplete");
        var result=AuthnContextComparison.evaluate(preparation.caseId(),prepared,samples,issues);
        return new CaseOutcome(result.outcome(),result.notVerifiedReason(),result.reasonCode(),result.reasonMessageKey(),List.copyOf(evidence),result.details());
    }
}
