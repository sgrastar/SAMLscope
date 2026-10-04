package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import java.util.*;

/** The approved default set is all-of. Only actual native consumption can refute prevention. */
final class DefaultAlgorithmComparison {
    static final String CASE="IIP-ALG08-c-idp-01",CAMPAIGN="default-algorithm-prevention";
    static final List<String> REQUIRED=List.of("sha256-control","invalid-sha256-signature",
            "md5-digest","rsa-md5","rsa15-encrypted-id","oaep-encrypted-id-control");
    record Sample(String fixture,DefaultAlgorithmNativeAdapter.Use nativeUse,List<EvidenceRef> evidence) {
        Sample {evidence=List.copyOf(evidence);}
    }
    static CaseOutcome evaluate(String run,String adapter,List<Sample> samples,List<EvidenceRef> proof) {
        var byId=new LinkedHashMap<String,Sample>();var refs=new LinkedHashSet<EvidenceRef>(proof);
        for(var sample:samples) {
            if(!REQUIRED.contains(sample.fixture())||byId.put(sample.fixture(),sample)!=null
                    ||sample.nativeUse()==null||sample.nativeUse().policyId().isBlank()
                    ||sample.nativeUse().consumerId().isBlank()||sample.nativeUse().evidence().isEmpty())
                return missing("ambiguous_native_algorithm_observations",List.copyOf(refs));
            refs.addAll(sample.evidence());refs.addAll(sample.nativeUse().evidence());
        }
        var normal=byId.get("sha256-control");var invalid=byId.get("invalid-sha256-signature");
        if(!decision(normal,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS)
                ||!decision(invalid,DefaultAlgorithmNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION)
                ||!sameConsumer(normal,invalid))return missing("signature_controls_unproven",List.copyOf(refs));
        var counterexamples=new ArrayList<String>();var completed=new ArrayList<String>();
        completed.add(normal.fixture());completed.add(invalid.fixture());
        for(var fixture:List.of("md5-digest","rsa-md5")) {
            var sample=byId.get(fixture);if(!signatureScopeMatches(normal,sample))continue;
            if(decision(sample,DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION))completed.add(fixture);
            if(decision(sample,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS))counterexamples.add(fixture);
        }
        var oaep=byId.get("oaep-encrypted-id-control");var rsa15=byId.get("rsa15-encrypted-id");
        if(decision(oaep,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS)&&sameConsumer(oaep,rsa15)) {
            completed.add(oaep.fixture());
            if(decision(rsa15,DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION))completed.add(rsa15.fixture());
            if(decision(rsa15,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS))counterexamples.add(rsa15.fixture());
        }
        var details=new LinkedHashMap<String,Object>();details.put("run_id",run);details.put("evidence_adapter",adapter);
        details.put("required_observations",REQUIRED);details.put("completed_observations",List.copyOf(completed));
        details.put("weak_algorithm_counterexamples",List.copyOf(counterexamples));
        details.put("default_algorithm_configuration_unchanged",true);
        if(!counterexamples.isEmpty())return outcome(Outcome.VIOLATED,null,"algorithm.default-prevention.weak-consumption-observed",refs,details);
        if(completed.containsAll(REQUIRED))return outcome(Outcome.SATISFIED,null,"algorithm.default-prevention.observed",refs,details);
        details.put("required_action","administrator_evidence");
        return outcome(Outcome.NOT_VERIFIED,"default_algorithm_consumer_evidence_incomplete","algorithm.default-prevention.unproven",refs,details);
    }
    private static boolean sameConsumer(Sample a,Sample b) {return a!=null&&b!=null
            &&a.nativeUse().policyId().equals(b.nativeUse().policyId())
            &&a.nativeUse().consumerId().equals(b.nativeUse().consumerId());}
    /** Only an original-bound RSA-MD5 rejection may occur before the normal signature consumer. */
    private static boolean signatureScopeMatches(Sample control,Sample candidate) {
        if(sameConsumer(control,candidate))return true;
        if(control==null||candidate==null||!"sha256-control".equals(control.fixture())
                ||!"rsa-md5".equals(candidate.fixture())
                ||!decision(control,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS)
                ||!decision(candidate,DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION)
                ||!control.nativeUse().policyId().equals(candidate.nativeUse().policyId())
                ||control.nativeUse().ingressRejectionProof()!=null)return false;
        var proof=candidate.nativeUse().ingressRejectionProof();
        return proof!=null&&control.nativeUse().consumerId().equals(proof.acceptedControlConsumerId())
                &&!control.evidence().isEmpty()&&control.evidence().getFirst().equals(proof.positiveControlInput())
                &&candidate.nativeUse().evidence().contains(proof.positiveControlInput())
                &&candidate.nativeUse().evidence().contains(proof.nativeDecoderOriginal());
    }
    private static boolean decision(Sample sample,DefaultAlgorithmNativeAdapter.Decision d){return sample!=null&&sample.nativeUse().decision()==d;}
    static CaseOutcome missing(String why,List<EvidenceRef> refs){return new CaseOutcome(Outcome.NOT_VERIFIED,why,
            "algorithm.default-prevention.unproven","algorithm.default-prevention.unproven",refs,
            Map.of("required_action","administrator_evidence","instructions_en",
                    "Prepare the target's unchanged default algorithm policy and native consumer evidence before any additional login."));}
    private static CaseOutcome outcome(Outcome result,String why,String reason,Collection<EvidenceRef> refs,Map<String,Object> details){return new CaseOutcome(result,why,reason,reason,List.copyOf(refs),Map.copyOf(details));}
}
