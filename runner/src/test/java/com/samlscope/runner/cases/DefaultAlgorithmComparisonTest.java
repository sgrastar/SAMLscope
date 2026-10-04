package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class DefaultAlgorithmComparisonTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",ADAPTER="test-native-defaults";
    private DefaultAlgorithmComparison.Sample sample(String fixture,DefaultAlgorithmNativeAdapter.Decision decision,String policy,String consumer) {
        return new DefaultAlgorithmComparison.Sample(fixture,new DefaultAlgorithmNativeAdapter.Use(policy,consumer,decision,
                List.of(new EvidenceRef("transcript","native-"+fixture))),List.of(new EvidenceRef("transcript","request-"+fixture)));
    }
    private List<DefaultAlgorithmComparison.Sample> full(){return DefaultAlgorithmComparison.REQUIRED.stream().map(id->sample(id,
            id.equals("invalid-sha256-signature")?DefaultAlgorithmNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION:
            id.endsWith("control")?DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS:DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,
            "default-policy",id.contains("encrypted-id")?"decrypt-nameids":"verify-request")).toList();}
    private CaseOutcome evaluate(List<DefaultAlgorithmComparison.Sample> samples){return DefaultAlgorithmComparison.evaluate(RUN,ADAPTER,samples,List.of(new EvidenceRef("default-algorithm-native-evidence",RUN+"/manifest.json#sha256=public")));}
    @Test void allThreeDefaultWeakAlgorithmsRequireRealConsumerRefusalAndNormalControls(){
        var result=evaluate(full());assertEquals(Outcome.SATISFIED,result.outcome());assertEquals(RUN,result.details().get("run_id"));
        for(var omit:DefaultAlgorithmComparison.REQUIRED){var reduced=full().stream().filter(s->!omit.equals(s.fixture())).toList();assertEquals(Outcome.NOT_VERIFIED,evaluate(reduced).outcome(),omit);}
    }
    @Test void eachActuallyConsumedWeakAlgorithmIndependentlyRefutesTheRecommendedSet(){
        for(var weak:List.of("md5-digest","rsa-md5","rsa15-encrypted-id")){
            var samples=new ArrayList<>(full());int at=DefaultAlgorithmComparison.REQUIRED.indexOf(weak);var prior=samples.get(at);
            samples.set(at,sample(weak,DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,prior.nativeUse().policyId(),prior.nativeUse().consumerId()));
            var result=evaluate(samples);assertEquals(Outcome.VIOLATED,result.outcome(),weak);assertEquals(List.of(weak),result.details().get("weak_algorithm_counterexamples"));
        }
    }
    @Test void ignoredCiphertextOrUnrelatedHttpFailureDoesNotProveAlgorithmRejection(){
        for(var weak:List.of("md5-digest","rsa-md5","rsa15-encrypted-id")){
            var samples=new ArrayList<>(full());int at=DefaultAlgorithmComparison.REQUIRED.indexOf(weak);var prior=samples.get(at);
            samples.set(at,sample(weak,DefaultAlgorithmNativeAdapter.Decision.UNPROVEN,prior.nativeUse().policyId(),prior.nativeUse().consumerId()));
            assertEquals(Outcome.NOT_VERIFIED,evaluate(samples).outcome(),weak);
        }
    }
    @Test void alteredPolicyOrDifferentConsumerCannotSupplyAPositiveControl(){
        for(var fixture:List.of("invalid-sha256-signature","md5-digest","rsa-md5","rsa15-encrypted-id"))for(var field:List.of("policy","consumer")){
            var samples=new ArrayList<>(full());int at=DefaultAlgorithmComparison.REQUIRED.indexOf(fixture);var prior=samples.get(at);
            samples.set(at,sample(fixture,prior.nativeUse().decision(),field.equals("policy")?"temporarily-weakened":prior.nativeUse().policyId(),field.equals("consumer")?"unused-parser":prior.nativeUse().consumerId()));
            assertEquals(Outcome.NOT_VERIFIED,evaluate(samples).outcome(),fixture+field);
        }
    }
    @Test void invalidSignatureAcceptanceIsFailedControlAndNeverProductViolation(){
        var samples=new ArrayList<>(full());samples.set(1,sample("invalid-sha256-signature",DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,"default-policy","verify-request"));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(samples).outcome());
    }
    @Test void actualMd5CounterexampleCanBeConclusiveWithoutInventingMissingEncryptionProof(){
        var samples=new ArrayList<>(full().subList(0,3));samples.set(2,sample("md5-digest",DefaultAlgorithmNativeAdapter.Decision.CONSUMED_SUCCESS,"default-policy","verify-request"));
        assertEquals(Outcome.VIOLATED,evaluate(samples).outcome());
    }
    @Test void duplicateFixtureAndMissingNativeOriginalReferencesFailClosed(){
        var duplicate=new ArrayList<>(full());duplicate.add(duplicate.getFirst());assertEquals(Outcome.NOT_VERIFIED,evaluate(duplicate).outcome());
        var missing=new ArrayList<>(full());missing.set(2,new DefaultAlgorithmComparison.Sample("md5-digest",new DefaultAlgorithmNativeAdapter.Use("default-policy","verify-request",DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,List.of()),List.of()));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(missing).outcome());
    }
    private List<DefaultAlgorithmComparison.Sample> earlyRejection(String fixture,
            DefaultAlgorithmNativeAdapter.Decision decision,String policy,
            DefaultAlgorithmNativeAdapter.IngressRejectionProof proof,List<EvidenceRef> originals) {
        var samples=new ArrayList<>(full());int at=DefaultAlgorithmComparison.REQUIRED.indexOf(fixture);
        samples.set(at,new DefaultAlgorithmComparison.Sample(fixture,
                new DefaultAlgorithmNativeAdapter.Use(policy,"native-early-decoder",decision,originals,proof),
                List.of(new EvidenceRef("transcript","request-"+fixture))));return samples;
    }
    private DefaultAlgorithmNativeAdapter.IngressRejectionProof ingress(String consumer,String control,String decoder) {
        return new DefaultAlgorithmNativeAdapter.IngressRejectionProof(consumer,
                new EvidenceRef("transcript",control),new EvidenceRef("transcript",decoder));
    }
    private List<EvidenceRef> originals() {return List.of(new EvidenceRef("transcript","request-sha256-control"),
            new EvidenceRef("transcript","native-stock-decoder-original"));}
    private DefaultAlgorithmNativeAdapter.IngressRejectionProof boundIngress() {
        return ingress("verify-request","request-sha256-control","native-stock-decoder-original");
    }
    @Test void nativeEarlyRsaMd5RejectionBindsTheExactSuccessfulControlWithoutRenamingItsConsumer() {
        var samples=earlyRejection("rsa-md5",DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,
                "default-policy",boundIngress(),originals());
        assertEquals("native-early-decoder",samples.get(3).nativeUse().consumerId());
        assertEquals(Outcome.SATISFIED,evaluate(samples).outcome());
    }
    @Test void absentOriginalOrDifferentControlConsumerCannotBridgeAnEarlyRejection() {
        for(var proof:Arrays.asList(null,ingress("unrelated-consumer","request-sha256-control","native-stock-decoder-original"),
                ingress("verify-request","previous-run-control","native-stock-decoder-original")))
            assertEquals(Outcome.NOT_VERIFIED,evaluate(earlyRejection("rsa-md5",
                    DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,"default-policy",proof,originals())).outcome());
        for(var retained:List.of(originals().subList(0,1),originals().subList(1,2)))
            assertEquals(Outcome.NOT_VERIFIED,evaluate(earlyRejection("rsa-md5",
                    DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,"default-policy",boundIngress(),retained)).outcome());
    }
    @Test void earlyIngressCannotBorrowAResponseInsteadOfTheSuccessfulControlInput() {
        var reply=new EvidenceRef("transcript","response-sha256-control");
        var samples=earlyRejection("rsa-md5",DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,"default-policy",
                ingress("verify-request",reply.reference(),"native-stock-decoder-original"),
                List.of(reply,new EvidenceRef("transcript","native-stock-decoder-original")));
        var control=samples.getFirst();samples.set(0,new DefaultAlgorithmComparison.Sample(control.fixture(),control.nativeUse(),
                List.of(control.evidence().getFirst(),reply)));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(samples).outcome());
    }
    @Test void earlyIngressCannotProveDifferentAlgorithmsAcceptanceOrAnInvalidSignatureControl() {
        for(var fixture:DefaultAlgorithmComparison.REQUIRED)for(var decision:DefaultAlgorithmNativeAdapter.Decision.values()) {
            if(fixture.equals("rsa-md5")&&decision==DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION)continue;
            assertEquals(Outcome.NOT_VERIFIED,evaluate(earlyRejection(fixture,decision,"default-policy",
                    boundIngress(),originals())).outcome(),fixture+decision);
        }
        assertEquals(Outcome.NOT_VERIFIED,evaluate(earlyRejection("rsa-md5",
                DefaultAlgorithmNativeAdapter.Decision.ALGORITHM_REJECTION,"changed-policy",boundIngress(),originals())).outcome());
    }
    @Test void ingressProofRequiresDistinctRecorderOriginals() {
        assertThrows(IllegalArgumentException.class,()->ingress("verify-request","same","same"));
        assertThrows(IllegalArgumentException.class,()->new DefaultAlgorithmNativeAdapter.IngressRejectionProof("verify-request",
                new EvidenceRef("receipt-claim","declared-success"),new EvidenceRef("transcript","native-stock-decoder-original")));
    }
}
