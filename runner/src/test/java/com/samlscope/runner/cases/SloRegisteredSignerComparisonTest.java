package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class SloRegisteredSignerComparisonTest {
    private static final String RUN="run_00000000000000000000000000";
    private static final List<EvidenceRef> ORIGINALS=List.of(new EvidenceRef("transcript","tx_original"));
    private static SloRegisteredSignerComparison.Sample sample(String id,SloRegisteredSignerNativeAdapter.Decision nativeDecision,boolean success){
        return new SloRegisteredSignerComparison.Sample(id,nativeDecision,success,List.of(new EvidenceRef("transcript","tx_"+id)));
    }
    private static List<SloRegisteredSignerComparison.Sample> complete(){return List.of(
            sample("local-invalid-signature",SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE,false),
            sample("local-other-signer",SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE,false),
            sample("local-normal",SloRegisteredSignerNativeAdapter.Decision.ACCEPTED,true));}
    private static CaseOutcome evaluate(List<SloRegisteredSignerComparison.Sample> samples,boolean optionalObserved){
        return SloRegisteredSignerComparison.evaluate(RUN,"test-native-slo",samples,ORIGINALS,optionalObserved,false);
    }
    @Test void unobservedOptionalIncomingResponseUsesApprovedNote(){
        var outcome=evaluate(complete(),false);assertEquals(Outcome.SATISFIED_WITH_NOTE,outcome.outcome());
        assertEquals("slo.signer.request-observed-response-unobserved",outcome.reasonCode());
        assertEquals(true,outcome.details().get("normal_control_ends_session"));assertTrue(outcome.evidence().containsAll(ORIGINALS));
    }
    @Test void observedOptionalConsumerWithoutItsSignerControlsRemainsUnverified(){assertEquals(Outcome.NOT_VERIFIED,evaluate(complete(),true).outcome());}
    @Test void mathematicallyValidWrongSignerAcceptedIsWholeCaseViolationOnlyWithBothControls(){
        var values=new ArrayList<>(complete());values.set(1,sample("local-other-signer",SloRegisteredSignerNativeAdapter.Decision.ACCEPTED,true));
        assertEquals(Outcome.VIOLATED,evaluate(values,false).outcome());
        values.set(0,sample("local-invalid-signature",SloRegisteredSignerNativeAdapter.Decision.ACCEPTED,true));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
    }
    @Test void httpOnlyMissingDeliveryAndAmbiguousFailureNeverConclude(){
        for(var id:List.of("local-invalid-signature","local-other-signer","local-normal")){
            var values=new ArrayList<>(complete());int index=SloRegisteredSignerComparison.FIXTURES.indexOf(id);
            values.set(index,sample(id,SloRegisteredSignerNativeAdapter.Decision.UNPROVEN,false));assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
            values.remove(index);assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
        }
    }
    @Test void normalOwnSessionFailureDoesNotProveSignerRestriction(){
        var values=new ArrayList<>(complete());values.set(2,sample("local-normal",SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE,false));assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
    }
    @Test void rejectionContradictedBySignedSuccessRemainsUnverified(){
        var values=new ArrayList<>(complete());values.set(1,sample("local-other-signer",SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE,true));assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
    }
    @Test void unknownDuplicateOrNullNativeDecisionCannotCreateSuccess(){
        var values=new ArrayList<>(complete());values.add(values.getFirst());assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
        values=new ArrayList<>(complete());values.set(1,sample("foreign-fixture",SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE,false));assertEquals(Outcome.NOT_VERIFIED,evaluate(values,false).outcome());
        assertThrows(NullPointerException.class,()->sample("local-other-signer",null,false));
    }
}
