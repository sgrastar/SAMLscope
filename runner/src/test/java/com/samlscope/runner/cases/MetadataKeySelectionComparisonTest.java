package com.samlscope.runner.cases;

import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static com.samlscope.runner.cases.MetadataKeySelectionComparison.*;

class MetadataKeySelectionComparisonTest {
    private List<Sample> baseline() {
        return List.of(row(FIRST,"a",Decision.SIGNED_SUCCESS), row(SECOND,"b",Decision.SIGNED_SUCCESS),
                row(UNADVERTISED,"c",Decision.NATIVE_SIGNATURE_REJECTION));
    }
    private Sample row(String variant, String signer, Decision decision) {
        return new Sample(variant,"run_keys","https://sp.example",List.of("a".repeat(64),"b".repeat(64)),
                signer.repeat(64),true,true,true,decision,List.of(new EvidenceRef("transcript",variant)));
    }
    @Test void fullKeySearchAndExhaustionMustBothBeObserved() {
        assertEquals(Outcome.SATISFIED,evaluate(baseline(),List.of()).outcome());
        for (var missing : REQUIRED)
            assertEquals(Outcome.NOT_VERIFIED,evaluate(baseline().stream().filter(s -> !s.variant().equals(missing)).toList(),List.of()).outcome());
    }
    @Test void firstKeyOnlyAndUnregisteredKeyMutantsAreDetected() {
        var firstOnly = new ArrayList<>(baseline()); firstOnly.set(1,row(SECOND,"b",Decision.NATIVE_SIGNATURE_REJECTION));
        assertEquals(Outcome.VIOLATED,evaluate(firstOnly,List.of()).outcome());
        var anyKey = new ArrayList<>(baseline()); anyKey.set(2,row(UNADVERTISED,"c",Decision.SIGNED_SUCCESS));
        assertEquals(Outcome.VIOLATED,evaluate(anyKey,List.of()).outcome());
    }
    @Test void absentNativeDecisionCannotProveExhaustion() {
        var rows = new ArrayList<>(baseline()); rows.set(2,row(UNADVERTISED,"c",Decision.UNOBSERVED));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(rows,List.of()).outcome());
        rows.set(0,row(FIRST,"a",Decision.NATIVE_SIGNATURE_REJECTION));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(rows,List.of()).outcome());
    }
    @Test void changedTrustOrBrokenSignaturesCannotSubstituteForUnadvertisedKey() {
        for (int mutation=0; mutation<7; mutation++) {
            var rows = new ArrayList<>(baseline()); var s=rows.get(2);
            rows.set(2,new Sample(s.variant(),mutation==0?"other":s.runId(),s.entityId(),
                    mutation==1?List.of("d".repeat(64),"e".repeat(64)):s.advertisedKeyHashes(),
                    mutation==2?"b".repeat(64):s.signerKeyHash(),mutation!=3,mutation!=4,mutation!=5,
                    s.decision(),mutation==6?List.of():s.evidence()));
            assertEquals(Outcome.NOT_VERIFIED,evaluate(rows,List.of()).outcome(),"mutation="+mutation);
        }
        var duplicated = new ArrayList<>(baseline());duplicated.add(duplicated.getFirst());
        assertEquals(Outcome.NOT_VERIFIED,evaluate(duplicated,List.of()).outcome());
    }
    private List<Sample> expanded() {
        return CONDITIONS.entrySet().stream().map(e -> {
            var c=e.getValue();
            var keys=java.util.stream.IntStream.range(0,c.count()).mapToObj(n ->
                    String.format("%064x",c.family().hashCode()+n)).toList();
            var signer=c.signerIndex()<0?"f".repeat(64):keys.get(c.signerIndex());
            return new Sample(e.getKey(),"run_keys","https://sp.example",keys,signer,true,true,true,
                    c.signerIndex()<0?Decision.NATIVE_SIGNATURE_REJECTION:Decision.SIGNED_SUCCESS,
                    List.of(new EvidenceRef("transcript",e.getKey())));
        }).toList();
    }
    @Test void allKeyCountsAndOmittedUseConditionsMustBeCovered() {
        for(var id:CASES) {
            assertEquals(Outcome.SATISFIED,evaluate(id,expanded(),List.of()).outcome());
            for(var missing:required(id))
                assertEquals(Outcome.NOT_VERIFIED,evaluate(id,expanded().stream()
                        .filter(s -> !s.variant().equals(missing)).toList(),List.of()).outcome(),id+":"+missing);
        }
    }
    @Test void eachRequiredAdvertisedSignerHasDetectionPower() {
        for(var id:List.of(ANY_PURPOSE,KEY_COUNT))for(var variant:required(id)) {
            if(variant.equals("entity-root"))continue;
            var mutant=expanded().stream().map(s -> !s.variant().equals(variant)?s:
                    new Sample(s.variant(),s.runId(),s.entityId(),s.advertisedKeyHashes(),s.signerKeyHash(),
                            true,true,true,Decision.NATIVE_SIGNATURE_REJECTION,s.evidence())).toList();
            assertEquals(Outcome.VIOLATED,evaluate(id,mutant,List.of()).outcome(),id+":"+variant);
        }
    }
    @Test void threeKeyFixturesCannotReuseTheFirstSignerOrChangeKeysBetweenRequests() {
        for(boolean changeKeys:List.of(false,true)) {
            var mutant=expanded().stream().map(s -> !s.variant().equals("three-signing-keys")?s:
                    new Sample(s.variant(),s.runId(),s.entityId(),
                            changeKeys?List.of("a".repeat(64),"b".repeat(64),"c".repeat(64)):s.advertisedKeyHashes(),
                            changeKeys?"c".repeat(64):s.advertisedKeyHashes().getFirst(),true,true,true,s.decision(),s.evidence())).toList();
            assertEquals(Outcome.NOT_VERIFIED,evaluate(KEY_COUNT,mutant,List.of()).outcome());
        }
    }

    @Test void bothKeyInfoFormsAreIndependentlyRequiredAndCanDetectTheOtherRejection() {
        for(var variant:required(REPRESENTATION)) {
            var mutant=expanded().stream().map(s -> !s.variant().equals(variant)?s:
                    new Sample(s.variant(),s.runId(),s.entityId(),s.advertisedKeyHashes(),s.signerKeyHash(),
                            true,true,true,Decision.NATIVE_SIGNATURE_REJECTION,s.evidence())).toList();
            assertEquals(Outcome.VIOLATED,evaluate(REPRESENTATION,mutant,List.of()).outcome(),variant);
        }
        var none=expanded().stream().map(s -> new Sample(s.variant(),s.runId(),s.entityId(),s.advertisedKeyHashes(),
                s.signerKeyHash(),true,true,true,Decision.NATIVE_SIGNATURE_REJECTION,s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,evaluate(REPRESENTATION,none,List.of()).outcome());
    }

    @Test void certificateEqualityMutantViolatesButNameOnlyAcceptanceFailsTheControl() {
        var sameRejected=expanded().stream().map(s -> !s.variant().equals(SAME_KEY)?s:
                new Sample(s.variant(),s.runId(),s.entityId(),s.advertisedKeyHashes(),s.signerKeyHash(),
                        true,true,true,Decision.NATIVE_SIGNATURE_REJECTION,s.evidence())).toList();
        assertEquals(Outcome.VIOLATED,evaluate(PUBLIC_KEY,sameRejected,List.of()).outcome());
        var wrongAccepted=expanded().stream().map(s -> !s.variant().equals(OTHER_KEY)?s:
                new Sample(s.variant(),s.runId(),s.entityId(),s.advertisedKeyHashes(),s.signerKeyHash(),
                        true,true,true,Decision.SIGNED_SUCCESS,s.evidence())).toList();
        assertEquals(Outcome.NOT_VERIFIED,evaluate(PUBLIC_KEY,wrongAccepted,List.of()).outcome());
    }

    @Test void anUnrelatedUnavailableFixtureDoesNotInvalidateACompleteCase() {
        for(var id:CASES) {
            var owned=expanded().stream().filter(s -> required(id).contains(s.variant())).toList();
            assertEquals(Outcome.SATISFIED,evaluate(id,owned,List.of()).outcome(),id);
            for(var missing:required(id)) {
                var result=evaluate(id,owned.stream().filter(s -> !s.variant().equals(missing)).toList(),List.of());
                assertEquals(Outcome.NOT_VERIFIED,result.outcome());
                assertEquals(List.of(missing),result.details().get("missing_variants"));
            }
        }
    }

}
