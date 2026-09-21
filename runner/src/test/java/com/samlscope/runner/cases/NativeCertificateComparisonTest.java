package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.*;

class NativeCertificateComparisonTest {
    private List<NativeCertificateComparison.Sample> accepted() {
        return NativeCertificateComparison.ALL.stream().sorted().map(v -> new NativeCertificateComparison.Sample(v,
                "run_control", "https://sp.example", true, true, true,
                NativeCertificateComparison.Decision.SIGNED_SUCCESS,
                NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION,
                List.of(new EvidenceRef("transcript", v)))).toList();
    }
    private NativeCertificateComparison.Sample decision(NativeCertificateComparison.Sample s, NativeCertificateComparison.Decision d) {
        return new NativeCertificateComparison.Sample(s.variant(),s.runId(),s.entityId(),s.conditionVerified(),
                s.positiveSignatureVerified(),s.invalidControlVerified(),d,s.negativeDecision(),s.evidence());
    }
    @Test void allConditionsAndTheirControlsCanEstablishKeyUse() {
        for (var id : NativeCertificateComparison.CASES)
            assertEquals(Outcome.SATISFIED,NativeCertificateComparison.evaluate(id,accepted(),List.of()).outcome());
    }
    @Test void validRequestRejectionRequiresTheMatchingApprovedCondition() {
        var expired = accepted().stream().map(s -> s.variant().equals("certificate-expired")
                ? decision(s,NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION) : s).toList();
        assertEquals(Outcome.VIOLATED,NativeCertificateComparison.evaluate(NativeCertificateComparison.VALIDITY,expired,List.of()).outcome());
        assertEquals(Outcome.SATISFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.CONTAINER,expired,List.of()).outcome());
        assertEquals(Outcome.VIOLATED,NativeCertificateComparison.evaluate(NativeCertificateComparison.RUNTIME,expired,List.of()).outcome());
        var future = accepted().stream().map(s -> s.variant().equals("certificate-not-yet-valid")
                ? decision(s,NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION) : s).toList();
        for (var id : NativeCertificateComparison.CASES)
            assertEquals(Outcome.VIOLATED,NativeCertificateComparison.evaluate(id,future,List.of()).outcome());
    }
    @Test void silenceAndAlwaysRejectingTargetsCannotEstablishAViolation() {
        for (var d : List.of(NativeCertificateComparison.Decision.UNOBSERVED,NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION)) {
            var rows=accepted().stream().map(s->decision(s,d)).toList();
            assertEquals(Outcome.NOT_VERIFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.VALIDITY,rows,List.of()).outcome());
        }
    }
    @Test void missingVariantsOrCorruptProvenanceDoNotPass() {
        for (var variant : NativeCertificateComparison.ALL) {
            if (variant.equals("certificate-expired")) continue;
            var rows=accepted().stream().filter(s->!s.variant().equals(variant)).toList();
            assertEquals(Outcome.NOT_VERIFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.CONTAINER,rows,List.of()).outcome());
        }
        var rows=new ArrayList<>(accepted());rows.add(rows.getFirst());
        assertEquals(Outcome.NOT_VERIFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.CONTAINER,rows,List.of()).outcome());
        assertEquals(Outcome.NOT_VERIFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.CONTAINER,accepted(),List.of("wrong-native-event")).outcome());
    }
    @Test void suiteErrorsAndMixedRunsRemainUnverified() {
        for (int i=0;i<5;i++) {
            var rows=new ArrayList<>(accepted());var s=rows.getFirst();
            rows.set(0,new NativeCertificateComparison.Sample(s.variant(),i==0?"other-run":s.runId(),s.entityId(),
                    i!=1,i!=2,i!=3,s.positiveDecision(),i==4?NativeCertificateComparison.Decision.SIGNED_SUCCESS:s.negativeDecision(),s.evidence()));
            assertEquals(Outcome.NOT_VERIFIED,NativeCertificateComparison.evaluate(NativeCertificateComparison.CONTAINER,rows,List.of()).outcome());
        }
    }
    @Test void runtimeInterpretationRequiresEveryConditionIncludingExpiration() {
        for (var variant : NativeCertificateComparison.ALL) {
            var incomplete = accepted().stream().filter(s -> !s.variant().equals(variant)).toList();
            assertEquals(Outcome.NOT_VERIFIED, NativeCertificateComparison.evaluate(
                    NativeCertificateComparison.RUNTIME, incomplete, List.of()).outcome(), variant);
        }
        // The approved runtime mutant honors a critical extension after accepting metadata.
        var mutant = accepted().stream().map(s -> s.variant().equals("certificate-critical-extension")
                ? decision(s, NativeCertificateComparison.Decision.NATIVE_SIGNATURE_REJECTION) : s).toList();
        assertEquals(Outcome.VIOLATED, NativeCertificateComparison.evaluate(
                NativeCertificateComparison.RUNTIME, mutant, List.of()).outcome());
        var unobserved = accepted().stream().map(s -> s.variant().equals("certificate-critical-extension")
                ? decision(s, NativeCertificateComparison.Decision.UNOBSERVED) : s).toList();
        assertEquals(Outcome.NOT_VERIFIED, NativeCertificateComparison.evaluate(
                NativeCertificateComparison.RUNTIME, unobserved, List.of()).outcome());
    }
}
