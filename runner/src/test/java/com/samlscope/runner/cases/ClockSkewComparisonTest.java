package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class ClockSkewComparisonTest {
    private static final String RUN="run_00000000000000000000000000",ADAPTER="unit-test-native-clock-consumer";
    private static final Instant NOW=Instant.parse("2026-10-03T09:00:00Z");
    private static final Duration T=Duration.ofSeconds(75);
    private ClockSkewComparison.Sample sample(String id,ClockSkewNativeAdapter.Decision decision) {
        String path=id.startsWith("issue-")?"request-policy":id.startsWith("conditions-")?"upstream-assertion-consumer":"metadata-resolver";
        boolean future=id.endsWith("future")||id.equals("conditions-not-before");
        int offset=id.startsWith("issue-outside-")?100:50;
        Instant value=id.endsWith("control")||id.equals("issue-invalid-signature")?null
                :future?NOW.plusSeconds(offset):NOW.minusSeconds(offset);
        return new ClockSkewComparison.Sample(id,value,new ClockSkewNativeAdapter.NativeUse(path,path,T,NOW,NOW.plusSeconds(1),decision,
                List.of(new EvidenceRef("transcript","tx_native_"+id))),List.of(new EvidenceRef("transcript","tx_input_"+id)));
    }
    private List<ClockSkewComparison.Sample> positive() {
        return ClockSkewComparison.REQUIRED.stream().map(id->sample(id,id.equals("issue-invalid-signature")
                ?ClockSkewNativeAdapter.Decision.INVALID_SIGNATURE_REJECTION:ClockSkewNativeAdapter.Decision.ACCEPTED)).toList();
    }
    private CaseOutcome evaluate(List<ClockSkewComparison.Sample> rows){return ClockSkewComparison.evaluate(RUN,ADAPTER,rows,List.of());}
    @Test void allApprovedPathsPlusSameConsumerControlsGiveSatisfiedAndOutsideAcceptanceOnlyAdvisory() {
        var result=evaluate(positive());assertEquals(Outcome.SATISFIED,result.outcome());
        assertEquals(false,result.details().get("advisory_affects_verdict"));
        assertEquals(List.of("issue-outside-past","issue-outside-future"),result.details().get("outside_t_acceptance_advisory"));
        assertEquals(false,result.details().get("suite_tolerance_used"));
    }
    @Test void ordinaryRequestSuccessCannotStandInForUnconsumedConditionsOrMetadata() {
        var partial=positive().stream().filter(s->s.fixtureId().startsWith("issue-")).toList();
        assertEquals(Outcome.NOT_VERIFIED,evaluate(partial).outcome());
        assertEquals("administrator_evidence",evaluate(partial).details().get("required_action"));
    }
    @Test void approvedInsideToleranceRefusalMutantIsDetectedButGenericRefusalIsUnproven() {
        var rows=new ArrayList<>(positive());int index=ClockSkewComparison.REQUIRED.indexOf("issue-within-future");
        rows.set(index,sample("issue-within-future",ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION));
        assertEquals(Outcome.VIOLATED,evaluate(rows).outcome());
        rows.set(index,sample("issue-within-future",ClockSkewNativeAdapter.Decision.UNPROVEN));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(rows).outcome());
    }
    @Test void anErrorOrSuccessFromAnotherPolicyContextDoesNotCompleteTheCase() {
        var rows=new ArrayList<>(positive());var original=rows.get(2);var u=original.nativeUse();
        rows.set(2,new ClockSkewComparison.Sample(original.fixtureId(),original.shiftedValue(),
                new ClockSkewNativeAdapter.NativeUse("foreign-policy",u.consumerId(),u.targetAttestedTolerance(),u.nativeStartedAt(),u.nativeCompletedAt(),
                        ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION,u.evidence()),original.evidence()));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(rows).outcome());
    }
    @Test void invalidSignatureControlAcceptanceCannotBecomeAClockConclusion() {
        var rows=new ArrayList<>(positive());rows.set(1,sample("issue-invalid-signature",ClockSkewNativeAdapter.Decision.ACCEPTED));
        assertEquals(Outcome.NOT_VERIFIED,evaluate(rows).outcome());
        rows=new ArrayList<>(positive());rows.add(rows.getFirst());assertEquals(Outcome.NOT_VERIFIED,evaluate(rows).outcome());
    }
    @Test void outsideToleranceRefusalAndAcceptanceHaveTheSameNormativeOutcome() {
        var rows=new ArrayList<>(positive());for(int i=0;i<rows.size();i++)if(rows.get(i).fixtureId().startsWith("issue-outside-"))
            rows.set(i,sample(rows.get(i).fixtureId(),ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION));
        assertEquals(Outcome.SATISFIED,evaluate(rows).outcome());
    }
    @Test void nonIssueInstantRefusalsAreAdvisoryAndCannotSatisfyTheApprovedAllGroup() {
        for(var id:List.of("conditions-not-before","conditions-not-on-or-after","metadata-valid-until")) {
            var rows=new ArrayList<>(positive());
            rows.set(ClockSkewComparison.REQUIRED.indexOf(id),sample(id,ClockSkewNativeAdapter.Decision.CAUSAL_TIME_REJECTION));
            var result=evaluate(rows);
            assertEquals(Outcome.NOT_VERIFIED,result.outcome(),id);
            assertEquals("approved_variant_semantics_ambiguous",result.notVerifiedReason(),id);
            assertEquals(List.of(id),result.details().get("non_issue_instant_refusal_advisory"),id);
            assertEquals(false,result.details().get("non_issue_instant_refusal_affects_verdict"),id);
            assertEquals(List.of(),result.details().get("counterexamples"),id);
            assertFalse(((List<?>)result.details().get("completed_observations")).contains(id),id);
        }
    }
}
