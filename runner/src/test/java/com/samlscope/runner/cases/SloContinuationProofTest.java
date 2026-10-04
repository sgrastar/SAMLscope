package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.Outcome;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Common result calculation after the reader verifies the signed protocol and execution. */
class SloContinuationProofTest {
    private static final String SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success",RESPONDER="urn:oasis:names:tc:SAML:2.0:status:Responder";
    private static final Set<String> SELECTED=Set.of("fail","remain","remain2");
    private SloContinuationProof.Operation operation(String trial,List<String> attempted,List<String> status,
            Set<String> terminalAttempted,Set<String> remaining,SloContinuationProof.TerminalAuthority authority){
        return new SloContinuationProof.Operation(trial,SELECTED,attempted,terminalAttempted,remaining,status,authority);
    }
    private SloContinuationProof.Operation complete(String trial,List<String> attempted,List<String> statuses){
        var remaining=new HashSet<>(SELECTED);remaining.removeAll(attempted);
        return operation(trial,attempted,statuses,new HashSet<>(attempted),remaining,SloContinuationProof.TerminalAuthority.VERIFIED_COMPLETE_EXECUTION);
    }
    @Test void verifiedFirstErrorAndBothLaterAttemptsSatisfyTheObligation(){
        assertEquals(Outcome.SATISFIED,SloContinuationProof.computeOutcome(complete("failure",List.of("remain2","fail","remain"),List.of(RESPONDER,SUCCESS,SUCCESS))));
    }
    @Test void verifiedTerminalStopAfterTheFirstErrorViolatesTheSameObligation(){
        assertEquals(Outcome.VIOLATED,SloContinuationProof.computeOutcome(complete("failure",List.of("remain2"),List.of(RESPONDER))));
    }
    @Test void missingHttpArrivalsWithoutCompleteExecutionAreNotAnAuthoritativeStop(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(operation("failure",List.of("fail"),List.of(RESPONDER),Set.of("fail"),Set.of("remain","remain2"),SloContinuationProof.TerminalAuthority.UNPROVEN)));
    }
    @Test void completeAllSuccessControlRemainsSatisfiedForBothConsumerImplementations(){
        assertEquals(Outcome.SATISFIED,SloContinuationProof.computeOutcome(complete("all-success",List.of("remain2","fail","remain"),List.of(SUCCESS,SUCCESS,SUCCESS))));
    }
    @Test void incompleteAllSuccessDoesNotSubstituteForTheApprovedErrorTrigger(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(complete("all-success",List.of("fail"),List.of(SUCCESS))));
    }
    @Test void errorAfterAnEarlierSuccessDoesNotMeetFirstOfThreeTrigger(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(complete("failure",List.of("remain2","fail","remain"),List.of(SUCCESS,RESPONDER,SUCCESS))));
    }
    @Test void retryOfOneParticipantCannotReplaceAnotherSelectedSession(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(complete("failure",List.of("fail","fail","remain"),List.of(RESPONDER,SUCCESS,SUCCESS))));
    }
    @Test void inconsistentTerminalAttemptedOrRemainingSetCannotProveAStop(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(operation("failure",List.of("fail"),List.of(RESPONDER),Set.of("fail","remain"),Set.of("remain2"),SloContinuationProof.TerminalAuthority.VERIFIED_COMPLETE_EXECUTION)));
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(operation("failure",List.of("fail"),List.of(RESPONDER),Set.of("fail"),Set.of("remain2"),SloContinuationProof.TerminalAuthority.VERIFIED_COMPLETE_EXECUTION)));
    }
    @Test void unknownParticipantAndMissingVerifiedResponderCannotProveViolation(){
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(complete("failure",List.of("foreign"),List.of(RESPONDER))));
        assertEquals(Outcome.NOT_VERIFIED,SloContinuationProof.computeOutcome(complete("failure",List.of("fail"),List.of())));
    }
}
