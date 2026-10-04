package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.Outcome;
import java.util.*;

/** Computes the continuation result after protocol, session and producer originals are verified. */
final class SloContinuationProof {
    enum TerminalAuthority { REACHED_ALL_SELECTED, VERIFIED_COMPLETE_EXECUTION, UNPROVEN }
    record Operation(String trial, Set<String> selected, List<String> attempted,
            Set<String> terminalAttempted, Set<String> terminalRemaining,
            List<String> verifiedStatuses, TerminalAuthority authority) {
        Operation {
            selected=Set.copyOf(selected);attempted=List.copyOf(attempted);
            terminalAttempted=Set.copyOf(terminalAttempted);terminalRemaining=Set.copyOf(terminalRemaining);
            verifiedStatuses=List.copyOf(verifiedStatuses);Objects.requireNonNull(authority);
        }
    }
    private static final String SUCCESS="urn:oasis:names:tc:SAML:2.0:status:Success",
            RESPONDER="urn:oasis:names:tc:SAML:2.0:status:Responder";
    static Outcome computeOutcome(Operation operation) {
        if(!Set.of("failure","all-success").contains(operation.trial())
                ||!operation.selected().equals(Set.of("fail","remain","remain2"))
                ||operation.attempted().isEmpty()||new HashSet<>(operation.attempted()).size()!=operation.attempted().size()
                ||!operation.selected().containsAll(operation.attempted())
                ||operation.verifiedStatuses().size()!=operation.attempted().size())return Outcome.NOT_VERIFIED;
        for(int i=0;i<operation.attempted().size();i++) {
            String expected="failure".equals(operation.trial())&&i==0?RESPONDER:SUCCESS;
            if(!expected.equals(operation.verifiedStatuses().get(i)))return Outcome.NOT_VERIFIED;
        }
        var attempted=new HashSet<>(operation.attempted());var remaining=new HashSet<>(operation.selected());remaining.removeAll(attempted);
        if(!attempted.equals(operation.terminalAttempted())||!remaining.equals(operation.terminalRemaining()))return Outcome.NOT_VERIFIED;
        if(operation.authority()==TerminalAuthority.UNPROVEN)return Outcome.NOT_VERIFIED;
        if(remaining.isEmpty())return Outcome.SATISFIED;
        return "failure".equals(operation.trial())&&operation.authority()==TerminalAuthority.VERIFIED_COMPLETE_EXECUTION
                ?Outcome.VIOLATED:Outcome.NOT_VERIFIED;
    }
    private SloContinuationProof() {}
}
