package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import java.util.*;

/** Mathematical signature validity and signer appropriateness are different controls. */
final class SloRegisteredSignerComparison {
    static final List<String> FIXTURES = List.of("local-invalid-signature", "local-other-signer", "local-normal");
    record Sample(String fixture, SloRegisteredSignerNativeAdapter.Decision nativeDecision,
            boolean correlatedSignedSuccess, List<EvidenceRef> evidence) {
        Sample { Objects.requireNonNull(fixture); Objects.requireNonNull(nativeDecision); evidence = List.copyOf(evidence); }
    }
    static CaseOutcome evaluate(String run, String adapter, List<Sample> samples,
            List<EvidenceRef> originals, boolean optionalResponseConsumerObserved,
            boolean optionalResponseSignerProof) {
        var byId = new HashMap<String,Sample>();
        var evidence = new LinkedHashSet<EvidenceRef>(originals);
        for (var s : samples) {
            if (!FIXTURES.contains(s.fixture()) || byId.put(s.fixture(),s) != null)
                return missing(run,adapter,"ambiguous-slo-signer-observations",List.copyOf(evidence));
            evidence.addAll(s.evidence());
        }
        var normal=byId.get("local-normal"); var invalid=byId.get("local-invalid-signature");
        var other=byId.get("local-other-signer");
        if (normal==null || normal.nativeDecision()!=SloRegisteredSignerNativeAdapter.Decision.ACCEPTED
                || !normal.correlatedSignedSuccess() || invalid==null
                || invalid.nativeDecision()!=SloRegisteredSignerNativeAdapter.Decision.REJECTED_SIGNATURE
                || invalid.correlatedSignedSuccess())
            return missing(run,adapter,"slo-signer-controls-unproven",List.copyOf(evidence));
        if (other==null || other.nativeDecision()==SloRegisteredSignerNativeAdapter.Decision.UNPROVEN)
            return missing(run,adapter,"other-entity-slo-signer-unproven",List.copyOf(evidence));
        var details=new LinkedHashMap<String,Object>();
        details.put("case_id",SloRegisteredSignerEvidence.CASE); details.put("native_run_id",run);
        details.put("evidence_adapter",adapter); details.put("native_receipt_owned",true);
        details.put("attested",false); details.put("optional_logout_response_consumer_observed",optionalResponseConsumerObserved);
        details.put("completed_fixtures",FIXTURES); details.put("normal_control_ends_session",true);
        if (other.nativeDecision()==SloRegisteredSignerNativeAdapter.Decision.ACCEPTED) {
            if (!other.correlatedSignedSuccess())
                return missing(run,adapter,"other-signer-acceptance-unproven",List.copyOf(evidence));
            return new CaseOutcome(Outcome.VIOLATED,null,"slo.signer.other-entity-key-accepted",
                    "slo.signer.other-entity-key-accepted",List.copyOf(evidence),details);
        }
        if (other.correlatedSignedSuccess())
            return missing(run,adapter,"contradictory-slo-signer-rejection",List.copyOf(evidence));
        if (optionalResponseConsumerObserved && !optionalResponseSignerProof)
            return missing(run,adapter,"optional-logout-response-signer-unproven",List.copyOf(evidence));
        return new CaseOutcome(optionalResponseConsumerObserved?Outcome.SATISFIED:Outcome.SATISFIED_WITH_NOTE,
                null,optionalResponseConsumerObserved?"slo.signer.issuer-key-observed":"slo.signer.request-observed-response-unobserved",
                optionalResponseConsumerObserved?"slo.signer.issuer-key-observed":"slo.signer.request-observed-response-unobserved",
                List.copyOf(evidence),details);
    }
    static CaseOutcome missing(String run,String adapter,String reason,List<EvidenceRef> evidence) {
        return new CaseOutcome(Outcome.NOT_VERIFIED,reason,"slo.signer.native-unproven","slo.signer.native-unproven",
                evidence,Map.of("case_id",SloRegisteredSignerEvidence.CASE,"native_run_id",run,
                        "evidence_adapter",adapter,"native_receipt_owned",true,"required_action","administrator_evidence",
                        "instructions_en","Prepare two registered peers and provide the authenticated session, operative SLO key lookup, complete controls and restoration originals. Additional ordinary logins do not establish signer identity."));
    }
    private SloRegisteredSignerComparison() { }
}
