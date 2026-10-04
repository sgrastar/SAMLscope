package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class ClockSkewEvidenceTestCaseTest {
    static final String RUN="run_00000000000000000000000000";
    static DefaultCaseContext context(boolean complete) {
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No new requests or evidence");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    static TestCase fallback() {
        return new TestCase() {
            public String id(){return ClockSkewEvidence.CASE;}
            public TargetRole role(){return TargetRole.IDP;}
            public CaseStep start(CaseContext context){throw new AssertionError("Missing clock policies cannot be filled by a login");}
            public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){throw new AssertionError("No browser fallback");}
        };
    }
    static CaseOutcome proof(Outcome outcome,boolean calibration,String run) {
        return new CaseOutcome(outcome,null,"clock-proof","clock-proof",List.of(
                new EvidenceRef("clock-skew-native-evidence",run+"/manifest.json#sha256="+"a".repeat(64)),
                new EvidenceRef("transcript","tx_00000000000000000000000000")),Map.of(
                "run_id",run,"evidence_adapter","bound-native-clock-consumer","counterfactual_calibration_only",calibration,
                "completed_observations",ClockSkewComparison.REQUIRED));
    }
    static ClockSkewEvidenceTestCase wrapper(CaseOutcome proof,boolean offline) {
        return new ClockSkewEvidenceTestCase(fallback(),c->Optional.ofNullable(proof),offline);
    }
    @Test void missingPoliciesFinishNotVerifiedWithoutRequestingMoreLogins() {
        var t=wrapper(null,false);var c=context(true);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.start(c)).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.resume(c,null,new CaseEvent.TranscriptReady())).outcome().outcome());
        assertFalse(t.evidenceStatus(c).ready());assertEquals(RunCampaignQuery.ActionKind.NONE,t.evidenceActionKind());
        assertTrue(t.evidenceActionKeys().isEmpty());assertFalse(BrowserFrontChannelScenario.class.isInstance(t));
    }
    @Test void actualSameRunProofHasIdenticalReadOnlyLifecycleAndDoesNotRewriteConclusiveResults() {
        var n=proof(Outcome.SATISFIED,false,RUN);var t=wrapper(n,false);var c=context(true);
        assertEquals(n,assertInstanceOf(CaseStep.Finish.class,t.start(c)).outcome());
        assertEquals(n,assertInstanceOf(CaseStep.Finish.class,t.resume(c,null,new CaseEvent.Aborted("old wait"))).outcome());
        assertTrue(t.evidenceStatus(c).ready());
        assertEquals(n,t.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("missing","missing")).orElseThrow());
        assertTrue(t.reevaluateRecordedEvidence(c,n).isEmpty());
    }
    @Test void incompleteHistoryAndForeignRunCannotBorrowAConclusion() {
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,wrapper(proof(Outcome.SATISFIED,false,RUN),false).start(context(false))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,wrapper(proof(Outcome.SATISFIED,false,"run_11111111111111111111111111"),false).start(context(true))).outcome().outcome());
    }
    @Test void calibrationPermissionComesFromOfflineConstructorAndCannotBeEnabledByReceipt() {
        var n=proof(Outcome.VIOLATED,true,RUN);var production=wrapper(n,false);var offline=wrapper(n,true);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,production.start(context(true))).outcome().outcome());
        assertFalse(production.evidenceStatus(context(true)).ready());
        assertEquals(n,assertInstanceOf(CaseStep.Finish.class,offline.start(context(true))).outcome());
    }
    @Test void noNewTranscriptEvidencePreservesTheOldNotVerifiedHistory() {
        var n=proof(Outcome.SATISFIED,false,RUN);var previous=new CaseOutcome(Outcome.NOT_VERIFIED,"old","old","old",n.evidence(),Map.of());
        assertTrue(wrapper(n,false).reevaluateRecordedEvidence(context(true),previous).isEmpty());
    }
    @Test void aConclusiveReceiptWithoutManifestProvenanceIsNotReady() {
        var p=proof(Outcome.SATISFIED,false,RUN);var missing=new CaseOutcome(p.outcome(),null,p.reasonCode(),p.reasonMessageKey(),
                p.evidence().stream().filter(r->"transcript".equals(r.kind())).toList(),p.details());
        assertFalse(wrapper(missing,false).evidenceStatus(context(true)).ready());
    }
}
