package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SloRegisteredSignerObservationTestCaseTest {
    @TempDir Path root;
    @org.junit.jupiter.api.BeforeEach void canonicalTemporaryRoot()throws Exception{root=root.toRealPath();}
    private static final String RUN="run_00000000000000000000000000",CASE=SloRegisteredSignerEvidence.CASE;
    private static CaseOutcome manual(){return new CaseOutcome(Outcome.SATISFIED,null,"attestation.satisfied","attestation.satisfied",List.of(new EvidenceRef("attestation","manual")),Map.of());}
    private SloRegisteredSignerObservationTestCase wrapper(){return new SloRegisteredSignerObservationTestCase(new Legacy(),root,e->{throw new AssertionError("Unexpected original access");},r->new byte[0],(r,v)->Optional.empty());}
    private static CaseOutcome finish(CaseStep s){return assertInstanceOf(CaseStep.Finish.class,s).outcome();}
    private static CaseExecution execution(CaseOutcome outcome){return new CaseExecution(RUN,CASE,1,CaseExecutionStatus.FINISHED,new CaseState("done",Map.of()),null,outcome,Instant.EPOCH);}
    @Test void unownedNativeDirectoryPreservesApprovedAttestationAndClassification(){var w=wrapper();assertEquals(Outcome.SATISFIED,finish(w.start(context())).outcome());assertEquals("Approved SLO attestation",w.promptEn());assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,w.evidenceClass(execution(manual())));}
    @Test void partialOwnedMalformedOrSymbolicProofDoesNotQueueLoginOrBorrowManualSuccess()throws Exception{
        Files.createDirectories(root.resolve(RUN));var w=wrapper();var outcome=finish(w.start(context()));assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());assertEquals(RunCampaignQuery.ActionKind.CONFIGURATION,w.evidenceActionKind(execution(outcome)));assertFalse(w.resolvedFromExternalEvidence(execution(outcome)));
        for(var event:List.<CaseEvent>of(new CaseEvent.Attested("satisfied","supported"),new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady()))assertEquals(Outcome.NOT_VERIFIED,finish(w.resume(context(),new CaseState("manual",Map.of()),event)).outcome());
        Files.writeString(root.resolve(RUN).resolve("manifest.json"),"{}");assertFalse(w.evidenceStatus(context()).ready());assertEquals(Outcome.NOT_VERIFIED,finish(w.start(context())).outcome());
        Files.delete(root.resolve(RUN).resolve("manifest.json"));Files.writeString(root.resolve("foreign"),"{}");Files.createSymbolicLink(root.resolve(RUN).resolve("manifest.json"),root.resolve("foreign"));assertEquals(Outcome.NOT_VERIFIED,finish(w.start(context())).outcome());
    }
    @Test void nativeMissingProofCanReconsiderOnlyPriorUnverifiedWithoutChangingConclusiveEvidence()throws Exception{
        Files.createDirectories(root.resolve(RUN));Files.writeString(root.resolve(RUN).resolve("manifest.json"),"{}");var w=wrapper();
        assertTrue(w.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("pending","case.pending-interaction")));assertFalse(w.supportsRecordedEvidenceReevaluation(manual()));assertTrue(w.reevaluateRecordedEvidence(context(),manual()).isEmpty());
        assertTrue(w.reevaluateRecordedEvidence(context(),CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
    }
    @Test void logoutEndIsPresentedWithoutForcingFreshSessionsForSignatureControls(){
        var w=wrapper();assertFalse(w.requiresFreshSession(new CaseState("await-fixture-local-invalid-signature",Map.of())));assertFalse(w.plansFreshSessionBoundary());
        assertTrue(w.instructionsEn(new CaseState("await-fixture-local-normal",Map.of())).contains("ends the test session"));assertEquals(List.of("active-probe-login-1"),w.evidenceActionKeys());
        var state=new CaseState("await-fixture-local-normal",Map.of("native_receipt_owned",true,"case_id",CASE,"native_run_id",RUN,"normal_control_ends_session",true));
        var waiting=new CaseExecution(RUN,CASE,1,CaseExecutionStatus.WAITING_INBOUND,state,new WaitCondition(WaitCondition.Kind.INBOUND,null,null,new InboundMatcher("saml-response",Map.of("inResponseTo","_request")),Instant.EPOCH.plusSeconds(60)),null,Instant.EPOCH);
        assertEquals(RunCampaignQuery.ActionKind.LOGIN,w.evidenceActionKind(waiting));assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,w.evidenceClass(waiting));assertFalse(w.resolvedFromExternalEvidence(waiting));
    }
    private static CaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No new send");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("No history rewrite");}},true);}
    private static class Legacy implements TestCase,AttestationPrompt{public String id(){return CASE;}public TargetRole role(){return TargetRole.IDP;}public String promptEn(){return "Approved SLO attestation";}public List<AttestationOption> options(){return List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied"));}public CaseStep start(CaseContext c){return new CaseStep.Finish(manual());}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return start(c);}}
}
