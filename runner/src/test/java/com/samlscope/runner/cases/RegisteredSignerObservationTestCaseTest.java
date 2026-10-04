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

class RegisteredSignerObservationTestCaseTest {
    @TempDir Path root;
    private static final String RUN="run_00000000000000000000000000",CASE=RegisteredSignerObservationTestCase.CASE;
    private static CaseOutcome satisfied(){return new CaseOutcome(Outcome.SATISFIED,null,"attestation.satisfied","attestation.satisfied",List.of(new EvidenceRef("attestation","manual")),Map.of());}
    private static CaseOutcome finish(CaseStep step){return assertInstanceOf(CaseStep.Finish.class,step).outcome();}
    private RegisteredSignerObservationTestCase wrapper(RegisteredSignerNativeEvidence... extra){return new RegisteredSignerObservationTestCase(new Legacy(),root,e->{throw new AssertionError("unexpected content access");},r->new byte[0],(r,v)->Optional.empty(),extra);}
    private void owned(String name)throws Exception{var folder=Files.createDirectories(root.resolve(RUN));Files.writeString(folder.resolve(name),"{}");}
    @Test void absentNativePreparationKeepsManualAttestationContract(){var test=wrapper();assertEquals(Outcome.SATISFIED,finish(test.start(context(true))).outcome());assertEquals("Approved attestation",test.promptEn());assertEquals(Outcome.SATISFIED,finish(test.resume(context(true),new CaseState("manual",Map.of()),new CaseEvent.Attested("satisfied","supported"))).outcome());}
    @Test void ownedMalformedPreparationCannotSendOrAcceptManualFallback()throws Exception{owned("preparation.json");var test=wrapper();assertEquals(Outcome.NOT_VERIFIED,finish(test.start(context(true))).outcome());for(var event:List.<CaseEvent>of(new CaseEvent.Attested("satisfied","supported"),new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady()))assertEquals(Outcome.NOT_VERIFIED,finish(test.resume(context(true),new CaseState("manual",Map.of()),event)).outcome());}
    @Test void finalOwnedInvalidProofCannotRequeueBrowserActions()throws Exception{owned("manifest.json");var test=wrapper();assertEquals(Outcome.NOT_VERIFIED,finish(test.start(context(true))).outcome());assertEquals(Outcome.NOT_VERIFIED,finish(test.resume(context(true),new CaseState("await-fixture-local-normal",Map.of()),new CaseEvent.TranscriptReady())).outcome());assertFalse(test.evidenceStatus(context(true)).ready());}
    @Test void symlinkOwnedPathCannotUseAttestedSuccess()throws Exception{Files.createDirectories(root.resolve("outside"));Files.createSymbolicLink(root.resolve(RUN),root.resolve("outside"));assertEquals(Outcome.NOT_VERIFIED,finish(wrapper().start(context(true))).outcome());}
    @Test void dualOwnerIsRejectedBeforeReadingEitherOriginal()throws Exception{owned("manifest.json");var test=wrapper(new ForbiddenOwner());var outcome=finish(test.start(context(true)));assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());assertEquals("ambiguous-native-registered-signer-owner",outcome.notVerifiedReason());assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,test.evidenceClass(execution(outcome)));}
    @Test void nativeClassificationUsesRecordedMarkersNeverLaterFilesystem()throws Exception{var test=wrapper();var manual=execution(satisfied());assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,test.evidenceClass(manual));owned("manifest.json");assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,test.evidenceClass(manual));var pending=finish(test.start(context(true)));assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,test.evidenceClass(execution(pending)));assertFalse(test.resolvedFromExternalEvidence(execution(pending)));}
    @Test void conclusiveExternalProofMustBeRunAndReceiptBound(){var test=wrapper();var refs=List.of(new EvidenceRef("native-registered-signer-evidence",RUN+"/manifest.json#"+"1".repeat(64)),new EvidenceRef("transcript","tx_original"));var detail=Map.<String,Object>of("evidence_adapter",KeycloakRegisteredSignerEvidence.ADAPTER,"case_id",CASE,"native_run_id",RUN,"native_receipt_owned",true);var proof=new CaseOutcome(Outcome.SATISFIED,null,"signature.signer.issuer-key-restriction-observed","observed",refs,detail);assertTrue(test.resolvedFromExternalEvidence(execution(proof)));assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,test.evidenceClass(execution(proof)));var foreign=new HashMap<>(detail);foreign.put("native_run_id","run_11111111111111111111111111");assertFalse(test.resolvedFromExternalEvidence(execution(new CaseOutcome(proof.outcome(),proof.notVerifiedReason(),proof.reasonCode(),proof.reasonMessageKey(),proof.evidence(),foreign))));}
    @Test void unfinishedHistoryCannotBecomeReadyFromNativeClaim()throws Exception{owned("manifest.json");var test=wrapper();assertFalse(test.evidenceStatus(context(false)).ready());assertTrue(test.reevaluateRecordedEvidence(context(false),CaseOutcome.notVerified("pending","pending")).isEmpty());assertEquals(Outcome.NOT_VERIFIED,finish(test.start(context(false))).outcome());}
    @Test void preparedSavedStateHasOperatorProvenanceWithoutRelabelingManualOutcome(){
        var test=wrapper();var saved=Map.<String,Object>of("evidence_adapter",KeycloakRegisteredSignerEvidence.ADAPTER,"case_id",CASE,"native_run_id",RUN,"native_receipt_owned",true);var wait=new CaseExecution(RUN,CASE,1,CaseExecutionStatus.WAITING_INBOUND,new CaseState("await-fixture-local-normal",saved),new WaitCondition(WaitCondition.Kind.INBOUND,null,null,new InboundMatcher("correlated-response",Map.of("inResponseTo","_known-request")),Instant.EPOCH.plusSeconds(60)),null,Instant.EPOCH);
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,test.evidenceClass(wait));assertEquals(RunCampaignQuery.ActionKind.LOGIN,test.evidenceActionKind(wait));assertFalse(test.resolvedFromExternalEvidence(wait));
        var manual=new CaseExecution(RUN,CASE,2,CaseExecutionStatus.FINISHED,wait.state(),null,satisfied(),Instant.EPOCH);assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,test.evidenceClass(manual));
    }
    private static CaseExecution execution(CaseOutcome o){return new CaseExecution(RUN,CASE,1,CaseExecutionStatus.FINISHED,new CaseState("done",Map.of()),null,o,Instant.EPOCH);}
    private static DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No sending");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("No history alteration");}},complete);}
    private static class Legacy implements TestCase,AttestationPrompt {
        public String id(){return CASE;}public TargetRole role(){return TargetRole.IDP;}public String promptEn(){return "Approved attestation";}public List<AttestationOption> options(){return List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied"));}
        public CaseStep start(CaseContext c){return new CaseStep.Finish(satisfied());}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return start(c);}
    }
    private static class ForbiddenOwner implements RegisteredSignerNativeEvidence {
        public boolean exists(String r){return true;}public boolean hasFinalProof(String r){throw new AssertionError("Ambiguous proof read");}public Optional<RegisteredSignerProbeInputs> probeInputs(CaseContext c){throw new AssertionError("Ambiguous proof read");}public Optional<CaseOutcome>evaluate(CaseContext c){throw new AssertionError("Ambiguous proof read");}public CaseOutcome pending(String r,String s){throw new AssertionError("Ambiguous proof read");}public String adapter(){return "simplesamlphp-native-issuer-key-locator-v1";}public String evidenceKind(){return "simplesamlphp-native-registered-signer-evidence";}
    }
}
