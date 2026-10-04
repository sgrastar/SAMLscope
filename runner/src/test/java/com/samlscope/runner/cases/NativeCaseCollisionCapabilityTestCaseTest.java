package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NativeCaseCollisionCapabilityTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private CaseContext context(boolean allow){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),new TestPlan.Interaction(false,allow),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No traffic");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError();}
    },true);}
    private AttestedOutcomeTestCase fallback(){return new AttestedOutcomeTestCase(KeycloakCaseCollisionCapabilityEvidence.CASE,TargetRole.IDP,"identifier-case-policy","Approved question",Duration.ofDays(7),List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied")));}
    private NativeCaseCollisionCapabilityTestCase wrapper(){return new NativeCaseCollisionCapabilityTestCase(fallback(),new KeycloakCaseCollisionCapabilityEvidence(directory,directory,e->{throw new AssertionError();},r->{throw new AssertionError();}));}
    @Test void absentProofPreservesAuthorizedManualInterface(){var w=wrapper();assertEquals(fallback().promptEn(),w.promptEn());assertEquals(fallback().options(),w.options());assertInstanceOf(CaseStep.AwaitAttestation.class,w.start(context(true)));assertEquals(fallback().start(context(false)),w.start(context(false)));assertEquals(List.of(w.id()),w.evidenceActionKeys());}
    @Test void ownedMalformedProofCannotUseSuccessfulManualDeclaration()throws Exception{Files.createDirectory(directory.resolve(RUN+".keycloak-case-policy"));var w=wrapper();assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,w.start(context(true))).outcome().outcome());assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,w.resume(context(true),null,new CaseEvent.Attested("satisfied",""))).outcome().outcome());assertFalse(w.evidenceStatus(context(true)).ready());assertTrue(w.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("pending","pending")).isEmpty());}
    @Test void wrongCaseAndRoleCannotGainCapabilityEvidence(){var reader=new KeycloakCaseCollisionCapabilityEvidence(directory,directory,e->new byte[0],r->new byte[0]);var wrong=new AttestedOutcomeTestCase("IIP-IDP21-a-idp-01",TargetRole.SP,"question",Duration.ofDays(7),fallback().options());assertThrows(IllegalArgumentException.class,()->new NativeCaseCollisionCapabilityTestCase(wrong,reader));}
    private CaseExecution execution(CaseOutcome outcome){return new CaseExecution(RUN,KeycloakCaseCollisionCapabilityEvidence.CASE,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,outcome,Instant.EPOCH);}
    @Test void nativeProvenanceNeedsCorrectEvidenceKindRunPathAndDigest(){var w=wrapper();var details=Map.<String,Object>of("evidence_adapter",KeycloakCaseCollisionCapabilityEvidence.SCHEMA,"run_id",RUN,"slo_protocol_traffic_verified",false);
        String path=RUN+".keycloak-case-policy/manifest.json#sha256="+"a".repeat(64);
        var valid=new CaseOutcome(Outcome.SATISFIED,null,"observed","observed",List.of(new EvidenceRef("native-case-collision-capability",path)),details);
        assertTrue(w.resolvedFromExternalEvidence(execution(valid)));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,w.evidenceClass(execution(valid)));
        for(var ref:List.of(new EvidenceRef("other",path),new EvidenceRef("native-case-collision-capability","other"),new EvidenceRef("native-case-collision-capability",path+"extra"))){var changed=new CaseOutcome(Outcome.SATISFIED,null,"observed","observed",List.of(ref),details);assertFalse(w.resolvedFromExternalEvidence(execution(changed)));}
        var bare=new CaseOutcome(Outcome.SATISFIED,null,"observed","observed",List.of(),details);assertFalse(w.resolvedFromExternalEvidence(execution(bare)));
    }
    @Test void onlyActualManualAnswerIsSelfAttested(){var w=wrapper();var manual=new CaseOutcome(Outcome.SATISFIED,null,"attestation.satisfied","attestation.satisfied",List.of(),Map.of("attested",true));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.SELF_ATTESTED,w.evidenceClass(execution(manual)));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,w.evidenceClass(execution(CaseOutcome.notVerified("pending","pending"))));}
    @Test void manualSelfCheckRequiresOriginalWaitPhaseAndNoOwnedReceipt()throws Exception{var w=wrapper();var wait=new CaseExecution(RUN,w.id(),0,CaseExecutionStatus.WAITING_ATTESTATION,new CaseState("await-attestation",Map.of()),new WaitCondition(WaitCondition.Kind.ATTESTATION,"approved",null,null,Instant.EPOCH),null,Instant.EPOCH);assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.SELF_CHECK,w.evidenceActionKind(wait));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.SELF_ATTESTED,w.evidenceClass(wait));var manual=campaign(w,wait);assertEquals(com.samlscope.runner.RunCampaignQuery.Plan.FULL,manual.campaigns().getFirst().plan());assertEquals(1,manual.campaigns().getFirst().deliberateUserActions());assertEquals(1,manual.campaigns().getFirst().remainingUserActions());assertEquals(0,manual.plans().stream().filter(p->p.plan()==com.samlscope.runner.RunCampaignQuery.Plan.STANDARD).findFirst().orElseThrow().deliberateUserActions());Files.createDirectory(directory.resolve(RUN+".keycloak-case-policy"));assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.NONE,w.evidenceActionKind(wait));var malformed=campaign(w,wait);assertEquals(com.samlscope.runner.RunCampaignQuery.Plan.STANDARD,malformed.campaigns().getFirst().plan());assertEquals(0,malformed.campaigns().getFirst().deliberateUserActions());}
    @Test void actualCampaignHasNoManualBudgetForNativeConclusion(){var w=wrapper();var details=Map.<String,Object>of("evidence_adapter",KeycloakCaseCollisionCapabilityEvidence.SCHEMA,"run_id",RUN,"slo_protocol_traffic_verified",false,"attested",false);var observed=new CaseOutcome(Outcome.SATISFIED,null,"observed","observed",List.of(new EvidenceRef("native-case-collision-capability",RUN+".keycloak-case-policy/manifest.json#sha256="+"a".repeat(64))),details);var report=campaign(w,execution(observed));assertEquals(com.samlscope.runner.RunCampaignQuery.Plan.STANDARD,report.campaigns().getFirst().plan());assertEquals(0,report.campaigns().getFirst().deliberateUserActions());assertEquals(0,report.campaigns().getFirst().remainingUserActions());assertEquals(0,report.plans().stream().filter(p->p.plan()==com.samlscope.runner.RunCampaignQuery.Plan.FULL).findFirst().orElseThrow().deliberateUserActions());}
    private com.samlscope.runner.RunCampaignQuery.CampaignReport campaign(NativeCaseCollisionCapabilityTestCase wrapper,CaseExecution execution){
        var definition=new com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition(wrapper.id(),"IIP-IDP21.a",TargetRole.IDP,com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode.ATTESTED,com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3,List.of(),Map.of(),List.of(),List.of(),List.of(),"case-sensitive-construction",List.of(),new com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements(List.of(),"none"),false,null,KeycloakCaseCollisionCapabilityEvidence.DIGEST);
        var repository=new CaseExecutionRepository(){
            public Optional<CaseExecution> find(String run,String id){return Optional.of(execution);}public List<CaseExecution> list(String run){return List.of(execution);}public boolean apply(long expected,CaseExecution value,List<OutboundAction> actions){throw new AssertionError("Read-only campaign");}public List<OutboxEntry> listOutbox(String run){return List.of();}public Optional<OutboxEntry> findOutbox(String id){return Optional.empty();}public boolean transitionOutbox(String id,OutboxStatus expected,OutboxStatus next,Map<String,Object> result,String reference,Instant at){throw new AssertionError();}public int recoverSendingAsUnknownDelivery(Instant at){throw new AssertionError();}
        };
        return new com.samlscope.runner.RunCampaignService(repository,new com.samlscope.core.casedef.CaseDefinitionCatalog(List.of(definition)),new com.samlscope.runner.TestCaseRegistry(List.of(wrapper)),run->context(true)).report(RUN);
    }

}
