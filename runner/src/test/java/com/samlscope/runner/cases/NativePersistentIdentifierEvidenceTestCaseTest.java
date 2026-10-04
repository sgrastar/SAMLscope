package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NativePersistentIdentifierEvidenceTestCaseTest {
    static final String RUN="run_00000000000000000000000000",ID="IIP-SSO05-a1-idp-01";
    @TempDir Path directory;
    private CaseContext context(boolean allow) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),new TestPlan.Interaction(false,allow),Reachability.CONFIRMED,new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Native evidence cannot send or record");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}
        },true);
    }
    private AttestedOutcomeTestCase fallback(){return new AttestedOutcomeTestCase(ID,TargetRole.IDP,"approved-opacity","Original approved question",Duration.ofDays(7),List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied")));}
    private NativePersistentIdentifierEvidenceTestCase wrapper() {
        var stores=new HashMap<String,DefaultAlgorithmSourceRunStore>();KeycloakPersistentIdentifierEvidence.DIGESTS.forEach((id,digest)->stores.put(id,new DefaultAlgorithmSourceRunStore(directory,id,digest)));
        return new NativePersistentIdentifierEvidenceTestCase(fallback(),new KeycloakPersistentIdentifierEvidence(directory,e->{throw new AssertionError();},r->{throw new AssertionError();},stores));
    }
    @Test void absencePreservesApprovedPromptAndManualInteraction() {
        var wrapper=wrapper();assertEquals(fallback().promptEn(),wrapper.promptEn());assertEquals(fallback().options(),wrapper.options());
        assertInstanceOf(CaseStep.AwaitAttestation.class,wrapper.start(context(true)));assertEquals(fallback().start(context(false)),wrapper.start(context(false)));
        assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.NONE,wrapper.evidenceActionKind());assertEquals(List.of(ID),wrapper.evidenceActionKeys());
        assertEquals(Outcome.NOT_VERIFIED,wrapper.queuedEvidenceOutcome(context(true)).outcome());
    }
    @Test void malformedOwnedPreparationCannotFallBackToSuccessfulDeclaration()throws Exception {
        Files.createDirectory(directory.resolve(RUN+".keycloak-native-identifier"));var wrapper=wrapper();
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,wrapper.start(context(true))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,wrapper.resume(context(true),null,new CaseEvent.Attested("satisfied",""))).outcome().outcome());
        assertFalse(wrapper.evidenceStatus(context(true)).ready());assertTrue(wrapper.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("before","before")).isEmpty());
    }
    @Test void unknownCaseAndWrongRoleAreRejected() {
        var stores=new HashMap<String,DefaultAlgorithmSourceRunStore>();KeycloakPersistentIdentifierEvidence.DIGESTS.forEach((id,digest)->stores.put(id,new DefaultAlgorithmSourceRunStore(directory,id,digest)));
        var reader=new KeycloakPersistentIdentifierEvidence(directory,e->new byte[0],r->new byte[0],stores);
        var wrong=new AttestedOutcomeTestCase(ID,TargetRole.SP,"question",Duration.ofDays(7),fallback().options());
        assertThrows(IllegalArgumentException.class,()->new NativePersistentIdentifierEvidenceTestCase(wrong,reader));
    }
    @Test void nativePreparationIsOperatorAssistedAndOnlyActualManualAnswersAreSelfAttested() {
        var wrapper=wrapper();var nativeOutcome=new CaseOutcome(Outcome.SATISFIED,null,"native","native",List.of(new EvidenceRef("native-persistent-identifier",RUN+".keycloak-native-identifier/manifest.json")),Map.of("evidence_adapter",KeycloakPersistentIdentifierEvidence.SCHEMA,"run_id",RUN,"attested",false));
        var nativeExecution=new CaseExecution(RUN,ID,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,nativeOutcome,Instant.EPOCH);
        assertTrue(wrapper.resolvedFromExternalEvidence(nativeExecution));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,wrapper.evidenceClass(nativeExecution));
        var manual=new CaseOutcome(Outcome.SATISFIED,null,"manual","manual",List.of(),Map.of("attested",true));var manualExecution=new CaseExecution(RUN,ID,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,manual,Instant.EPOCH);
        assertFalse(wrapper.resolvedFromExternalEvidence(manualExecution));assertEquals(com.samlscope.runner.RunCampaignQuery.EvidenceClass.SELF_ATTESTED,wrapper.evidenceClass(manualExecution));
    }
    @Test void manualWaitShowsSelfCheckAndMalformedPreparationShowsNoHumanAction()throws Exception {
        var wrapper=wrapper();var waiting=new CaseExecution(RUN,ID,0,CaseExecutionStatus.WAITING_ATTESTATION,new CaseState("await-attestation",Map.of("question_key","approved-opacity")),new WaitCondition(WaitCondition.Kind.ATTESTATION,"approved-opacity",null,null,Instant.now().plusSeconds(300)),null,Instant.EPOCH);
        assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.SELF_CHECK,wrapper.evidenceActionKind(waiting));
        assertEquals(1,campaign(wrapper,waiting).deliberateUserActions());assertEquals(1,campaign(wrapper,waiting).remainingUserActions());
        Files.createDirectory(directory.resolve(RUN+".keycloak-native-identifier"));assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.NONE,wrapper.evidenceActionKind(waiting));assertEquals(0,campaign(wrapper,waiting).deliberateUserActions());
    }
    @Test void actualCampaignBudgetCountsNoNewActionForNativeConclusionOrDisallowedMissingProof() {
        var wrapper=wrapper();var nativeOutcome=new CaseOutcome(Outcome.SATISFIED,null,"native","native",List.of(new EvidenceRef("native-persistent-identifier",RUN+".keycloak-native-identifier/manifest.json")),Map.of("evidence_adapter",KeycloakPersistentIdentifierEvidence.SCHEMA,"run_id",RUN,"attested",false));
        var nativeExecution=new CaseExecution(RUN,ID,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,nativeOutcome,Instant.EPOCH);
        assertEquals(0,campaign(wrapper,nativeExecution).deliberateUserActions());assertEquals(0,campaign(wrapper,nativeExecution).remainingUserActions());
        var missing=new CaseExecution(RUN,ID,0,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,CaseOutcome.notVerified("interaction_disallowed","attestation.interaction-disallowed"),Instant.EPOCH);
        assertEquals(0,campaign(wrapper,missing).deliberateUserActions());
    }
    private com.samlscope.runner.RunCampaignQuery.Campaign campaign(NativePersistentIdentifierEvidenceTestCase wrapper,CaseExecution execution) {
        var definition=new com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition(ID,"IIP-SSO05.a1",TargetRole.IDP,com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode.ATTESTED,com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1,
            List.of(),Map.of(),List.of(),List.of(),List.of(),"principal-valued-saved-attribute",List.of(),new com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements(List.of(),"none"),false,null,KeycloakPersistentIdentifierEvidence.DIGESTS.get(ID));
        var repository=new CaseExecutionRepository(){
            public Optional<CaseExecution> find(String run,String id){return Optional.of(execution);}public List<CaseExecution> list(String run){return List.of(execution);}
            public boolean apply(long expected,CaseExecution value,List<OutboundAction> actions){throw new AssertionError("Read-only campaign");}
            public List<OutboxEntry> listOutbox(String run){return List.of();}public Optional<OutboxEntry> findOutbox(String id){return Optional.empty();}
            public boolean transitionOutbox(String id,OutboxStatus expected,OutboxStatus next,Map<String,Object> result,String reference,Instant at){throw new AssertionError();}
            public int recoverSendingAsUnknownDelivery(Instant at){throw new AssertionError();}
        };
        var service=new com.samlscope.runner.RunCampaignService(repository,new com.samlscope.core.casedef.CaseDefinitionCatalog(List.of(definition)),new com.samlscope.runner.TestCaseRegistry(List.of(wrapper)),run->context(true));
        return service.report(RUN).campaigns().getFirst();
    }
}
