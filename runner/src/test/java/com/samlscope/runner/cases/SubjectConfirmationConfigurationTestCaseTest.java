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

class SubjectConfirmationConfigurationTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path data;
    private static final class Fallback implements TestCase,ConfigurationPrompt,AttestationPrompt,ProtocolEvidenceCase {
        private final String id; int starts,resumes,statuses;
        Fallback(String id){this.id=id;}
        public String id(){return id;} public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Original approved configuration instruction";}
        public String promptEn(){return "Original approved attestation prompt";}
        public List<AttestationOption> options(){return List.of(AttestationOption.of("observed",Outcome.SATISFIED,"approved.attestation"));}
        public CaseStep start(CaseContext context){starts++;return new CaseStep.Finish(CaseOutcome.notVerified("original_config","approved.configuration"));}
        public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){resumes++;return new CaseStep.Finish(CaseOutcome.notVerified("original_attestation","approved.attestation"));}
        public EvidenceStatus evidenceStatus(CaseContext context){statuses++;return new EvidenceStatus(false,List.of("original-evidence"),List.of(),Map.of("original",true));}
    }
    private SubjectConfirmationConfigurationTestCase wrapper(Fallback fallback){return new SubjectConfirmationConfigurationTestCase(fallback,e->{throw new AssertionError("No recorder originals may be invented");},r->new byte[0],data,r->"browser_sso_idp");}
    private CaseContext context(boolean complete){
        TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Read-only evidence cannot send or record");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Read-only evidence cannot change originals");}};
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    @Test void noOwnedOriginalsKeepApprovedConfigAttestationAndStatusFallback(){
        for(String id:List.of(SimpleSamlPhpSubjectConfirmationEvidence.FR,SimpleSamlPhpSubjectConfirmationEvidence.GD)){
            var fallback=new Fallback(id);var test=wrapper(fallback);var context=context(true);
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context)).outcome().outcome());
            assertEquals("approved.attestation",((CaseStep.Finish)test.resume(context,CaseState.initial(),new CaseEvent.Attested("observed","record"))).outcome().reasonCode());
            assertEquals(Map.of("original",true),test.evidenceStatus(context).details());
            assertEquals(1,fallback.starts);assertEquals(1,fallback.resumes);assertEquals(1,fallback.statuses);
            assertEquals(fallback.instructionEn(),test.instructionEn());assertEquals(fallback.promptEn(),test.promptEn());assertEquals(fallback.options(),test.options());
            assertEquals(RunCampaignQuery.ActionKind.NONE,test.evidenceActionKind());
        }
    }
    @Test void ownedInvalidAndIncompleteOriginalsNeverUseDeclarations()throws Exception{
        Path folder=Files.createDirectory(data.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"no_observation_opportunity\":true}");
        for(boolean complete:List.of(true,false))for(String id:List.of(SimpleSamlPhpSubjectConfirmationEvidence.FR,SimpleSamlPhpSubjectConfirmationEvidence.GD)){
            var fallback=new Fallback(id);var test=wrapper(fallback);var context=context(complete);
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context)).outcome().outcome());
            for(CaseEvent event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("observed","claimed native absence"),new CaseEvent.TranscriptReady()))
                assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context,CaseState.initial(),event)).outcome().outcome());
            assertFalse(test.evidenceStatus(context).ready());assertTrue(test.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
            assertEquals(0,fallback.starts);assertEquals(0,fallback.resumes);assertEquals(0,fallback.statuses);
        }
    }
    @Test void ownedFileAndSymlinkCannotShadowToLegacyConfiguration()throws Exception{
        Path path=Files.writeString(data.resolve(RUN),"{}");var fallback=new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.FR);var test=wrapper(fallback);
        assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(true))).outcome().outcome());
        Files.delete(path);Files.createSymbolicLink(path,Files.createDirectory(data.resolve("foreign")));
        assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(true))).outcome().outcome());assertEquals(0,fallback.starts);
    }
    @Test void anotherNativeAdapterCannotUseAttestationWhenItsOriginalsAreMalformed()throws Exception{
        for(String suffix:List.of(".keycloak-subject-confirmation", ".shibboleth-subject-confirmation")){
            Path receipt=Files.writeString(data.resolve(RUN+suffix+".json"),"{\"restored\":true}");
            var fallback=new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.FR);var test=wrapper(fallback);
            for(boolean complete:List.of(true,false)){
                var context=context(complete);
                assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context)).outcome().outcome());
                for(CaseEvent event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("observed","claimed native absence"),new CaseEvent.TranscriptReady()))
                    assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context,CaseState.initial(),event)).outcome().outcome());
                assertFalse(test.evidenceStatus(context).ready());
                assertTrue(test.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
            }
            assertEquals(0,fallback.starts);assertEquals(0,fallback.resumes);assertEquals(0,fallback.statuses);
            Files.delete(receipt);
            Path originals=Files.createDirectory(data.resolve(RUN+suffix));
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context(true))).outcome().outcome());
            assertEquals(0,fallback.starts);Files.delete(originals);
        }
    }
    @Test void competingNativeOwnersFailClosedBeforeReadingAnyOriginal()throws Exception{
        Path ssp=Files.createDirectory(data.resolve(RUN));Files.writeString(ssp.resolve("manifest.json"),"{}");
        Files.writeString(data.resolve(RUN+".keycloak-subject-confirmation.json"),"{}");
        Files.createDirectory(data.resolve(RUN+".shibboleth-subject-confirmation"));
        var fallback=new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.GD);var test=wrapper(fallback);
        assertEquals("browser.subject-confirmation.native-unproven",((CaseStep.Finish)test.start(context(true))).outcome().reasonCode());
        assertFalse(test.evidenceStatus(context(true)).ready());assertEquals(0,fallback.starts);
    }
    @Test void nativeProvenanceRequiresAdapterReasonAndBothOriginalKinds(){
        var test=wrapper(new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.FR));
        var refs=List.of(new EvidenceRef("transcript","tx_actual"),new EvidenceRef("native-subject-confirmation",RUN+"/manifest.json#digest"));
        var outcome=new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,"browser.subject-confirmation.native-no-opportunity","native",refs,Map.of("evidence_adapter",SimpleSamlPhpSubjectConfirmationEvidence.SCHEMA));
        assertTrue(test.resolvedFromExternalEvidence(execution(outcome)));
        assertFalse(test.resolvedFromExternalEvidence(execution(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,"attestation.satisfies","native",refs,outcome.details()))));
        assertFalse(test.resolvedFromExternalEvidence(execution(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,outcome.reasonCode(),"native",refs,Map.of("evidence_adapter","unknown")))));
        for(var missing:List.of(List.of(refs.get(0)),List.of(refs.get(1)),List.<EvidenceRef>of()))assertFalse(test.resolvedFromExternalEvidence(execution(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,outcome.reasonCode(),"native",missing,outcome.details()))));
        assertFalse(test.resolvedFromExternalEvidence(execution(CaseOutcome.notVerified("unproven","browser.subject-confirmation.native-unproven"))));
    }
    @Test void nativeAdapterProvenanceCannotBorrowAnotherProductsReceiptOrRun(){
        var test=wrapper(new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.FR));
        var adapters=Map.of(KeycloakSubjectConfirmationEvidence.SCHEMA,"keycloak",ShibbolethSubjectConfirmationEvidence.SCHEMA,"shibboleth");
        for(var adapter:adapters.entrySet()){
            String product=adapter.getValue(),kind="native-"+product+"-subject-confirmation";
            String path=RUN+"."+product+"-subject-confirmation.json#digest";
            var refs=List.of(new EvidenceRef("transcript","tx_actual"),new EvidenceRef(kind,path));
            var details=Map.<String,Object>of("evidence_adapter",adapter.getKey());
            var outcome=new CaseOutcome(Outcome.SATISFIED_WITH_NOTE,null,"browser.subject-confirmation.native-no-opportunity","native",refs,details);
            assertTrue(test.resolvedFromExternalEvidence(execution(outcome)));
            for(var wrong:List.of(new EvidenceRef("native-subject-confirmation",RUN+"/manifest.json#digest"),
                    new EvidenceRef(kind,"run_00000000000000000000000001."+product+"-subject-confirmation.json#digest"))){
                var forged=new CaseOutcome(outcome.outcome(),null,outcome.reasonCode(),outcome.reasonMessageKey(),
                        List.of(refs.get(0),wrong),details);
                assertFalse(test.resolvedFromExternalEvidence(execution(forged)));
            }
        }
    }
    @Test void recordedReevaluationDoesNotRewriteConclusiveOutcomes(){
        var test=wrapper(new Fallback(SimpleSamlPhpSubjectConfirmationEvidence.FR));
        for(var outcome:List.of(CaseOutcome.of(Outcome.SATISFIED,"existing",List.of()),CaseOutcome.of(Outcome.VIOLATED,"existing",List.of()),CaseOutcome.of(Outcome.SATISFIED_WITH_NOTE,"existing",List.of()))){
            assertFalse(test.supportsRecordedEvidenceReevaluation(outcome));assertTrue(test.reevaluateRecordedEvidence(context(true),outcome).isEmpty());
        }
        assertFalse(test.supportsRecordedEvidenceReevaluation(null));
    }
    private CaseExecution execution(CaseOutcome outcome){return new CaseExecution(RUN,SimpleSamlPhpSubjectConfirmationEvidence.FR,1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,outcome,Instant.now());}
}
