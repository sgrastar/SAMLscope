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

class AttributePolicyConfigurationTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path data;
    private static final class Fallback implements TestCase, ConfigurationPrompt {
        private final String id; int starts, resumes;
        Fallback(String id){this.id=id;}
        public String id(){return id;}
        public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Approved fixed attribute policy";}
        public CaseStep start(CaseContext context){starts++;return new CaseStep.Finish(CaseOutcome.notVerified("original","approved.configuration"));}
        public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){resumes++;return new CaseStep.Finish(CaseOutcome.notVerified("original","approved.evidence"));}
    }
    private AttributePolicyConfigurationTestCase wrapper(Fallback fallback){
        return new AttributePolicyConfigurationTestCase(fallback,entry->{throw new AssertionError("No invented original or protocol operation");},
                run->new byte[0],(run,variant)->Optional.empty(),data.resolve("attribute-policy-preparations"));
    }
    private CaseContext context(boolean complete){
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Read-only reevaluation cannot record or send");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Original history is immutable");}
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    private Path nativeFolder()throws Exception{
        return Files.createDirectories(data.resolve("attribute-service-index-evidence").resolve(RUN));
    }
    @Test void absentNativeOriginalsKeepTheApprovedConfigurationFallback(){
        var fallback=new Fallback(AttributePolicyComparison.INDEX);var test=wrapper(fallback);var context=context(true);
        assertEquals("approved.configuration",((CaseStep.Finish)test.start(context)).outcome().reasonCode());
        assertEquals("approved.evidence",((CaseStep.Finish)test.resume(context,CaseState.initial(),new CaseEvent.Attested("observed","record"))).outcome().reasonCode());
        assertEquals(1,fallback.starts);assertEquals(1,fallback.resumes);
        assertTrue(test.requiresPreparationConfirmation());
        assertEquals(List.of("control","attribute-policy-indexed"),test.evidenceActionKeys());
    }
    @Test void ownedDeclarationsCannotEscapeToConfirmationOrAttestation()throws Exception{
        Files.writeString(nativeFolder().resolve("manifest.json"),"{\"restored\":true,\"indexSelected\":true}");
        for(boolean complete:List.of(true,false)){
            var fallback=new Fallback(AttributePolicyComparison.INDEX);var test=wrapper(fallback);var context=context(complete);
            assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.start(context)).outcome().outcome());
            for(CaseEvent event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("observed","claimed selection"),new CaseEvent.TranscriptReady()))
                assertEquals(Outcome.NOT_VERIFIED,((CaseStep.Finish)test.resume(context,CaseState.initial(),event)).outcome().outcome());
            assertFalse(test.evidenceStatus(context).ready());
            assertTrue(test.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty());
            assertEquals(0,fallback.starts);assertEquals(0,fallback.resumes);
        }
    }
    @Test void nativeIndexOriginalsDoNotReplaceOtherAttributePolicyCases()throws Exception{
        Files.writeString(nativeFolder().resolve("manifest.json"),"{}");
        for(String id:List.of(AttributePolicyComparison.ENTITY,AttributePolicyComparison.REQUESTED)){
            var fallback=new Fallback(id);var test=wrapper(fallback);
            assertEquals("approved.configuration",((CaseStep.Finish)test.start(context(true))).outcome().reasonCode());
            assertEquals("approved.evidence",((CaseStep.Finish)test.resume(context(true),CaseState.initial(),new CaseEvent.Attested("observed","record"))).outcome().reasonCode());
            assertEquals(1,fallback.starts);assertEquals(1,fallback.resumes);
        }
    }
    @Test void recordedNativeReevaluationCannotRewriteExistingConclusions(){
        var test=wrapper(new Fallback(AttributePolicyComparison.INDEX));
        for(Outcome value:List.of(Outcome.SATISFIED,Outcome.VIOLATED,Outcome.SATISFIED_WITH_NOTE)){
            var previous=CaseOutcome.of(value,"existing",List.of());
            assertFalse(test.supportsRecordedEvidenceReevaluation(previous));
            assertTrue(test.reevaluateRecordedEvidence(context(true),previous).isEmpty());
        }
        assertFalse(test.supportsRecordedEvidenceReevaluation(null));
    }
}
