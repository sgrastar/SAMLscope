package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EncryptedLogoutNativeTestCaseTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),
            TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
            new TranscriptRecorder(){
                public List<TranscriptEntry> list(String run){return List.of();}
                public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No direct recording");}
                public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("No original changes");}
            },complete);}
    private EncryptedLogoutNativeTestCase test(){
        java.util.function.Function<String,IdpBasicLogoutScenarioTestCase.Configuration> configurations=
                r->{throw new AssertionError("Owned evidence cannot start another native operation");};
        return new EncryptedLogoutNativeTestCase(new IdpBasicLogoutScenarioTestCase(
                IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID,configurations),new SimpleSamlPhpEncryptedLogoutEvidence(directory,
                e->{throw new AssertionError("No valid original reference");},r->new byte[0],configurations));
    }
    @Test void incompleteOwnedReceiptShadowsEveryProtocolLifecycleWithoutAnotherSend()throws Exception{
        var owned=Files.createDirectory(directory.resolve(RUN));Files.writeString(owned.resolve("manifest.json"),"{}");
        var test=test();
        for(boolean complete:List.of(true,false)){
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(complete))).outcome().outcome());
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(complete),null,new CaseEvent.TranscriptReady())).outcome().outcome());
            assertEquals(Outcome.NOT_VERIFIED,test.queuedEvidenceOutcome(context(complete)).outcome());
            assertFalse(test.evidenceStatus(context(complete)).ready());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("old",
                "slo.encrypted-id.multiple-keys.negative-control-failed")).isEmpty());
    }
    @Test void queuedLookupDoesNotStartAnUnownedBrowserScenario(){
        assertEquals(Outcome.NOT_VERIFIED,test().queuedEvidenceOutcome(context(true)).outcome());
        assertFalse(test().evidenceStatus(context(true)).ready());
    }
    @Test void CompletedAndUnknownDeliveryConclusionsCannotBeRewritten(){
        assertFalse(test().supportsRecordedEvidenceReevaluation(CaseOutcome.of(Outcome.SATISFIED,"old",List.of())));
        assertFalse(test().supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("unknown","outbox.unknown-delivery")));
        assertTrue(test().supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("old",
                "slo.encrypted-id.multiple-keys.negative-control-failed")));
    }
}
