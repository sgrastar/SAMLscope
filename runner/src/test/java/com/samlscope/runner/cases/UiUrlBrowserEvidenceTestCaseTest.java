package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class UiUrlBrowserEvidenceTestCaseTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000";
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return List.of();}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Observer wrote a transcript");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Observer mutated a transcript");}
        },true);
    }
    @Test void absentOrCallerInventedEvidenceCannotCompleteTheCase() throws Exception {
        var observer=new UiUrlBrowserEvidenceTestCase(e->{throw new AssertionError("No originals expected");},
                run->"<EntityDescriptor/>".getBytes(java.nio.charset.StandardCharsets.UTF_8),directory);
        assertEquals(15,new HashSet<>(observer.evidenceActionKeys()).size());
        assertFalse(observer.evidenceStatus(context()).ready());
        assertEquals(Outcome.NOT_VERIFIED,observer.queuedEvidenceOutcome(context()).outcome());
        assertInstanceOf(CaseStep.Finish.class,observer.start(context()));
        // A proposed decision cannot replace the required native receipt and originals.
        Files.writeString(directory.resolve(RUN+".json"),"{\"use\":\"VERIFIED_NONUSE\",\"outcome\":\"SATISFIED\"}");
        assertFalse(observer.evidenceStatus(context()).ready());
        assertEquals(Outcome.NOT_VERIFIED,observer.queuedEvidenceOutcome(context()).outcome());
    }
    @Test void symlinkCannotSupplyAnExternalReceipt() throws Exception {
        var reader=new UiUrlEvidenceFile(directory);
        var other=directory.resolve("other.json");Files.writeString(other,"{}");
        Files.createSymbolicLink(directory.resolve(RUN+".json"),other);
        assertThrows(IllegalArgumentException.class,()->reader.read(context(),new byte[0],e->new byte[0]));
    }
}
