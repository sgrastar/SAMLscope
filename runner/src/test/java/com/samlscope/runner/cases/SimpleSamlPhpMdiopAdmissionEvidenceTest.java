package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class SimpleSamlPhpMdiopAdmissionEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("No interactions from reader");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("No original changes from reader");}},true);}
    @Test void malformedNativeDeclarationsDoNotProveAdmission()throws Exception{
        Files.writeString(directory.resolve(RUN+".ssp-mdiop-representation.json"),"{\"admitted\":true,\"restored\":true}");var reader=new SimpleSamlPhpMdiopAdmissionEvidence(directory,e->{throw new AssertionError();});
        assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).outcome());}
    @Test void presentDirectoryAndSymlinkAreOwnedFailClosed()throws Exception{
        Path file=directory.resolve(RUN+".ssp-mdiop-representation.json");Files.createDirectory(file);var reader=new SimpleSamlPhpMdiopAdmissionEvidence(directory,e->{throw new AssertionError();});
        assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).outcome());Files.delete(file);
        Path other=Files.writeString(directory.resolve("other.json"),"{}");Files.createSymbolicLink(file,other);assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).outcome());}
    @Test void invalidRunNeverFindsOrReadsAReceipt(){var reader=new SimpleSamlPhpMdiopAdmissionEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists("../"+RUN));assertFalse(reader.exists(null));assertFalse(reader.exists(RUN));}
}
