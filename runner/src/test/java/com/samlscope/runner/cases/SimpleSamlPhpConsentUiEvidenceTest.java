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

class SimpleSamlPhpConsentUiEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,
        new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader must not execute interactions");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Reader must not modify originals");}},true);}
    @Test void missingAdapterProofDoesNotShadowLegacy(){
        var reader=new SimpleSamlPhpConsentUiEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists(RUN));assertTrue(reader.evaluate(context(),new byte[0]).isEmpty());}
    @Test void declaredDisplayAndRestorationWithoutOriginalsRemainUnverified()throws Exception{
        Path folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"selected\":\"display\",\"restored\":true}");
        var reader=new SimpleSamlPhpConsentUiEvidence(directory,e->{throw new AssertionError();});assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
    @Test void presentFileAndSymlinkFolderAreOwnedFailClosed()throws Exception{
        Path path=Files.writeString(directory.resolve(RUN),"invalid");var reader=new SimpleSamlPhpConsentUiEvidence(directory,e->{throw new AssertionError();});assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());
        Files.delete(path);Path other=Files.createDirectory(directory.resolve("other"));Files.createSymbolicLink(path,other);assertTrue(reader.exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
    @Test void traversalAndSymlinkManifestCannotSupplyNativeEvidence()throws Exception{
        var reader=new SimpleSamlPhpConsentUiEvidence(directory,e->{throw new AssertionError();});assertFalse(reader.exists("../"+RUN));Path folder=Files.createDirectory(directory.resolve(RUN));Path fake=Files.writeString(directory.resolve("other.json"),"{}");Files.createSymbolicLink(folder.resolve("manifest.json"),fake);assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(context(),new byte[0]).orElseThrow().outcome());}
}
