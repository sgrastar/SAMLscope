package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.transcript.*;import com.samlscope.core.plan.*;import com.samlscope.core.run.Reachability;import com.samlscope.core.evaluation.Outcome;import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;import java.time.*;import java.util.*;import org.junit.jupiter.api.Test;import org.junit.jupiter.api.io.TempDir;
class SimpleSamlPhpEncryptedLogoutEvidenceTest{
 @TempDir Path directory;private static final String RUN="run_00000000000000000000000000";
 private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}},complete);}
 private SimpleSamlPhpEncryptedLogoutEvidence reader(){return new SimpleSamlPhpEncryptedLogoutEvidence(directory,e->{throw new AssertionError();},run->new byte[0],run->{throw new AssertionError();});}
 @Test void absentPreservesLegacy(){assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());assertFalse(reader().exists("../"+RUN));}
 @Test void operatorClaimsCannotManufactureUnknownKeyCounterexample()throws Exception{var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{\"restored\":true,\"unknown_key_success\":true,\"native_decryption_failed\":true}");assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
 @Test void ownedFileAndSymlinkFailClosed()throws Exception{var file=Files.writeString(directory.resolve(RUN),"{}");assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());Files.delete(file);Files.createSymbolicLink(file,Files.createDirectory(directory.resolve("foreign")));assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
 @Test void incompleteTranscriptNeverConcludes()throws Exception{Files.createDirectory(directory.resolve(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());}
}
