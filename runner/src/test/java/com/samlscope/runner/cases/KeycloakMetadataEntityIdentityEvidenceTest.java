package com.samlscope.runner.cases;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
class KeycloakMetadataEntityIdentityEvidenceTest {
 @TempDir Path root;private static final String RUN="run_00000000000000000000000000",CASE="IIP-MD05-a1-idp-01";
 private KeycloakMetadataEntityIdentityEvidence reader(){return new KeycloakMetadataEntityIdentityEvidence(root,e->{throw new AssertionError("Malformed proof read wire");},r->new byte[0],r->Optional.empty());}
 private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String r){throw new AssertionError("Malformed proof read history");}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No sending");}public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object>s){throw new AssertionError("No history editing");}},complete);}
 @Test void absentProofPreservesApprovedFallback(){assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true),CASE).isEmpty());}
 @Test void partialOwnedDirectoryStaysUnverified()throws Exception{Files.createDirectory(root.resolve(RUN));assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true),CASE).orElseThrow().outcome());}
 @Test void malformedReceiptStaysUnverified()throws Exception{var dir=Files.createDirectory(root.resolve(RUN));Files.writeString(dir.resolve("manifest.json"),"broken");assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true),CASE).orElseThrow().outcome());}
 @Test void ownedSymlinkNeverFallsBack()throws Exception{var dir=Files.createDirectory(root.resolve("elsewhere"));Files.createSymbolicLink(root.resolve(RUN),dir);assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true),CASE).orElseThrow().outcome());}
 @Test void incompleteHistoryCannotAdopt()throws Exception{Files.createDirectory(root.resolve(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false),CASE).orElseThrow().outcome());}
 @Test void unrelatedCaseAndUnsafeRunNeverOwn(){assertFalse(reader().exists("../"+RUN));assertFalse(reader().exists(null));assertTrue(reader().evaluate(context(true),"IIP-MD06-a-idp-01").isEmpty());}
}
