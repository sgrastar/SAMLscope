package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakAuthenticationIdentityEvidenceTest {
    @TempDir Path root;
    private static final String RUN="run_00000000000000000000000000";
    private KeycloakAuthenticationIdentityEvidence reader(){return new KeycloakAuthenticationIdentityEvidence(root,
        e->{throw new AssertionError("Malformed proof must not parse wire originals");},r->new byte[0],r->Optional.empty());}
    private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String run){throw new AssertionError("Owned invalid proof must not read transcript");}
        public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Reader must never send or record");}
        public TranscriptEntry updateSamlAnalysis(String run,String id,Map<String,Object> summary){throw new AssertionError("Reader must never alter history");}
    },complete);}
    @Test void absentNativeProofPreservesApprovedFallback(){assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());}
    @Test void sidecarWithoutManifestOwnsProofAndStaysUnverified()throws Exception {Files.createDirectory(root.resolve(RUN));assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void malformedReceiptCannotBecomeConfigurationDeclaration()throws Exception {Path folder=Files.createDirectory(root.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"not-json");assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void symlinkOwnedDirectoryNeverFallsBack()throws Exception {Path other=Files.createDirectory(root.resolve("other"));Files.writeString(other.resolve("manifest.json"),"{}");Files.createSymbolicLink(root.resolve(RUN),other);assertTrue(reader().exists(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(true)).orElseThrow().outcome());}
    @Test void incompleteHistoryCannotActivateNativeEvidence()throws Exception {Files.createDirectory(root.resolve(RUN));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());}
    @Test void unsafeRunCannotOwnFiles(){assertFalse(reader().exists("../"+RUN));assertFalse(reader().exists(null));assertFalse(reader().exists("run_foreign"));}
}
