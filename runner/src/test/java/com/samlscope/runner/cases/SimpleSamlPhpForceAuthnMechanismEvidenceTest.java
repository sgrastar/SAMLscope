package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
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

class SimpleSamlPhpForceAuthnMechanismEvidenceTest {
    private static final String RUN="run_00000000000000000000000000";
    @TempDir Path directory;
    private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),
        TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String id){throw new AssertionError("Invalid provenance must not reach protocol proof");}
        public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read only");}
        public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Read only");}},complete);}
    private SimpleSamlPhpForceAuthnMechanismEvidence reader(String profile){return new SimpleSamlPhpForceAuthnMechanismEvidence(directory,
        e->{throw new AssertionError("No genuine original");},r->{throw new AssertionError("No genuine target");},r->profile);}
    @Test void MissingOriginalsDoNotClaimAccess(){assertTrue(reader("browser_sso_idp").read(context(true)).isEmpty());}
    @Test void IncorrectProfileCannotBorrowBrowserProof()throws Exception{Files.createDirectory(directory.resolve(RUN+".simplesamlphp-forceauthn-mechanism"));
        assertEquals(Outcome.NOT_VERIFIED,reader("ecp_idp").read(context(true)).orElseThrow().outcome());}
    @Test void IncompleteTranscriptIsUnproven()throws Exception{Files.createDirectory(directory.resolve(RUN+".simplesamlphp-forceauthn-mechanism"));
        assertEquals(Outcome.NOT_VERIFIED,reader("browser_sso_idp").read(context(false)).orElseThrow().outcome());}
    @Test void MalformedOwnedReceiptCannotFallThrough()throws Exception{var f=Files.createDirectory(directory.resolve(RUN+".simplesamlphp-forceauthn-mechanism"));
        Files.writeString(f.resolve("manifest.json"),"{}");assertEquals(Outcome.NOT_VERIFIED,reader("browser_sso_idp").read(context(true)).orElseThrow().outcome());}
    @Test void LinkedFolderIsRejected()throws Exception{Files.createSymbolicLink(directory.resolve(RUN+".simplesamlphp-forceauthn-mechanism"),Files.createDirectory(directory.resolve("other")));
        assertEquals(Outcome.NOT_VERIFIED,reader("browser_sso_idp").read(context(true)).orElseThrow().outcome());}
}
