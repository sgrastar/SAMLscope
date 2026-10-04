package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;

class SimpleSamlPhpPersistentPairwiseEvidenceTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000";
    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
            TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
                public List<TranscriptEntry> list(String run){return List.of();}
                public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Read-only evidence reader");}
                public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Read-only evidence reader");}
            },complete);
    }
    @Test void equalAttributeAliasesCannotProveEqualPrincipals()throws Exception {
        var aliases=new JsonCodec().mapper().readTree("[{\"principal\":\"alice\",\"uid\":[\"shared\"]},{\"principal\":\"bob\",\"uid\":[\"shared\"]}]");
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPersistentPairwiseEvidence.uniquePrincipal(aliases,"shared"));
    }
    @Test void uniquePublicNativeMappingBindsIdentifyingUid()throws Exception {
        var users=new JsonCodec().mapper().readTree("[{\"principal\":\"alice\",\"uid\":[\"uid-alice\"]},{\"principal\":\"bob\",\"uid\":[\"uid-bob\"]}]");
        assertEquals("alice",SimpleSamlPhpPersistentPairwiseEvidence.uniquePrincipal(users,"uid-alice"));
        assertEquals("bob",SimpleSamlPhpPersistentPairwiseEvidence.uniquePrincipal(users,"uid-bob"));
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPersistentPairwiseEvidence.uniquePrincipal(users,"foreign"));
    }
    @Test void AmbiguousOrNonTextualIdentifyingValuesCannotConclude()throws Exception {
        for(var raw:List.of("[]","[{\"principal\":\"a\",\"uid\":[\"x\",\"y\"]}]","[{\"principal\":\"a\",\"uid\":[42]}]",
            "[{\"principal\":\"a\",\"uid\":[\"x\"]},{\"principal\":\"a\",\"uid\":[\"y\"]}]")) {
            var users=new JsonCodec().mapper().readTree(raw);
            assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpPersistentPairwiseEvidence.uniquePrincipal(users,"x"));
        }
    }
    @Test void missingOriginalsAndSymlinkedCampaignCannotConclude()throws Exception {
        var reader=new SimpleSamlPhpPersistentPairwiseEvidence(directory,entry->new byte[0],run->new byte[0]);
        assertTrue(reader.evaluate(context(true)).isEmpty());assertTrue(reader.evaluate(context(false)).isEmpty());
        var outside=Files.createDirectory(directory.resolve("outside"));
        Files.writeString(outside.resolve("manifest.json"),"{\"schema\":\""+SimpleSamlPhpPersistentPairwiseEvidence.SCHEMA+"\",\"runId\":\""+RUN+"\",\"same_principal\":true}");
        Files.createSymbolicLink(directory.resolve(RUN),outside);assertTrue(reader.evaluate(context(true)).isEmpty());
    }
}
