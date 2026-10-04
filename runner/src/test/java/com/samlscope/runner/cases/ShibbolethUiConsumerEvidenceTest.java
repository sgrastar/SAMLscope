package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ShibbolethUiConsumerEvidenceTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000";
    private CaseContext context(boolean complete) {
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return List.of();}
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    private ShibbolethUiConsumerEvidence reader(){return new ShibbolethUiConsumerEvidence(directory,e->{throw new AssertionError("Invalid proof must not read content");});}
    @Test void missingEvidenceDoesNotClaimOwnershipOrDetermineAnyCase(){
        assertFalse(reader().exists(RUN));
        for(var id:ShibbolethUiConsumerEvidence.SUPPORTED)assertTrue(reader().read(context(true),"<target/>".getBytes(),id).isEmpty());
    }
    @Test void ownedFolderWithoutManifestCannotFallBackToLegacyProof()throws Exception {
        Files.createDirectory(directory.resolve(RUN));assertTrue(reader().exists(RUN));
        assertTrue(reader().read(context(true),"<target/>".getBytes(),"IIP-MD05-fb-idp-01").isEmpty());
    }
    @Test void ownedFileCannotFallBackToLegacyProof()throws Exception {
        Files.writeString(directory.resolve(RUN),"broken");assertTrue(reader().exists(RUN));
        assertTrue(reader().read(context(true),"<target/>".getBytes(),"IIP-MD05-fg-idp-01").isEmpty());
    }
    @Test void ownedSymlinkCannotFallBackToLegacyProof()throws Exception {
        var external=Files.createDirectory(directory.resolve("external"));Files.createSymbolicLink(directory.resolve(RUN),external);
        assertTrue(reader().exists(RUN));assertTrue(reader().read(context(true),"<target/>".getBytes(),"IIP-MD05-fh-idp-01").isEmpty());
    }
    @Test void incompleteRecorderAndForeignCaseCannotDetermine()throws Exception {
        var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),"{}");
        assertTrue(reader().read(context(false),"<target/>".getBytes(),"IIP-MD05-fj-idp-01").isEmpty());
        assertTrue(reader().read(context(true),"<target/>".getBytes(),"IIP-MD05-fa-idp-01").isEmpty());
    }
    @Test void uploadedOutcomeDoesNotSubstituteForOriginals()throws Exception {
        var folder=Files.createDirectory(directory.resolve(RUN));Files.writeString(folder.resolve("manifest.json"),
            "{\"schema\":\"samlscope-shibboleth-native-ui-v1\",\"runId\":\""+RUN+"\",\"outcome\":\"SATISFIED\"}");
        for(var id:ShibbolethUiConsumerEvidence.SUPPORTED)assertTrue(reader().read(context(true),"<target/>".getBytes(),id).isEmpty());
    }
}
