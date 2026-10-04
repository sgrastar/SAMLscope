package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataRoleKeyEvidenceTest {
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path directory;
    @Test void brokenOwnedFolderAndSymlinkCannotFallbackIntoActiveSending()throws Exception{
        var reader=reader();assertFalse(reader.exists(RUN));Files.writeString(directory.resolve(RUN),"not a folder");assertTrue(reader.exists(RUN));assertTrue(reader.evaluate(context(true)).isEmpty());Files.delete(directory.resolve(RUN));var outside=Files.createDirectory(directory.resolve("outside"));Files.writeString(outside.resolve("manifest.json"),"{}");Files.createSymbolicLink(directory.resolve(RUN),outside);assertTrue(reader.exists(RUN));assertTrue(reader.evaluate(context(true)).isEmpty());
    }
    @Test void selfReportedCountersAndRestoreFlagCannotEstablishRoleUse()throws Exception{
        var proof=Files.createDirectory(directory.resolve(RUN));Files.writeString(proof.resolve("manifest.json"),"{\"schema\":\""+MetadataRoleKeyEvidence.SCHEMA+"\",\"adapter\":\""+MetadataRoleKeyEvidence.ADAPTER+"\",\"runId\":\""+RUN+"\",\"normalSignedEncryptedSuccesses\":4,\"restored\":true}");assertTrue(reader().evaluate(context(true)).isEmpty());assertTrue(reader().evaluate(context(false)).isEmpty());
    }
    private MetadataRoleKeyEvidence reader(){return new MetadataRoleKeyEvidence(directory,e->new byte[0],r->new byte[0],(r,v)->Optional.empty());}
    private static DefaultCaseContext context(boolean complete){var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object> m){throw new UnsupportedOperationException();}};return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);}
}
