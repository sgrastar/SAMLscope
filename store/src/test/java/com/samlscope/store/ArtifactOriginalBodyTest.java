package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;

class ArtifactOriginalBodyTest {
    @TempDir Path folder;
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW=Instant.parse("2026-10-08T00:00:00Z");
    FileTranscriptRecorder recorder;
    @BeforeEach void setup(){
        var db=new SqliteDatabase(folder);var json=new JsonCodec();
        var plan=new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","Example",FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP,"https://idp.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);
        new SqlitePlanRepository(db,json).save(plan);new SqliteRunRepository(db,json).save(new TestRun(RUN,plan.id(),RunStatus.RUNNING,Reachability.CONFIRMED,Map.of(),NOW,NOW));
        recorder=new FileTranscriptRecorder(db,json,folder);
    }
    TranscriptEntry record(String type){return recorder.record(new TranscriptInput(RUN,Direction.INBOUND,NOW,"action","POST","https://suite.example/acs",200,Map.of(),"SAMLart=example&RelayState=scope".getBytes(StandardCharsets.UTF_8),"application/x-www-form-urlencoded",null,new byte[0],Map.of("type",type,"body_sha256","forged-input-hash")));}
    @Test void recorderComputesItsOwnHashAndLegacyReadersRemainFailClosed(){
        var entry=record("ArtifactReceived");assertArrayEquals("SAMLart=example&RelayState=scope".getBytes(StandardCharsets.UTF_8),recorder.readBody(entry));assertNotEquals("forged-input-hash",entry.samlSummary().get("body_sha256"));
        var old=record("Other");assertThrows(StoreException.class,()->recorder.readBody(old));
        TranscriptContentReader lambda=e->new byte[0];assertThrows(UnsupportedOperationException.class,()->lambda.readBody(entry));
    }
    @Test void foreignRunForgedEntryAbsoluteAndTraversalReferencesAreRejected(){
        var e=record("ArtifactReceived");
        for(String path:List.of("/tmp/foreign","transcripts/../keys/secret",e.bodyRef().replace(RUN,"run_11111111111111111111111111"))){var copy=copy(e,RUN,path,e.bodyBytes());assertThrows(IllegalArgumentException.class,()->recorder.readBody(copy));}
        assertThrows(IllegalArgumentException.class,()->recorder.readBody(copy(e,"run_11111111111111111111111111",e.bodyRef(),e.bodyBytes())));
        assertThrows(IllegalArgumentException.class,()->recorder.readBody(copy(e,RUN,e.bodyRef(),e.bodyBytes()+1)));
    }
    @Test void sameLengthReplacementAndSymlinkCannotSubstituteAnOriginal()throws Exception{
        var e=record("ArtifactReceived");var path=folder.resolve(e.bodyRef());var original=Files.readAllBytes(path);var altered=original.clone();altered[0]='x';Files.write(path,altered);assertThrows(StoreException.class,()->recorder.readBody(e));
        var elsewhere=folder.resolve("outside.body");Files.write(elsewhere,original);Files.delete(path);Files.createSymbolicLink(path,elsewhere);assertThrows(IllegalArgumentException.class,()->recorder.readBody(e));
    }
    @Test void existingRecorderRedactionStillPrecedesTheStoredHash(){
        var body="SAMLart=example&password=secret-sentinel".getBytes(StandardCharsets.UTF_8);
        var e=recorder.record(new TranscriptInput(RUN,Direction.INBOUND,NOW,"action","POST","https://suite.example/acs",200,Map.of(),body,"application/x-www-form-urlencoded",null,new byte[0],Map.of("type","ArtifactReceived")));
        assertFalse(new String(recorder.readBody(e),StandardCharsets.UTF_8).contains("secret-sentinel"));
    }
    static TranscriptEntry copy(TranscriptEntry e,String run,String body,int length){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),body,length,e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary());}
}
