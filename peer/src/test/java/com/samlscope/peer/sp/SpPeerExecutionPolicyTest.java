package com.samlscope.peer.sp;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;

class SpPeerExecutionPolicyTest {
    @TempDir Path directory;

    @Test void heldLateMetadataReceiptPreservesOriginalAnalysisAndWholeRun() throws Exception {
        var fixture = fixture();
        var peer = fixture.peer(run -> { throw new IllegalStateException("retained-definition-read-only"); });
        var before = fixture.runs.find(fixture.run.id()).orElseThrow();
        assertThrows(IllegalStateException.class, () -> peer.consumeDetailed(fixture.plan.id(),
                fixture.body, Map.of(), fixture.url));
        assertEquals(before, fixture.runs.find(fixture.run.id()).orElseThrow());
        var original = fixture.recorder.list(fixture.run.id()).getFirst();
        assertArrayEquals(fixture.xml, fixture.recorder.readDecodedSaml(original));
        assertEquals("transcripts/"+fixture.run.id()+"/"+original.id()+".body", original.bodyRef());
        assertArrayEquals(fixture.body, java.nio.file.Files.readAllBytes(directory.resolve(original.bodyRef())));
        assertEquals("_issued", original.correlationId());
        assertEquals(true, original.samlSummary().get("metadataProbeAccepted"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success", original.samlSummary().get("statusCode"));
    }

    @Test void allowedCurrentReceiptStillCompletesAndInvokesBoundRunPolicy() {
        var fixture = fixture();
        var checked = new ArrayList<String>();
        fixture.peer(checked::add).consumeDetailed(fixture.plan.id(), fixture.body, Map.of(), fixture.url);
        assertEquals(List.of(fixture.run.id()), checked);
        var completed = fixture.runs.find(fixture.run.id()).orElseThrow();
        assertEquals(RunStatus.COMPLETED, completed.status());
        assertEquals(fixture.run.context(), completed.context());
        assertEquals(1, fixture.recorder.list(fixture.run.id()).size());
    }

    private Fixture fixture() {
        var now=Instant.parse("2026-10-08T00:00:00Z");var clock=Clock.fixed(now,ZoneOffset.UTC);
        var database=new SqliteDatabase(directory);var json=new JsonCodec();
        var plans=new SqlitePlanRepository(database,json);var runs=new SqliteRunRepository(database,json);
        var plan=new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","Owned late receipt",FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP,"https://idp.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),now,now);
        plans.save(plan);var service=new RunService(plans,runs,new RunEventBus(),clock);
        var created=service.create(plan.id());var context=Map.<String,Object>of(
                "metadata_polling_requests",Map.of("control","_issued"),"active_metadata_request_id","_issued",
                "metadata_lab",Map.of("selected_variant","control","campaign_index",0));
        var run=service.update(created,RunStatus.WAITING_BROWSER,Reachability.CONFIRMED,context);
        byte[] xml=("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_receipt' InResponseTo='_issued' Version='2.0' IssueInstant='2026-10-08T00:00:00Z'>"
                +"<saml:Issuer>https://idp.example/entity</saml:Issuer><samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status></samlp:Response>").getBytes(StandardCharsets.UTF_8);
        byte[] body=("SAMLResponse="+URLEncoder.encode(Base64.getEncoder().encodeToString(xml),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);
        return new Fixture(plan,run,plans,runs,service,new FileTranscriptRecorder(database,json,directory),directory,clock,xml,body,
                "https://peer.example/p/"+plan.id()+"/sp/acs/0?mdv=control&run="+run.id());
    }

    private record Fixture(TestPlan plan,TestRun run,SqlitePlanRepository plans,SqliteRunRepository runs,
                           RunService service,FileTranscriptRecorder recorder,Path directory,Clock clock,byte[] xml,byte[] body,String url) {
        SpPeerService peer(java.util.function.Consumer<String> policy) {
            var saml=new SamlProtocolService(URI.create("https://peer.example"),new FilePlanKeyStore(directory,clock),
                    new XmlSigner(),new OpenSamlReader(),clock);
            return new SpPeerService(plans,runs,service,new MetadataCache(directory),new TargetMetadataParser(),
                    saml,recorder,clock,(r,a,b,e)->{},new TargetInitiatedIntents(),policy);
        }
    }
}
