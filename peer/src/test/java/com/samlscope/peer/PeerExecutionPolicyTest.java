package com.samlscope.peer;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.Direction;
import com.samlscope.peer.idp.IdpPeerService;
import com.samlscope.peer.logout.SloPeerService;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PeerExecutionPolicyTest {
    @TempDir Path directory;
    private int fixtures;
    static final String P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion";

    @Test void heldPrimaryAndSecondaryIdpRequestsKeepOriginalWithoutSigningOrOutput() {
        for(boolean secondary:List.of(false,true)) {
            var f=fixture(FunctionalProfile.BROWSER_SSO_SP);var before=f.runs.find(f.run.id()).orElseThrow();
            var peer=new IdpPeerService(f.plans,f.runs,f.service,f.cache,new TargetMetadataParser(),f.saml,f.recorder,f.clock,secondary,r->{throw new IllegalStateException("historical-read-only");});
            byte[] request=authnRequest();
            assertThrows(IllegalStateException.class,()->peer.consume(f.plan.id(),"POST",null,form("SAMLRequest",request),Map.of(),"https://suite.example/idp/sso"));
            assertEquals(before,f.runs.find(f.run.id()).orElseThrow());assertEquals(1,f.recorder.list(f.run.id()).size());
            var in=f.recorder.list(f.run.id()).getFirst();assertEquals(Direction.INBOUND,in.direction());assertArrayEquals(request,f.recorder.readDecodedSaml(in));assertEquals("_authn",in.correlationId());
        }
    }

    @Test void currentPrimaryAndSecondaryIdpRequestsStillProduceResponses() {
        for(boolean secondary:List.of(false,true)) {
            var f=fixture(FunctionalProfile.BROWSER_SSO_SP);var checked=new ArrayList<String>();
            var peer=new IdpPeerService(f.plans,f.runs,f.service,f.cache,new TargetMetadataParser(),f.saml,f.recorder,f.clock,secondary,checked::add);
            var result=peer.consume(f.plan.id(),"POST",null,form("SAMLRequest",authnRequest()),Map.of(),"https://suite.example/idp/sso");
            assertEquals(List.of(f.run.id()),checked);assertNotNull(result);assertEquals(2,f.recorder.list(f.run.id()).size());assertEquals(RunStatus.COMPLETED,f.runs.find(f.run.id()).orElseThrow().status());
        }
    }

    @Test void heldLogoutRequestDoesNotConsumePreparedTargetIntentOrIssueResponse() {
        var f=fixture(FunctionalProfile.SINGLE_LOGOUT_IDP);var before=f.runs.find(f.run.id()).orElseThrow();var intents=new TargetInitiatedIntents();
        intents.prepare(f.run.id(),f.plan.id(),TargetInitiatedIntents.Kind.TARGET_LOGOUT,Duration.ofMinutes(5),f.clock);
        var peer=f.slo(intents,r->{throw new IllegalStateException("historical-read-only");});byte[] request=logout("LogoutRequest");
        assertThrows(IllegalStateException.class,()->peer.consume(f.plan.id(),SloPeerService.Transport.FRONT_CHANNEL,"POST",null,form("SAMLRequest",request),Map.of(),"https://suite.example/sp/slo"));
        assertTrue(intents.find(f.run.id(),f.clock).isPresent());assertEquals(before,f.runs.find(f.run.id()).orElseThrow());
        assertEquals(1,f.recorder.list(f.run.id()).size());var in=f.recorder.list(f.run.id()).getFirst();assertEquals(Direction.INBOUND,in.direction());assertArrayEquals(request,f.recorder.readDecodedSaml(in));
    }

    @Test void observationalLogoutResponseRemainsReadableWithoutExecutingPolicy() {
        var f=fixture(FunctionalProfile.SINGLE_LOGOUT_IDP);var before=f.runs.find(f.run.id()).orElseThrow();
        var peer=f.slo(new TargetInitiatedIntents(),r->{throw new AssertionError("Observation must not request execution");});
        var result=peer.consume(f.plan.id(),SloPeerService.Transport.FRONT_CHANNEL,"POST",null,form("SAMLResponse",logout("LogoutResponse")),Map.of(),"https://suite.example/sp/slo?run="+f.run.id());
        assertNull(result.response());assertEquals(before,f.runs.find(f.run.id()).orElseThrow());assertEquals(1,f.recorder.list(f.run.id()).size());
    }

    @Test void currentLogoutRequestStillProducesCorrelatedResponse() {
        var f=fixture(FunctionalProfile.SINGLE_LOGOUT_IDP);var checked=new ArrayList<String>();
        var result=f.slo(new TargetInitiatedIntents(),checked::add).consume(f.plan.id(),SloPeerService.Transport.FRONT_CHANNEL,"POST",null,form("SAMLRequest",logout("LogoutRequest")),Map.of(),"https://suite.example/sp/slo?run="+f.run.id());
        assertEquals(List.of(f.run.id()),checked);assertNotNull(result.response());assertEquals(2,f.recorder.list(f.run.id()).size());
        assertEquals("_logout",SecureXml.parse(result.response().xml()).getDocumentElement().getAttribute("InResponseTo"));
    }

    private Fixture fixture(FunctionalProfile profile) {
        var at=Instant.parse("2026-10-08T00:00:00Z");var clock=Clock.fixed(at,ZoneOffset.UTC);var dir=directory.resolve("fixture"+(fixtures++));var db=new SqliteDatabase(dir);var json=new JsonCodec();var plans=new SqlitePlanRepository(db,json);var runs=new SqliteRunRepository(db,json);
        var plan=new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","Owned policy fixture",profile,new TestPlan.Target(profile==FunctionalProfile.BROWSER_SSO_SP?TargetKind.SP:TargetKind.IDP,"https://target.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://target.example/metadata")),MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),at,at);plans.save(plan);
        var service=new RunService(plans,runs,new RunEventBus(),clock);var created=service.create(plan.id());var run=service.update(created,RunStatus.RUNNING,Reachability.CONFIRMED,Map.of("saved","unchanged"));var cache=new MetadataCache(dir);
        String role=profile==FunctionalProfile.BROWSER_SSO_SP?"SPSSODescriptor":"IDPSSODescriptor";
        byte[] md=("<md:EntityDescriptor xmlns:md='"+MetadataService.MD+"' entityID='https://target.example/entity'><md:"+role+" protocolSupportEnumeration='"+P+"'><md:AssertionConsumerService Binding='"+MetadataService.POST+"' Location='https://target.example/acs' index='0'/><md:SingleLogoutService Binding='"+MetadataService.POST+"' Location='https://target.example/slo'/></md:"+role+"></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);cache.put(plan.id(),md);cache.putIfAbsent(run.id(),md);
        var saml=new SamlProtocolService(URI.create("https://suite.example"),new FilePlanKeyStore(dir,clock),new XmlSigner(),new OpenSamlReader(),clock);
        return new Fixture(plan,run,plans,runs,service,cache,saml,new FileTranscriptRecorder(db,json,dir),clock);
    }
    private byte[] authnRequest(){return ("<samlp:AuthnRequest xmlns:samlp='"+P+"' xmlns:saml='"+A+"' ID='_authn' Version='2.0' IssueInstant='2026-10-08T00:00:00Z' AssertionConsumerServiceURL='https://target.example/acs'><saml:Issuer>https://target.example/entity</saml:Issuer></samlp:AuthnRequest>").getBytes(StandardCharsets.UTF_8);}
    private byte[] logout(String type){return ("<samlp:"+type+" xmlns:samlp='"+P+"' xmlns:saml='"+A+"' ID='_logout' Version='2.0' IssueInstant='2026-10-08T00:00:00Z'><saml:Issuer>https://target.example/entity</saml:Issuer>"+(type.equals("LogoutRequest")?"<saml:NameID>fixture</saml:NameID>":"<samlp:Status><samlp:StatusCode Value='"+P+":status:Success'/></samlp:Status>")+"</samlp:"+type+">").getBytes(StandardCharsets.UTF_8);}
    private byte[] form(String name,byte[] xml){return (name+"="+URLEncoder.encode(Base64.getEncoder().encodeToString(xml),StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8);}
    private record Fixture(TestPlan plan,TestRun run,SqlitePlanRepository plans,SqliteRunRepository runs,RunService service,MetadataCache cache,SamlProtocolService saml,FileTranscriptRecorder recorder,Clock clock){
        SloPeerService slo(TargetInitiatedIntents intents,java.util.function.Consumer<String> policy){return new SloPeerService(plans,runs,cache,new TargetMetadataParser(),saml,recorder,clock,(r,a,x,e)->{},intents,policy);}
    }
}
