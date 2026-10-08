package com.samlscope.runner.outbox;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.store.*;
import com.sun.net.httpserver.*;
import java.net.*;
import java.net.http.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import javax.net.ssl.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class ArtifactResolutionOutboundSenderTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW=Instant.parse("2026-10-08T00:00:00Z");
    @TempDir Path folder;
    HttpsServer server; PlanCredentials suite; FileTranscriptRecorder recorder; URI endpoint;
    String oldStore,oldPassword,oldType; byte[] received;
    byte[] reply="<soap:Envelope xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'><soap:Body/></soap:Envelope>".getBytes(StandardCharsets.UTF_8);
    @BeforeEach void setup() throws Exception {
        var store=folder.resolve("transport.p12");
        var keytool=Path.of(System.getProperty("java.home"),"bin","keytool").toString();
        var process=new ProcessBuilder(keytool,"-genkeypair","-alias","transport","-keyalg","RSA","-keysize","2048",
                "-validity","2","-dname","CN=localhost","-ext","SAN=dns:localhost","-storetype","PKCS12",
                "-keystore",store.toString(),"-storepass","fixture-password","-keypass","fixture-password","-noprompt")
                .redirectErrorStream(true).start();
        var output=new String(process.getInputStream().readAllBytes(),StandardCharsets.UTF_8);
        assertEquals(0,process.waitFor(),output);
        var keys=KeyStore.getInstance("PKCS12");try(var stream=Files.newInputStream(store)){keys.load(stream,"fixture-password".toCharArray());}
        var managers=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());managers.init(keys,"fixture-password".toCharArray());
        var tls=SSLContext.getInstance("TLS");tls.init(managers.getKeyManagers(),null,null);
        server=HttpsServer.create(new InetSocketAddress("localhost",0),0);server.setHttpsConfigurator(new HttpsConfigurator(tls));
        server.createContext("/resolve",exchange->{
            received=exchange.getRequestBody().readAllBytes();
            assertEquals("POST",exchange.getRequestMethod());assertEquals("\"http://www.oasis-open.org/committees/security\"",exchange.getRequestHeaders().getFirst("SOAPAction"));
            assertNull(exchange.getRequestHeaders().getFirst("Authorization"));assertNull(exchange.getRequestHeaders().getFirst("Cookie"));
            exchange.getResponseHeaders().set("Content-Type","text/xml");exchange.getResponseHeaders().set("Set-Cookie","secret=never-record");
            exchange.sendResponseHeaders(200,reply.length);exchange.getResponseBody().write(reply);exchange.close();
        });server.start();endpoint=URI.create("https://localhost:"+server.getAddress().getPort()+"/resolve");
        oldStore=System.getProperty("javax.net.ssl.trustStore");oldPassword=System.getProperty("javax.net.ssl.trustStorePassword");oldType=System.getProperty("javax.net.ssl.trustStoreType");
        System.setProperty("javax.net.ssl.trustStore",store.toString());System.setProperty("javax.net.ssl.trustStorePassword","fixture-password");System.setProperty("javax.net.ssl.trustStoreType","PKCS12");
        var db=new SqliteDatabase(folder);var json=new JsonCodec();var clock=Clock.fixed(NOW,ZoneOffset.UTC);
        new SqlitePlanRepository(db,json).save(new TestPlan(PLAN,"Artifact transport",FunctionalProfile.BROWSER_SSO_IDP,new TestPlan.Target(TargetKind.IDP,"https://idp.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),MetadataDeliveryKind.MANUAL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW));
        new SqliteRunRepository(db,json).save(new TestRun(RUN,PLAN,RunStatus.RUNNING,Reachability.CONFIRMED,Map.of(),NOW,NOW));
        recorder=new FileTranscriptRecorder(db,json,folder);suite=new FilePlanKeyStore(folder.resolve("plan-keys"),clock).getOrCreate(PLAN);
    }
    @AfterEach void teardown(){if(server!=null)server.stop(0);restore("javax.net.ssl.trustStore",oldStore);restore("javax.net.ssl.trustStorePassword",oldPassword);restore("javax.net.ssl.trustStoreType",oldType);}
    @Test void closedPkixHostnameSenderProducesOriginalBoundReceipt() throws Exception {
        var action=action(endpoint);
        reply=("<soap:Envelope xmlns:soap='"+ArtifactResolutionProtocol.SOAP+"'><soap:Body><p:ArtifactResponse xmlns:p='"+SamlArtifact.P+"' xmlns:a='"+ArtifactResolutionProtocol.A+"' ID='_outer' Version='2.0' IssueInstant='"+NOW+"' InResponseTo='_"+action.actionId()+"'><a:Issuer>https://idp.example/entity</a:Issuer><p:Status><p:StatusCode Value='"+ArtifactResolutionProtocol.SUCCESS+"'/></p:Status><p:Response ID='_inner' Version='2.0' IssueInstant='"+NOW+"' InResponseTo='_authn' Destination='https://suite.example/acs'><a:Issuer>https://idp.example/entity</a:Issuer><p:Status><p:StatusCode Value='"+ArtifactResolutionProtocol.SUCCESS+"'/></p:Status></p:Response></p:ArtifactResponse></soap:Body></soap:Envelope>").getBytes(StandardCharsets.UTF_8);
        var sender=ArtifactResolutionOutboundSender.create(recorder,Clock.fixed(NOW,ZoneOffset.UTC),run->Optional.of(suite));
        var result=sender.send(RUN,action,null);assertArrayEquals(action.payload(),received);assertEquals(2,recorder.list(RUN).size());
        var response=recorder.list(RUN).stream().filter(e->e.id().equals(result.transcriptEntryId())).findFirst().orElseThrow();
        assertFalse(response.headers().keySet().stream().anyMatch(k->k.equalsIgnoreCase("Set-Cookie")));
        assertArrayEquals(reply,recorder.readBody(response));
        @SuppressWarnings("unchecked") var receipt=(Map<String,Object>)result.details().get("transport_authentication");
        assertNotNull(receipt);assertEquals(receipt,response.samlSummary().get("transport_authentication"));
        var proof=ArtifactTlsEvidence.verify(receipt,RUN,action.actionId(),endpoint,(String)result.details().get("request_transcript"),response.id(),action.payload(),reply,suite.certificate());
        assertTrue(proof.isPresent());assertTrue(proof.orElseThrow().coversResponse(reply));
        var resolved=new ArtifactResolutionProtocol().verifyResponse(reply,"_"+action.actionId(),"_authn","https://idp.example/entity",URI.create("https://suite.example/acs"),List.of(),proof.orElseThrow());
        assertEquals("closed-pkix-hostname-tls",resolved.authentication());
        assertThrows(IllegalArgumentException.class,()->new ArtifactResolutionProtocol().verifyResponse(reply,"_"+action.actionId(),"_authn","https://idp.example/entity",URI.create("https://suite.example/acs"),List.of()));
        assertTrue(ArtifactTlsEvidence.verify(receipt,RUN,action.actionId(),endpoint,"another-request",response.id(),action.payload(),reply,suite.certificate()).isEmpty());
    }
    @Test void injectedClientHasNoTlsAuthorityEvenWithSuccessfulRealTls() throws Exception {
        var client=ArtifactTlsPolicy.create().client();var sender=new ArtifactResolutionOutboundSender(client,recorder,Clock.fixed(NOW,ZoneOffset.UTC));
        var result=sender.send(RUN,action(endpoint),null);assertFalse(result.details().containsKey("transport_authentication"));
    }
    @Test void hostnameMismatchAndUntrustedCertificateDoNotProduceProof() throws Exception {
        var sender=ArtifactResolutionOutboundSender.create(recorder,Clock.fixed(NOW,ZoneOffset.UTC),run->Optional.of(suite));
        var wrongHost=URI.create("https://127.0.0.1:"+server.getAddress().getPort()+"/resolve");
        assertThrows(SSLHandshakeException.class,()->sender.send(RUN,action(wrongHost),null));
        // An absent store can fall back to the JDK's cacerts with our fixture password.
        // Use an explicit, readable store whose sole anchor cannot authenticate this server.
        var unrelatedStore=folder.resolve("unrelated-trust-store.p12");
        var unrelatedTrust=KeyStore.getInstance("PKCS12");unrelatedTrust.load(null,null);
        unrelatedTrust.setCertificateEntry("unrelated-authority",suite.certificate());
        try(var output=Files.newOutputStream(unrelatedStore)){unrelatedTrust.store(output,"fixture-password".toCharArray());}
        System.setProperty("javax.net.ssl.trustStore",unrelatedStore.toString());
        var untrusted=ArtifactResolutionOutboundSender.create(recorder,Clock.fixed(NOW,ZoneOffset.UTC),run->Optional.of(suite));
        assertThrows(SSLHandshakeException.class,()->untrusted.send(RUN,action(endpoint),null));
        assertTrue(recorder.list(RUN).stream().noneMatch(e->e.samlSummary().containsKey("transport_authentication")));
    }
    @Test void artifactResolutionRemainsUnsafeAndRejectsCredentialsAndRedirectingClients() throws Exception {
        var sender=ArtifactResolutionOutboundSender.create(recorder,Clock.fixed(NOW,ZoneOffset.UTC),run->Optional.of(suite));
        assertEquals(OutboundKind.Retry.UNSAFE,OutboundKind.ARTIFACT_RESOLVE.retry());
        assertThrows(IllegalArgumentException.class,()->sender.send(RUN,action(endpoint),new byte[]{1}));
        assertThrows(IllegalArgumentException.class,()->new ArtifactResolutionOutboundSender(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build(),recorder,Clock.fixed(NOW,ZoneOffset.UTC)));
        assertTrue(recorder.list(RUN).isEmpty());
    }
    OutboundAction action(URI target){var artifact=SamlArtifact.parse(Base64.getEncoder().encodeToString(ByteBuffer.allocate(44).putShort((short)4).putShort((short)7).put(new byte[40]).array()));var id=ActionIds.derive(RUN,ArtifactResolutionOutboundSender.CASE,ArtifactResolutionOutboundSender.PHASE,0);return new OutboundAction(id,OutboundKind.ARTIFACT_RESOLVE,new ArtifactResolutionProtocol().resolve(artifact,"_"+id,target,"https://suite.example/sp",NOW,suite),target,false);}
    static void restore(String key,String value){if(value==null)System.clearProperty(key);else System.setProperty(key,value);}
}
