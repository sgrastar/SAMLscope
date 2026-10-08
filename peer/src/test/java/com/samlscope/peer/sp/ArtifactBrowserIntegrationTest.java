package com.samlscope.peer.sp;

import static org.junit.jupiter.api.Assertions.*;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.runner.cases.*;
import com.samlscope.runner.outbox.*;
import com.samlscope.saml.artifact.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;

/** Actual persisted case -> browser peer callback -> outbox SOAP -> recorded result. */
class ArtifactBrowserIntegrationTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS",TARGET="https://idp.example/entity",SUITE="https://suite.example/p/"+PLAN;
    static final URI SSO=URI.create("https://idp.example/sso"),ACS=URI.create("https://suite.example/p/"+PLAN+"/sp/acs/0");
    static final String CASE=ArtifactBindingEvidence.CASE;
    @TempDir Path folder;
    final LiveClock clock=new LiveClock();
    SqlitePlanRepository plans;SqliteRunRepository runs;SqliteCaseExecutionRepository executions;
    FileTranscriptRecorder recorder;PlanCredentials suite,target;MetadataCache metadata;TestPlan plan;
    ActiveProbeCoordinator coordinator;SpPeerService peer;HttpServer server;
    final AtomicInteger sends=new AtomicInteger(); boolean unknown,invalidSignature;int httpStatus=200;
    byte[] targetMetadata;String relay,artifact;
    @BeforeEach void setup() throws Exception {
        var database=new SqliteDatabase(folder);var json=new JsonCodec();
        plans=new SqlitePlanRepository(database,json);runs=new SqliteRunRepository(database,json);executions=new SqliteCaseExecutionRepository(database,json);recorder=new FileTranscriptRecorder(database,json,folder);
        plan=new TestPlan(PLAN,"Generic Artifact",FunctionalProfile.BROWSER_SSO_IDP,new TestPlan.Target(TargetKind.IDP,TARGET,new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),MetadataDeliveryKind.MANUAL,Map.of("artifact_binding",true),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),clock.instant(),clock.instant());
        plans.save(plan);runs.save(new TestRun(RUN,PLAN,RunStatus.RUNNING,Reachability.CONFIRMED,Map.of(),clock.instant(),clock.instant()));
        var keys=new FilePlanKeyStore(folder.resolve("keys"),clock);suite=keys.getOrCreate(PLAN);target=keys.getOrCreate(PLAN,"target");
        server=HttpServer.create(new InetSocketAddress("127.0.0.1",0),0);
        var ars=URI.create("http://127.0.0.1:"+server.getAddress().getPort()+"/resolve");
        server.createContext("/resolve",exchange->{try{
            sends.incrementAndGet();var request=exchange.getRequestBody().readAllBytes();var outer=new ArtifactResolutionProtocol().soapMessage(request,"ArtifactResolve");
            assertEquals(artifact,outer.getElementsByTagNameNS(SamlArtifact.P,"Artifact").item(0).getTextContent());
            new ArtifactResolutionProtocol().verifyResolve(request,SamlArtifact.parse(artifact),outer.getAttribute("ID"),ars,SUITE,suite.certificate());
            var response=artifactResponse(outer.getAttribute("ID"));exchange.getResponseHeaders().set("Content-Type","text/xml");exchange.sendResponseHeaders(httpStatus,response.length);exchange.getResponseBody().write(response);exchange.close();
        }catch(Exception failure){exchange.close();throw new RuntimeException(failure);}});server.start();
        String cert=Base64.getEncoder().encodeToString(target.certificate().getEncoded());
        targetMetadata=("<md:EntityDescriptor xmlns:md='"+SamlArtifact.MD+"' xmlns:ds='"+ArtifactResolutionProtocol.DS+"' entityID='"+TARGET+"'><md:IDPSSODescriptor protocolSupportEnumeration='"+SamlArtifact.P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:ArtifactResolutionService index='7' Binding='"+SamlArtifact.SOAP+"' Location='"+ars+"'/><md:SingleSignOnService Binding='"+MetadataService.POST+"' Location='"+SSO+"'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        metadata=new MetadataCache(folder);metadata.put(PLAN,targetMetadata);metadata.putIfAbsent(RUN,targetMetadata);
        var config=new IdpErrorProbeConfiguration(SSO,SUITE,ACS,Duration.ofMinutes(2),true,true,true);
        var test=new IdpAcsSelectionScenarioTestCase(CASE,r->config,recorder,r->Optional.of(TARGET),r->List.of(target.certificate()),r->Optional.of(suite)).withArtifactInput(recorder,r->targetMetadata);
        var registry=new TestCaseRegistry(List.of(test));
        CaseContextProvider contexts=r->new DefaultCaseContext(r,TargetRole.IDP,clock,plan.parameters(),plan.interaction(),Reachability.CONFIRMED,recorder,true);
        var service=new CaseExecutionService(executions,new PlanRequestSigning(plans,runs,keys));service.enqueueFrontChannel(RUN,test,contexts.contextFor(RUN));
        var sender=new HttpOutboundSender(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(),recorder,clock);
        var dispatcher=new OutboundDispatcher(executions,(r,a,c)->{var result=sender.send(r,a,c);if(unknown)throw new java.io.IOException("delivery uncertain after send");return result;},(r,a)->Optional.empty(),new OutboundPolicy(true),clock);
        coordinator=new ActiveProbeCoordinator(URI.create("https://suite.example"),plans,runs,executions,dispatcher,recorder,contexts,(p,r)->config,registry,clock,service,r->suite);
        var saml=new SamlProtocolService(URI.create("https://suite.example"),keys,new XmlSigner(),new OpenSamlReader(),clock);
        peer=new SpPeerService(plans,runs,new RunService(plans,runs,new RunEventBus(),clock),metadata,new TargetMetadataParser(),saml,recorder,clock,(r,a,b,e)->coordinator.accept(r,a,b,e));
        artifact=Base64.getEncoder().encodeToString(ByteBuffer.allocate(44).putShort((short)4).putShort((short)7).put(MessageDigest.getInstance("SHA-1").digest(TARGET.getBytes(StandardCharsets.UTF_8))).put(new byte[20]).array());
    }
    @AfterEach void teardown(){if(server!=null)server.stop(0);}
    String prepareArtifact(){
        for(String fixture:List.of("post-binding-control","redirect-binding","unsupported-binding")){
            var status=coordinator.status(RUN);assertEquals(ActiveProbeCoordinator.State.READY,status.state(),fixture+" "+executions.find(RUN,CASE).orElseThrow());var prepared=coordinator.prepare(RUN,status.actionId(),false);clock.advance();
            var response=browserResponse("_"+status.actionId(),fixture.equals("post-binding-control"));
            var form="SAMLResponse="+url(Base64.getEncoder().encodeToString(response))+"&RelayState="+url(prepared.relayState());
            peer.consumeDetailed(PLAN,form.getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),ACS.toString());
            clock.advance();
        }
        var ready=coordinator.status(RUN);var original=coordinator.prepare(RUN,ready.actionId(),false);
        relay=original.relayState();clock.advance();
        var entry=recorder.list(RUN).stream().filter(e->e.id().equals(original.transcriptEntryId())).findFirst().orElseThrow();
        assertEquals(ArtifactBindingEvidence.FIXTURE,entry.samlSummary().get("fixture_id"));
        assertEquals(ArtifactBindingEvidence.PHASE,executions.find(RUN,CASE).orElseThrow().state().phase());
        return "SAMLart="+url(artifact)+"&RelayState="+url(relay);
    }
    @Test void getArtifactUsesExistingPeerCallbackAndOneUnsafeSoapResolution(){
        var form=prepareArtifact();var consumed=peer.consumeRedirectDetailed(PLAN,form,Map.of("Cookie",List.of("secret=not-recorded")),ACS.resolve("4")+"?"+form);
        assertTrue(consumed.activeProbe());assertEquals(Outcome.SATISFIED,outcome());assertEquals(1,sends.get());
        assertEquals(10,executions.find(RUN,CASE).orElseThrow().outcome().evidence().size());
        assertTrue(recorder.list(RUN).stream().filter(e->"ArtifactReceived".equals(e.samlSummary().get("type"))).allMatch(e->e.headers().keySet().stream().noneMatch(k->k.equalsIgnoreCase("Cookie"))));
        coordinator.status(RUN);assertEquals(1,sends.get());
    }
    @Test void postArtifactPreservesOriginalFormAndReplaysDoNotAdvanceOrSendAgain(){
        var form=prepareArtifact();var body=form.getBytes(StandardCharsets.UTF_8);var headers=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));
        peer.consumeDetailed(PLAN,body,headers,ACS.resolve("4").toString());assertEquals(Outcome.SATISFIED,outcome());
        var received=recorder.list(RUN).stream().filter(e->"ArtifactReceived".equals(e.samlSummary().get("type"))).findFirst().orElseThrow();assertArrayEquals(body,recorder.readBody(received));
        peer.consumeDetailed(PLAN,body,headers,ACS.resolve("4").toString());assertEquals(1,sends.get());
    }
    @Test void malformedMixedForeignRelayAndWrongAcsCannotReachTheOutbox(){
        var form=prepareArtifact();var headers=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));
        for(String bad:List.of(form+"&SAMLResponse=other",form+"&SAMLart="+url(artifact),"SAMLart=malformed&RelayState="+url(relay),"SAMLart="+url(artifact)+"&RelayState=foreign"))assertThrows(RuntimeException.class,()->peer.consumeDetailed(PLAN,bad.getBytes(StandardCharsets.UTF_8),headers,ACS.resolve("4").toString()));
        assertThrows(RuntimeException.class,()->peer.consumeDetailed(PLAN,form.getBytes(StandardCharsets.UTF_8),headers,ACS.toString()));assertEquals(0,sends.get());assertEquals(CaseExecutionStatus.WAITING_INBOUND,executions.find(RUN,CASE).orElseThrow().status());
    }
    @Test void unknownDeliveryNeverSucceedsAndUnsafeStatusQueriesNeverRetry(){
        var form=prepareArtifact();unknown=true;peer.consumeRedirectDetailed(PLAN,form,Map.of(),ACS.resolve("4")+"?"+form);
        assertEquals(Outcome.NOT_VERIFIED,outcome());assertEquals(1,sends.get());coordinator.status(RUN);assertEquals(1,sends.get());
        assertEquals(OutboxStatus.UNKNOWN_DELIVERY,executions.findOutbox(ActionIds.derive(RUN,CASE,ArtifactResolutionOutboundSender.PHASE,0)).orElseThrow().status());
    }
    @Test void invalidSignatureOnHttp200IsNotProductFailureOrSuccess(){
        var form=prepareArtifact();invalidSignature=true;peer.consumeRedirectDetailed(PLAN,form,Map.of(),ACS.resolve("4")+"?"+form);assertEquals(Outcome.NOT_VERIFIED,outcome());
    }
    @Test void trustedResponseOnHttp500StillHasNoSuccessfulBindingProof(){
        var form=prepareArtifact();httpStatus=500;peer.consumeRedirectDetailed(PLAN,form,Map.of(),ACS.resolve("4")+"?"+form);assertEquals(Outcome.NOT_VERIFIED,outcome());
    }
    @Test void foreignRunOrChangedMetadataEpochCannotBeBorrowedForTheCurrentCase(){
        var form=prepareArtifact();
        var another="run_1123456789ABCDEFGHJKMNPQRS";
        var foreign="SAMLart="+url(artifact)+"&RelayState="+url(ActiveProbeCorrelation.encode(another,ActionIds.derive(another,CASE,ArtifactBindingEvidence.PHASE,0)));
        assertThrows(RuntimeException.class,()->peer.consumeRedirectDetailed(PLAN,foreign,Map.of(),ACS.resolve("4")+"?"+foreign));
        targetMetadata=(new String(targetMetadata,StandardCharsets.UTF_8)+" ").getBytes(StandardCharsets.UTF_8);
        peer.consumeRedirectDetailed(PLAN,form,Map.of(),ACS.resolve("4")+"?"+form);assertEquals(Outcome.NOT_VERIFIED,outcome());assertEquals(0,sends.get());
    }
    Outcome outcome(){return executions.find(RUN,CASE).orElseThrow().outcome().outcome();}
    byte[] browserResponse(String request,boolean success){var d=SecureXml.newDocument();var root=d.createElementNS(SamlArtifact.P,"samlp:Response");root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",SamlArtifact.P);root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",ArtifactResolutionProtocol.A);d.appendChild(root);response(root,"_b"+request,request,success,ACS);new XmlSigner().sign(root,target,null);return SecureXml.serialize(d);}
    byte[] artifactResponse(String resolve){var d=SecureXml.newDocument();var env=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Envelope");env.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:soap",ArtifactResolutionProtocol.SOAP);d.appendChild(env);var body=d.createElementNS(ArtifactResolutionProtocol.SOAP,"soap:Body");env.appendChild(body);var outer=d.createElementNS(SamlArtifact.P,"samlp:ArtifactResponse");outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",SamlArtifact.P);outer.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",ArtifactResolutionProtocol.A);body.appendChild(outer);response(outer,"_outer",resolve,true,null);var inner=d.createElementNS(SamlArtifact.P,"samlp:Response");outer.appendChild(inner);response(inner,"_inner","_"+ActionIds.derive(RUN,CASE,ArtifactBindingEvidence.PHASE,0),true,ACS.resolve("4"));new XmlSigner().sign(outer,invalidSignature?suite:target,null);return SecureXml.serialize(d);}
    void response(Element e,String id,String inResponseTo,boolean success,URI destination){e.setAttribute("ID",id);e.setAttribute("Version","2.0");e.setAttribute("IssueInstant",clock.instant().toString());e.setAttribute("InResponseTo",inResponseTo);if(destination!=null)e.setAttribute("Destination",destination.toString());var d=e.getOwnerDocument();var issuer=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Issuer");issuer.setTextContent(TARGET);e.appendChild(issuer);var status=d.createElementNS(SamlArtifact.P,"samlp:Status");e.appendChild(status);var code=d.createElementNS(SamlArtifact.P,"samlp:StatusCode");status.appendChild(code);code.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:"+(success?"Success":"Responder"));if(success&&destination!=null){var assertion=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Assertion");assertion.setAttribute("ID","_assert"+id);assertion.setAttribute("Version","2.0");assertion.setAttribute("IssueInstant",clock.instant().toString());e.appendChild(assertion);var assertionIssuer=d.createElementNS(ArtifactResolutionProtocol.A,"saml:Issuer");assertionIssuer.setTextContent(TARGET);assertion.appendChild(assertionIssuer);}}
    static String url(String s){return URLEncoder.encode(s,StandardCharsets.UTF_8);}
    static final class LiveClock extends Clock {Instant now=Instant.parse("2026-10-08T00:00:00Z");public ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(ZoneId z){return this;}public Instant instant(){return now;}void advance(){now=now.plusSeconds(1);}}
}
