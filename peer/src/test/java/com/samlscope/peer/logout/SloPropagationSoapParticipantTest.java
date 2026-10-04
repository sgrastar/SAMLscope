package com.samlscope.peer.logout;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.RunEventBus;
import com.samlscope.runner.RunService;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.logout.SloPropagationFixtures;
import com.samlscope.saml.metadata.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class SloPropagationSoapParticipantTest {
    @TempDir java.nio.file.Path directory;
    static final String P="urn:oasis:names:tc:SAML:2.0:protocol", A="urn:oasis:names:tc:SAML:2.0:assertion";

    @Test void preparedFailureAndAllSuccessProduceSignedParticipantScopedRepliesOnlyAtReturnBoundary() {
        for (var trial : List.of("failure", "all-success")) {
            var f=fixture(); prepare(f, trial, f.saml.prepareSloPropagationMetadata(f.plan,f.run,trial,f.at),Map.of());
            for(var participant:List.of("remain2","fail","remain")) {
                var url=f.saml.sloPropagationEndpoint(f.plan,f.run,trial,participant).toString();
                int before=f.recorder.list(f.run).size();
                var result=f.service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,request(f,url,f.plan.target().entityId()),
                        Map.of("Authorization",List.of("secret"),"Cookie",List.of("secret")),url);
                assertEquals(before+1,f.recorder.list(f.run).size(),"Construction alone must not claim a reply returned");
                var envelope=f.service.soapResponse(result); var response=message(envelope);
                assertEquals(requestId(url),response.getAttribute("InResponseTo"));
                assertEquals("https://idp.example/slo/soap",response.getAttribute("Destination"));
                assertEquals("https://suite.example/p/"+f.plan.id()+"/sp-"+participant,response.getElementsByTagNameNS(A,"Issuer").item(0).getTextContent());
                var status=((Element)response.getElementsByTagNameNS(P,"StatusCode").item(0)).getAttribute("Value");
                assertEquals("urn:oasis:names:tc:SAML:2.0:status:"+("failure".equals(trial)&&"remain2".equals(participant)?"Responder":"Success"),status);
                assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(response,f.keys.getOrCreate(f.plan.id()).certificate()));
                var entries=f.recorder.list(f.run); var out=entries.stream().filter(e->e.direction()==Direction.OUTBOUND
                        && result.response().id().equals(e.correlationId())).findFirst().orElseThrow();
                assertArrayEquals(envelope,f.recorder.readDecodedSaml(out)); assertEquals(200,out.status());
                assertEquals("soapResponse-return",out.samlSummary().get("producerBoundary"));
                assertEquals(participant,out.samlSummary().get("propagationParticipant"));
                assertEquals(SloPropagationFixtures.mode(trial),out.samlSummary().get("propagationMode"));
                assertEquals(List.of("remain2","fail","remain").indexOf(participant)+1,out.samlSummary().get("propagationOrdinal"));
                assertTrue(entries.stream().filter(e->e.direction()==Direction.INBOUND).allMatch(e->e.headers().isEmpty()));
            }
        }
    }

    @Test void missingAmbiguousForeignOrAlteredPreparationCannotSelectErrorMode() {
        for(var fault:List.of("missing","duplicate","foreign-case","foreign-run","foreign-plan","altered-bytes","wrong-timestamp")) {
            var f=fixture();var raw=f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at);
            var fields=new LinkedHashMap<String,Object>();
            switch(fault) {
                case "foreign-case" -> fields.put("case_id","IIP-IDP17-s-idp-01");
                case "foreign-run" -> fields.put("run_id","run_foreign");
                case "foreign-plan" -> fields.put("plan_id","plan_foreign");
                case "wrong-timestamp" -> fields.put("prepared_at",f.at.plusSeconds(1).toString());
                case "altered-bytes" -> raw=new String(raw,StandardCharsets.UTF_8).replace("sp-remain2","sp-foreign").getBytes(StandardCharsets.UTF_8);
            }
            if(!"missing".equals(fault))prepare(f,"failure",raw,fields);
            if("duplicate".equals(fault))prepare(f,"failure",raw,fields);
            var url=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","fail").toString();int before=f.recorder.list(f.run).size();
            assertThrows(SamlException.class,()->f.service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,
                    request(f,url,f.plan.target().entityId()),Map.of(),url),fault);
            assertEquals(before,f.recorder.list(f.run).size(),fault);
        }
    }

    @Test void markerEndpointIssuerAndRunAreExactAndCannotFallIntoNormalSuccess() {
        for(var fault:List.of("marker","participant","trial","extra-query","different-destination","foreign-issuer","foreign-run","front-channel","unprepared-base")) {
            var f=fixture();prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
            var original=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","fail").toString();
            var url=switch(fault){case "marker"->original.replace("error-v2","error-v1");case "participant"->original.replace("participant=fail","participant=foreign");
                case "trial"->original.replace("trial=failure","trial=other");case "extra-query"->original+"&other=1";
                case "foreign-run"->original.replace(f.run,"run_00000000000000000000000000");case "unprepared-base"->original.replace("suite.example","foreign.example");default->original;};
            var issuer="foreign-issuer".equals(fault)?"https://foreign.example":f.plan.target().entityId();
            var raw=request(f,"different-destination".equals(fault)?original+"&other=1":url,issuer);
            var transport="front-channel".equals(fault)?SloPeerService.Transport.FRONT_CHANNEL:SloPeerService.Transport.SOAP;
            assertThrows(RuntimeException.class,()->f.service.consume(f.plan.id(),transport,"POST",null,raw,Map.of(),url),fault);
            assertEquals(2,f.recorder.list(f.run).size(),fault);
        }
    }

    @Test void malformedEnvelopeAndNonLogoutNeverProduceFixtureReply() {
        var f=fixture();prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
        var url=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","fail").toString();
        for(var fault:List.of("two-bodies","two-messages","non-logout","bare")) {
            var raw=new String(request(f,url,f.plan.target().entityId()),StandardCharsets.UTF_8);
            var invalid=switch(fault){case "two-bodies"->raw.replace("</S:Envelope>","<S:Body/></S:Envelope>");
                case "two-messages"->raw.replace("</S:Body>","<samlp:LogoutRequest xmlns:samlp='"+P+"'/></S:Body>");
                case "non-logout"->raw.replace("LogoutRequest","AuthnRequest");default->"<samlp:LogoutRequest xmlns:samlp='"+P+"'/>";};
            assertThrows(SamlException.class,()->f.service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,invalid.getBytes(StandardCharsets.UTF_8),Map.of(),url));
            assertTrue(f.recorder.list(f.run).stream().noneMatch(e->"LogoutResponse".equals(e.samlSummary().get("type"))));
        }
    }

    @Test void unmarkedSoapKeepsExistingPrimarySuccessBehavior() {
        var f=fixture();var url="https://suite.example/p/"+f.plan.id()+"/sp/slo/soap?run="+f.run;
        var result=f.service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,request(f,url,f.plan.target().entityId()),Map.of(),url);
        var root=SecureXml.parse(result.response().xml()).getDocumentElement();
        assertEquals("https://suite.example/p/"+f.plan.id(),root.getElementsByTagNameNS(A,"Issuer").item(0).getTextContent());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success",((Element)root.getElementsByTagNameNS(P,"StatusCode").item(0)).getAttribute("Value"));
        assertEquals(2,f.recorder.list(f.run).size());assertTrue(result.summary().isEmpty());
    }

    @Test void duplicateRequestParticipantAndReturnCannotCreateAnotherFirstErrorAfterServiceRecreation() {
        var f=fixture();prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
        var first=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","remain2").toString();
        var result=consume(f,f.service,first,"_first");f.service.soapResponse(result);
        var restarted=restarted(f);var next=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","fail").toString();
        int before=f.recorder.list(f.run).size();
        assertThrows(SamlException.class,()->consume(f,restarted,next,"_first"));
        assertThrows(SamlException.class,()->consume(f,restarted,first,"_retry_new_id"));
        assertThrows(SamlException.class,()->restarted.soapResponse(result));
        assertEquals(before,f.recorder.list(f.run).size());
        var response=message(restarted.soapResponse(consume(f,restarted,next,"_next")));
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Success",status(response));
        prepare(f,"all-success",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"all-success",f.at),Map.of());
        var foreignTrial=f.saml.sloPropagationEndpoint(f.plan,f.run,"all-success","remain2").toString();
        assertThrows(SamlException.class,()->consume(f,restarted,foreignTrial,"_first"));
    }

    @Test void unsignedWrongKeyAndChangedSignedContentNeverConsumeFirstClaim() {
        var f=fixture();prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
        var url=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","remain").toString();
        var unsigned=request(f,url,f.plan.target().entityId(),"_unsigned",null);
        var wrongKey=request(f,url,f.plan.target().entityId(),"_wrong",f.keys.getOrCreate(f.plan.id()));
        var altered=new String(request(f,url,f.plan.target().entityId(),"_altered",f.target),StandardCharsets.UTF_8)
                .replace("public-test","changed-public-test").getBytes(StandardCharsets.UTF_8);
        for(var raw:List.of(unsigned,wrongKey,altered))
            assertThrows(SamlException.class,()->f.service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,raw,Map.of(),url));
        assertEquals(2,f.recorder.list(f.run).size());
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder",status(message(f.service.soapResponse(consume(f,f.service,url,"_valid")))));
    }

    @Test void missingDuplicateOrForeignTrialOriginCannotClaimFirstArrival() {
        for(var fault:List.of("missing","duplicate","foreign-trial")) {
            var f=fixture();var raw=f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at);
            var fields=Map.<String,Object>of("type","MetadataPrepared","variant",SloPropagationFixtures.variant("failure"),"case_id",SloPropagationFixtures.CASE,
                    "run_id",f.run,"plan_id",f.plan.id(),"prepared_at",f.at.toString());
            f.recorder.record(new TranscriptInput(f.run,Direction.OUTBOUND,f.at,null,"CONFIGURATION","https://suite.example/metadata",null,Map.of(),raw,"application/samlmetadata+xml",null,raw,fields));
            if("duplicate".equals(fault)){origin(f,"failure");origin(f,"failure");}
            if("foreign-trial".equals(fault))origin(f,"all-success");
            var url=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","fail").toString();var before=f.recorder.list(f.run).size();
            assertThrows(SamlException.class,()->consume(f,f.service,url,"_valid"),fault);
            assertEquals(before,f.recorder.list(f.run).size());
        }
    }

    @Test void firstSelectionIsScopedToPreparedRunAndTrialAndAllSuccessNeverSelectsError() {
        var first=fixture();var second=fixture();
        for(var f:List.of(first,second))for(var trial:List.of("failure","all-success")) {
            prepare(f,trial,f.saml.prepareSloPropagationMetadata(f.plan,f.run,trial,f.at),Map.of());
            var url=f.saml.sloPropagationEndpoint(f.plan,f.run,trial,"remain2").toString();
            var response=message(f.service.soapResponse(consume(f,f.service,url,"_"+trial)));
            assertEquals("urn:oasis:names:tc:SAML:2.0:status:"+("failure".equals(trial)?"Responder":"Success"),status(response));
        }
    }

    @Test void parallelArrivalsCannotInventSequentialFirstErrorContinuation() throws Exception {
        var barrier=new java.util.concurrent.CountDownLatch(2);var at=Instant.parse("2026-10-03T00:00:00Z");
        var clock=new Clock(){public java.time.ZoneId getZone(){return ZoneOffset.UTC;}public Clock withZone(java.time.ZoneId z){return this;}
            public Instant instant(){barrier.countDown();try{if(!barrier.await(10,java.util.concurrent.TimeUnit.SECONDS))throw new IllegalStateException("Arrival barrier timed out");}
                catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}return at;}};
        var f=fixture(clock);prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
        try(var threads=java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var tasks=new ArrayList<java.util.concurrent.Future<Object>>();
            for(var participant:List.of("remain2","fail")) {
                var url=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure",participant).toString();
                tasks.add(threads.submit(()->{try{return consume(f,f.service,url,"_"+participant);}catch(SamlException rejected){return rejected;}}));
            }
            var results=new ArrayList<Object>();for(var task:tasks)results.add(task.get(20,java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(1,results.stream().filter(SloPeerService.Result.class::isInstance).count());
            assertEquals(1,results.stream().filter(SamlException.class::isInstance).count());
            var selected=(SloPeerService.Result)results.stream().filter(SloPeerService.Result.class::isInstance).findFirst().orElseThrow();
            assertEquals("urn:oasis:names:tc:SAML:2.0:status:Responder",status(message(f.service.soapResponse(selected))));
            var arrivals=f.recorder.list(f.run).stream().filter(e->e.direction()==Direction.INBOUND).toList();
            assertEquals(1,arrivals.size());assertEquals(at,arrivals.getFirst().timestamp());
        }
    }

    @Test void modeMismatchAndOldMarkerNeverBorrowCurrentPreparation() {
        var f=fixture();prepare(f,"failure",f.saml.prepareSloPropagationMetadata(f.plan,f.run,"failure",f.at),Map.of());
        var original=f.saml.sloPropagationEndpoint(f.plan,f.run,"failure","remain2").toString();
        for(var url:List.of(original.replace("first-arrival","all-success"),original.replace("error-v2","error-v1"),original.replace("&mode=first-arrival","")))
            assertThrows(SamlException.class,()->consume(f,f.service,url,"_bad_mode"));
        assertEquals(2,f.recorder.list(f.run).size());
    }

    private String status(Element response){return ((Element)response.getElementsByTagNameNS(P,"StatusCode").item(0)).getAttribute("Value");}
    private SloPeerService.Result consume(F f,SloPeerService service,String url,String id) {
        return service.consume(f.plan.id(),SloPeerService.Transport.SOAP,"POST",null,request(f,url,f.plan.target().entityId(),id,f.target),Map.of(),url);
    }

    private void prepare(F f,String trial,byte[] raw,Map<String,Object> changes) {
        var fields=new LinkedHashMap<String,Object>();fields.put("type","MetadataPrepared");fields.put("variant",SloPropagationFixtures.variant(trial));
        fields.put("case_id",SloPropagationFixtures.CASE);fields.put("run_id",f.run);fields.put("plan_id",f.plan.id());fields.put("prepared_at",f.at.toString());fields.putAll(changes);
        f.recorder.record(new TranscriptInput(f.run,Direction.OUTBOUND,f.at,null,"CONFIGURATION","https://suite.example/p/"+f.plan.id()+"/metadata",null,Map.of(),raw,"application/samlmetadata+xml",null,raw,fields));
        if(f.recorder.list(f.run).stream().noneMatch(e->originAction(f,trial).equals(e.correlationId()))) origin(f,trial);
    }
    private String originAction(F f,String trial) { return com.samlscope.core.caseexec.ActionIds.derive(f.run,SloPropagationFixtures.CASE,"slo-basic-v6-soap-propagation-"+trial+"-logout",0); }
    private void origin(F f,String trial) {
        var action=originAction(f,trial);
        f.recorder.record(new TranscriptInput(f.run,Direction.OUTBOUND,f.at,action,"POST","https://idp.example/slo/soap",null,Map.of(),new byte[0],"text/xml",null,new byte[0],
                Map.of("type","LogoutRequest","action_id",action,"probe_transport","direct-soap")));
    }
    private String requestId(String url) { return "_request_"+Integer.toHexString(url.hashCode()); }
    private byte[] request(F f,String url,String issuer) { return request(f,url,issuer,requestId(url),f.target); }
    private byte[] request(F f,String url,String issuer,String id,PlanCredentials credentials) {
        var xml=SecureXml.parse(("<samlp:LogoutRequest xmlns:samlp='"+P+"' xmlns:saml='"+A+"' ID='"+id+"' Version='2.0' IssueInstant='2026-10-03T00:00:00Z' Destination='"+url.replace("&","&amp;")+"'><saml:Issuer>"+issuer+"</saml:Issuer><saml:NameID>public-test</saml:NameID><samlp:SessionIndex>_session</samlp:SessionIndex></samlp:LogoutRequest>").getBytes(StandardCharsets.UTF_8));
        if(credentials!=null)new XmlSigner().sign(xml.getDocumentElement(),credentials,(Element)xml.getDocumentElement().getFirstChild());
        var envelope=SecureXml.parse(("<S:Envelope xmlns:S='http://schemas.xmlsoap.org/soap/envelope/'><S:Body/></S:Envelope>").getBytes(StandardCharsets.UTF_8));
        envelope.getDocumentElement().getFirstChild().appendChild(envelope.importNode(xml.getDocumentElement(),true));
        return SecureXml.serialize(envelope);
    }
    private Element message(byte[] envelope){return (Element)SecureXml.parse(envelope).getElementsByTagNameNS(P,"LogoutResponse").item(0);}
    private F fixture() { return fixture(Clock.fixed(Instant.parse("2026-10-03T00:00:00Z"),ZoneOffset.UTC)); }
    private F fixture(Clock serviceClock) {
        var at=Instant.parse("2026-10-03T00:00:00Z");var clock=Clock.fixed(at,ZoneOffset.UTC);var db=new SqliteDatabase(directory);var json=new JsonCodec();
        var plans=new SqlitePlanRepository(db,json);var runs=new SqliteRunRepository(db,json);
        var plan=new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS","propagation",FunctionalProfile.SINGLE_LOGOUT_IDP,
                new TestPlan.Target(TargetKind.IDP,"https://idp.example/entity",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),at,at);plans.save(plan);
        var run=new RunService(plans,runs,new RunEventBus(),clock).create(plan.id());var keys=new FilePlanKeyStore(directory,clock);
        var target=keys.getOrCreate(plan.id(),"control");
        var cache=new MetadataCache(directory);cache.put(plan.id(),("<md:EntityDescriptor xmlns:md='"+MetadataService.MD+"' entityID='https://idp.example/entity'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo xmlns:ds='"+MetadataService.DS+"'><ds:X509Data><ds:X509Certificate>"+certificate(target)+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding='"+MetadataService.SOAP+"' Location='https://idp.example/slo/soap'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8));
        var recorder=new FileTranscriptRecorder(db,json,directory);var saml=new SamlProtocolService(URI.create("https://suite.example"),keys,new XmlSigner(),new OpenSamlReader(),clock);
        var service=new SloPeerService(plans,runs,cache,new TargetMetadataParser(),saml,recorder,serviceClock);
        return new F(plan,run.id(),at,keys,target,saml,recorder,service,plans,runs,cache,serviceClock);
    }
    private String certificate(PlanCredentials credentials) { try {return Base64.getEncoder().encodeToString(credentials.certificate().getEncoded());}catch(Exception invalid){throw new IllegalStateException(invalid);} }
    private SloPeerService restarted(F f) {return new SloPeerService(f.plans,f.runs,f.cache,new TargetMetadataParser(),f.saml,f.recorder,f.serviceClock);}
    private record F(TestPlan plan,String run,Instant at,FilePlanKeyStore keys,PlanCredentials target,SamlProtocolService saml,FileTranscriptRecorder recorder,SloPeerService service,PlanRepository plans,com.samlscope.core.run.RunRepository runs,MetadataCache cache,Clock serviceClock){}
}
