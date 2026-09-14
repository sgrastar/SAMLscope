package com.samlscope.peer.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import com.samlscope.runner.ActiveProbeCorrelation;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.evaluation.EvidenceRef;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunStatus;
import com.samlscope.runner.RunEventBus;
import com.samlscope.runner.RunService;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class SloPeerServiceTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void recordsPostRequestAndBuildsACorrelatedSignedLogoutResponse() {
        var fixture = fixture();
        var body = "SAMLRequest=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(logoutRequest()), StandardCharsets.UTF_8);
        var result = fixture.service.consume(
                fixture.plan.id(), SloPeerService.Transport.FRONT_CHANNEL, "POST", null,
                body.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://suite.example/p/" + fixture.plan.id() + "/sp/slo?run=" + fixture.runId);

        assertEquals("LogoutRequest", result.messageType());
        assertEquals(MetadataService.POST, result.responseBinding());
        var response = SecureXml.parse(result.response().xml()).getDocumentElement();
        assertEquals("LogoutResponse", response.getLocalName());
        assertEquals("_logout", response.getAttribute("InResponseTo"));
        assertEquals(2, fixture.recorder.list(fixture.runId).size());
    }

    @Test
    void preservesSoapTransportAndReturnsASoapEnvelope() {
        var fixture = fixture();
        var request = """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">
                  <S:Body>%s</S:Body>
                </S:Envelope>
                """.formatted(new String(logoutRequest(), StandardCharsets.UTF_8));
        var result = fixture.service.consume(
                fixture.plan.id(), SloPeerService.Transport.SOAP, "POST", null,
                request.getBytes(StandardCharsets.UTF_8), Map.of(),
                "https://suite.example/p/" + fixture.plan.id() + "/sp/slo/soap?run=" + fixture.runId);

        assertEquals(MetadataService.SOAP, result.responseBinding());
        var envelope = SecureXml.parse(fixture.service.soapResponse(result));
        assertEquals("Envelope", envelope.getDocumentElement().getLocalName());
        assertTrue(envelope.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "LogoutResponse").getLength() == 1);
    }

    @Test void soapScopeMatrixRejectsAmbiguousMessagesAndKeepsRawEvidence() {
        var fixture=fixture();
        var request=new String(logoutRequest(),StandardCharsets.UTF_8);
        var response=request.replace("LogoutRequest","LogoutResponse").replace("<saml:NameID>user</saml:NameID>",
                "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status>");
        for(var prefix:List.of("S","soap"))for(var message:List.of(request,response))
        for(var fault:List.of("header-only","two-bodies","two-messages","wrapper","wrong-body-namespace","nested-body",
                "wrong-envelope-namespace","bare-message","unknown-child","empty-body","wrong-message-namespace","soap12")) {
            var start="<"+prefix+":Envelope xmlns:"+prefix+"='http://schemas.xmlsoap.org/soap/envelope/'>";
            var body="<"+prefix+":Body>"+message+"</"+prefix+":Body>";
            var end="</"+prefix+":Envelope>";
            var xml=switch(fault) {
                case "header-only" -> start+"<"+prefix+":Header>"+message+"</"+prefix+":Header>"+end;
                case "two-bodies" -> start+body+body+end;
                case "two-messages" -> start+"<"+prefix+":Body>"+message+message+"</"+prefix+":Body>"+end;
                case "wrapper" -> start+"<"+prefix+":Body><wrapper>"+message+"</wrapper></"+prefix+":Body>"+end;
                case "wrong-body-namespace" -> start+"<x:Body xmlns:x='urn:other'>"+message+"</x:Body>"+end;
                case "nested-body" -> start+"<wrapper>"+body+"</wrapper>"+end;
                case "wrong-envelope-namespace" -> (start+body+end).replace("http://schemas.xmlsoap.org/soap/envelope/","urn:wrong");
                case "bare-message" -> message;
                case "unknown-child" -> start+"<"+prefix+":Body>"+message+"<other/></"+prefix+":Body>"+end;
                case "empty-body" -> start+"<"+prefix+":Body/>"+end;
                case "wrong-message-namespace" -> (start+body+end).replace("urn:oasis:names:tc:SAML:2.0:protocol","urn:wrong");
                default -> (start+body+end).replace("http://schemas.xmlsoap.org/soap/envelope/","http://www.w3.org/2003/05/soap-envelope");
            };
            var before=fixture.inputs.size();var bytes=xml.getBytes(StandardCharsets.UTF_8);
            assertThrows(com.samlscope.saml.normal.SamlException.class,()->fixture.service.consume(fixture.plan.id(),
                    SloPeerService.Transport.SOAP,"POST",null,bytes,Map.of("Authorization",List.of("secret"),"Cookie",List.of("secret")),
                    "https://suite.example/slo?run="+fixture.runId),fault);
            assertEquals(before+1,fixture.inputs.size());var recorded=fixture.inputs.getLast();
            assertEquals(com.samlscope.core.transcript.Direction.INBOUND,recorded.direction());
            assertArrayEquals(bytes,recorded.decodedSaml());
            assertTrue(recorded.headers().isEmpty());
            assertEquals("invalid-soap-message-scope",recorded.samlSummary().get("parseStatus"));
            assertTrue(fixture.calls.isEmpty());
        }
    }

    @Test void validSoapBodyWinsOverHeaderDecoysAndPreservesRawEnvelope() {
        var fixture=fixture();var request=new String(logoutRequest(),StandardCharsets.UTF_8);
        for(var prefix:List.of("S","soap"))for(var header:List.of("",request.replace("_logout","_header"))) {
            var xml="<"+prefix+":Envelope xmlns:"+prefix+"='http://schemas.xmlsoap.org/soap/envelope/'><"+prefix+":Header>"+header
                    +"</"+prefix+":Header><"+prefix+":Body><!-- comment -->"+request+"</"+prefix+":Body></"+prefix+":Envelope>";
            var bytes=xml.getBytes(StandardCharsets.UTF_8);var before=fixture.inputs.size();
            var result=fixture.service.consume(fixture.plan.id(),SloPeerService.Transport.SOAP,"POST",null,bytes,Map.of(),
                    "https://suite.example/slo?run="+fixture.runId);
            assertEquals("_logout",SecureXml.parse(result.response().xml()).getDocumentElement().getAttribute("InResponseTo"));
            assertArrayEquals(bytes,fixture.inputs.get(before).decodedSaml());
        }
    }

    @Test void activeResponsesAreRecordedBeforeDispatchIncludingMalformedAndMismatchedMessages() {
        var fixture = fixture();
        var action = "action_slo";
        var relay = ActiveProbeCorrelation.encode(fixture.runId, action);
        var normal = logoutResponse("_"+action, "Success");
        var samples = List.of(normal, logoutResponse("_"+action, "Responder"),
                logoutResponse("_other", "Success"), normal.replace("InResponseTo='_"+action+"'", ""),
                new String(logoutRequest(),StandardCharsets.UTF_8), normal.replace("LogoutResponse", "Response"),
                "<samlp:LogoutResponse", normal.replace("urn:oasis:names:tc:SAML:2.0:protocol", "urn:wrong"),
                normal.replace("<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status>", ""));
        for (var method : List.of("POST", "GET")) {
            for (var queryRun : List.of(false, true)) {
                for (int i=0;i<samples.size();i++) {
                    var xml = samples.get(i).getBytes(StandardCharsets.UTF_8);
                    var form = encoded(method, xml, relay);
                    var url = "https://suite.example/p/"+fixture.plan.id()+"/sp/slo"+(queryRun ? "?run="+fixture.runId : "");
                    var result = fixture.service.consume(fixture.plan.id(), SloPeerService.Transport.FRONT_CHANNEL,
                            method, method.equals("GET") ? form : null,
                            method.equals("POST") ? form.getBytes(StandardCharsets.UTF_8) : new byte[0],
                            Map.of("aUtHoRiZaTiOn",List.of("Bearer secret"),"COOKIE",List.of("session=secret"),"X-Test",List.of("keep")),url);
                    assertTrue(result.activeProbe()); assertEquals(action,result.activeProbeActionId());
                    assertNull(result.response());
                    var call = fixture.calls.getLast();
                    assertEquals(fixture.runId,call.runId()); assertEquals(action,call.actionId()); assertArrayEquals(xml,call.xml());
                    assertEquals(result.summary(),call.recordedSummary());
                    if (i==0 || i==1 || i==8) assertEquals(true,result.summary().get("activeProbeAccepted"));
                    else assertNotEquals(true,result.summary().get("activeProbeAccepted"));
                    var input = fixture.inputs.getLast();
                    assertFalse(input.headers().keySet().stream().anyMatch(k -> k.equalsIgnoreCase("Authorization") || k.equalsIgnoreCase("Cookie")));
                    assertEquals(List.of("keep"),input.headers().get("X-Test"));
                    var entry = fixture.recorder.list(fixture.runId).stream().filter(e -> e.id().equals(call.evidence().reference())).findFirst().orElseThrow();
                    assertEquals(call.evidence().reference(),entry.id());
                    assertEquals(method.equals("GET") ? form : null,entry.rawQuery());
                }
            }
        }
        assertEquals(36,fixture.calls.size());
    }

    @Test void rejectsAmbiguousOrUnrelatedRunAndPlanCorrelationBeforeRecordingOrDispatch() {
        var fixture = fixture(); var valid = ActiveProbeCorrelation.encode(fixture.runId,"action_slo");
        var unknown = ActiveProbeCorrelation.encode("run_unknown","action_slo");
        for (var method : List.of("POST","GET")) {
            for (var scenario : List.of("query-conflict","duplicate-run","unknown-run","unknown-plan",
                    "invalid-relay","missing-relay","empty-run","duplicate-encoded-run")) {
                var relay = switch (scenario) { case "unknown-run" -> unknown; case "invalid-relay" -> "sp1:broken"; case "missing-relay" -> ""; default -> valid; };
                var suffix = switch(scenario) {
                    case "query-conflict" -> "?run=run_other";
                    case "duplicate-run" -> "?run="+fixture.runId+"&run="+fixture.runId;
                    case "duplicate-encoded-run" -> "?run="+fixture.runId+"&%72un="+fixture.runId;
                    case "empty-run" -> "?run=";
                    default -> "";
                };
                var form=encoded(method,logoutResponse("_action_slo","Success").getBytes(StandardCharsets.UTF_8),relay);
                assertThrows(RuntimeException.class,()->fixture.service.consume(
                        scenario.equals("unknown-plan") ? "plan_other" : fixture.plan.id(),SloPeerService.Transport.FRONT_CHANNEL,
                        method,method.equals("GET")?form:null,method.equals("POST")?form.getBytes(StandardCharsets.UTF_8):new byte[0],Map.of(),
                        "https://suite.example/sp/slo"+suffix),scenario);
                assertEquals(0,fixture.calls.size()); assertEquals(0,fixture.inputs.size());
            }
        }
    }

    private String logoutResponse(String correlation,String status) {
        return "<samlp:LogoutResponse xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_response' Version='2.0' "
                +"IssueInstant='2026-08-29T00:00:00Z' InResponseTo='"+correlation+"'><samlp:Status><samlp:StatusCode Value='"
                +"urn:oasis:names:tc:SAML:2.0:status:"+status+"'/></samlp:Status></samlp:LogoutResponse>";
    }
    private String encoded(String method,byte[] xml,String relay) {
        byte[] bytes=xml;
        if (method.equals("GET")) {
            var deflater=new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION,true);
            deflater.setInput(xml);deflater.finish();var buffer=new byte[xml.length+100];int length=deflater.deflate(buffer);deflater.end();
            bytes=java.util.Arrays.copyOf(buffer,length);
        }
        return "SAMLResponse="+URLEncoder.encode(Base64.getEncoder().encodeToString(bytes),StandardCharsets.UTF_8)
                +"&RelayState="+URLEncoder.encode(relay,StandardCharsets.UTF_8);
    }

    private Fixture fixture() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var clock = Clock.fixed(now, ZoneOffset.UTC);
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plans = new SqlitePlanRepository(database, json);
        var runs = new SqliteRunRepository(database, json);
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "IdP target", FunctionalProfile.SINGLE_LOGOUT_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.HTTP_URL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        plans.save(plan);
        var runService = new RunService(plans, runs, new RunEventBus(), clock);
        var run = runService.create(plan.id());
        runService.update(run, RunStatus.COMPLETED, run.targetToSuiteReachability(), Map.of());
        var cache = new MetadataCache(directory);
        cache.put(plan.id(), targetMetadata());
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var calls = new ArrayList<Call>();
        var inputs = new ArrayList<TranscriptInput>();
        TranscriptRecorder observed = new TranscriptRecorder() {
            public TranscriptEntry record(TranscriptInput input) { inputs.add(input); return recorder.record(input); }
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) {
                return recorder.updateSamlAnalysis(id,correlation,summary);
            }
            public List<TranscriptEntry> list(String run) { return recorder.list(run); }
        };
        var service = new SloPeerService(
                plans, runs, cache, new TargetMetadataParser(),
                new SamlProtocolService(URI.create("https://suite.example"),
                        new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock),
                observed, clock,(runId,action,xml,evidence)-> {
                    var recorded=recorder.list(runId).stream().filter(e->e.id().equals(evidence.reference())).findFirst().orElseThrow();
                    calls.add(new Call(runId,action,xml,evidence,recorded.samlSummary()));
                });
        return new Fixture(plan, run.id(), service, recorder,calls,inputs);
    }

    private byte[] targetMetadata() {
        return """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://idp.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://idp.example/slo/post"/>
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
                        Location="https://idp.example/slo/soap"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] logoutRequest() {
        return """
                <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="_logout" Version="2.0" IssueInstant="2026-08-29T00:00:00Z">
                  <saml:Issuer>https://idp.example/entity</saml:Issuer>
                  <saml:NameID>user</saml:NameID>
                </samlp:LogoutRequest>
                """.getBytes(StandardCharsets.UTF_8);
    }

    private record Fixture(
            TestPlan plan, String runId, SloPeerService service, FileTranscriptRecorder recorder,
            List<Call> calls,List<TranscriptInput> inputs) {}
    private record Call(String runId,String actionId,byte[] xml,EvidenceRef evidence,Map<String,Object> recordedSummary) {}
}
