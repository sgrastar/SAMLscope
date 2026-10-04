package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the core with real signed XML; product-specific rejection is an explicit test seam. */
class SloRegisteredSignerEvidenceTest {
    @TempDir Path directory;
    private static final String RUN="run_00000000000000000000000000",OTHER="run_11111111111111111111111111",PLAN="plan_00000000000000000000000000",OTHER_PLAN="plan_11111111111111111111111111";
    private static final String ENTITY="https://suite.example/p/"+PLAN,OTHER_ENTITY="https://suite.example/p/"+OTHER_PLAN,TARGET="https://idp.example",ACS=ENTITY+"/sp/acs",SLO=ENTITY+"/sp/slo";
    private static final Instant NOW=Instant.parse("2026-10-03T13:00:00Z");
    private final Map<String,byte[]> decoded=new HashMap<>();private final List<TranscriptEntry> entries=new ArrayList<>();private final JsonCodec json=new JsonCodec();
    private Path folder;private ObjectNode manifest;private byte[] metadata;private PlanCredentials own,other,target;private boolean acceptOtherSigner;
    @Test void completeSignedSameSessionRequestProofUsesOptionalResponseNote()throws Exception{
        setup();var outcome=reader().evaluate(context()).orElseThrow();assertEquals(Outcome.SATISFIED_WITH_NOTE,outcome.outcome());assertTrue(outcome.evidence().stream().anyMatch(e->e.kind().equals(SloRegisteredSignerEvidence.KIND)));
    }
    @Test void realPreparedSessionCreatesInvalidControlFirstWithoutExtraAuthentication()throws Exception{
        setup();assertTrue(reader().probeInputs(context()).isPresent());Files.delete(folder.resolve("manifest.json"));
        var legacy=new TestFallback();var wrapper=new SloRegisteredSignerObservationTestCase(legacy,directory,e->decoded.get(e.id()),r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),adapter());
        var first=assertInstanceOf(CaseStep.AwaitInbound.class,wrapper.start(context()));assertEquals("await-fixture-local-invalid-signature",first.next().phase());assertEquals(1,first.actions().size());assertEquals(OutboundKind.LOGOUT_REQUEST,first.actions().getFirst().kind());
        assertFalse(wrapper.requiresFreshSession(first.next()));assertEquals(true,first.next().data().get("normal_control_ends_session"));
        var execution=new CaseExecution(RUN,SloRegisteredSignerEvidence.CASE,1,CaseExecutionStatus.WAITING_INBOUND,first.next(),new WaitCondition(WaitCondition.Kind.INBOUND,null,null,first.matcher(),NOW.plusSeconds(600)),null,NOW);
        assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.LOGIN,wrapper.evidenceActionKind(execution));
    }
    @Test void actualPreparedSignedRedirectAndPostBindingsBothProveTheSameSession()throws Exception{
        setup();assertTrue(reader().probeInputs(context()).isPresent());
        var encoded=new com.samlscope.saml.binding.SignedRedirectEncoder().encode(URI.create(TARGET+"/sso"),decoded.get("tx_baseline_request"),RUN,own);
        redirectBaseline(encoded.rawQuery(),encoded.destination().toString(),encoded.decodedXml());
        assertTrue(reader().probeInputs(context()).isPresent());assertEquals(Outcome.SATISFIED_WITH_NOTE,reader().evaluate(context()).orElseThrow().outcome());
        var targetRoot=SecureXml.parse(metadata).getDocumentElement();
        assertTrue(SloRegisteredSignerEvidence.baselineAdvertised(targetRoot,"GET",TARGET+"/sso"));
        assertTrue(SloRegisteredSignerEvidence.baselineAdvertised(targetRoot,"POST",TARGET+"/sso"));
        assertFalse(SloRegisteredSignerEvidence.baselineAdvertised(targetRoot,"GET",TARGET+"/foreign"));
    }
    @Test void preparedRedirectRequiresOriginalQueryActualPeerAndExactDecodedMessage()throws Exception{
        setup();byte[] source=decoded.get("tx_baseline_request");var encoder=new com.samlscope.saml.binding.SignedRedirectEncoder();var encoded=encoder.encode(URI.create(TARGET+"/sso"),source,RUN,own);
        String changed=encoded.rawQuery().replace("RelayState="+RUN,"RelayState=foreign");redirectBaseline(changed,TARGET+"/sso?"+changed,encoded.decodedXml());assertTrue(reader().probeInputs(context()).isEmpty());
        var wrongPeer=encoder.encode(URI.create(TARGET+"/sso"),source,RUN,other);redirectBaseline(wrongPeer.rawQuery(),wrongPeer.destination().toString(),wrongPeer.decodedXml());assertTrue(reader().probeInputs(context()).isEmpty());
        redirectBaseline(encoded.rawQuery(),encoded.destination().toString(),source);assertTrue(reader().probeInputs(context()).isEmpty());
        redirectBaseline(encoded.rawQuery(),TARGET+"/foreign?"+encoded.rawQuery(),encoded.decodedXml());assertTrue(reader().probeInputs(context()).isEmpty());
    }
    private void redirectBaseline(String rawQuery,String url,byte[] raw){
        var e=entries.getFirst();entries.set(0,new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),"GET",url,e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),rawQuery,e.samlSummary()));decoded.put(e.id(),raw);
    }
    @Test void normalSignedRedirectResponseUsesItsOriginalFullUrlAndQuery()throws Exception{
        setup();var encoded=new com.samlscope.saml.binding.SignedRedirectEncoder().encode(URI.create(SLO),decoded.get("tx_logout_response"),RUN,target);
        redirectResponse(encoded.rawQuery(),encoded.destination().toString(),encoded.decodedXml());
        assertEquals(Outcome.SATISFIED_WITH_NOTE,reader().evaluate(context()).orElseThrow().outcome());
        assertEquals("https://suite.example/sp%20name/slo",SloRegisteredSignerEvidence.responseEndpoint("https://suite.example/sp%20name/slo?"+encoded.rawQuery(),encoded.rawQuery(),"GET","https://suite.example/sp%20name/slo"));
    }
    @Test void registeredFixedQueryIsBoundBeforeTheUnchangedSignedResponseQuery()throws Exception{
        setup();String endpoint=SLO+"?tenant=x&language=en%20GB";
        var fixture=SecureXml.parse(Files.readAllBytes(folder.resolve("primary/fixture.xml")));((org.w3c.dom.Element)fixture.getDocumentElement().getElementsByTagNameNS(SloRegisteredSignerEvidence.MD,"SingleLogoutService").item(0)).setAttribute("Location",endpoint);
        var prep=(ObjectNode)json.mapper().readTree(Files.readAllBytes(folder.resolve("preparation.json")));var fixtureBytes=SecureXml.serialize(fixture);
        asset(prep,"primary/fixture.xml",fixtureBytes);asset(manifest,"primary/fixture.xml",fixtureBytes);asset(manifest,"preparation.json",json.mapper().writeValueAsBytes(prep));save("manifest.json",json.mapper().writeValueAsBytes(manifest));
        var reply=SecureXml.parse(decoded.get("tx_logout_response"));reply.getDocumentElement().setAttribute("Destination",endpoint);
        var encoded=new com.samlscope.saml.binding.SignedRedirectEncoder().encode(URI.create(endpoint),SecureXml.serialize(reply),RUN,target);
        redirectResponse(encoded.rawQuery(),encoded.destination().toString(),encoded.decodedXml());assertEquals(Outcome.SATISFIED_WITH_NOTE,reader().evaluate(context()).orElseThrow().outcome());
        String foreign=encoded.rawQuery().replace("tenant=x&","tenant=other&");redirectResponse(foreign,SLO+"?"+foreign,encoded.decodedXml());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        redirectResponse(encoded.rawQuery(),encoded.destination().toString(),encoded.decodedXml());assertEquals(Outcome.SATISFIED_WITH_NOTE,reader().evaluate(context()).orElseThrow().outcome());
    }
    @Test void redirectResponseCannotBorrowAQueryKeyEndpointOrDecodedMessage()throws Exception{
        setup();byte[] raw=decoded.get("tx_logout_response");var encoder=new com.samlscope.saml.binding.SignedRedirectEncoder();var valid=encoder.encode(URI.create(SLO),raw,RUN,target);
        redirectResponse(valid.rawQuery(),SLO,valid.decodedXml());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        redirectResponse(valid.rawQuery(),valid.destination()+"&foreign=1",valid.decodedXml());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        var wrong=encoder.encode(URI.create(SLO),raw,RUN,other);redirectResponse(wrong.rawQuery(),wrong.destination().toString(),wrong.decodedXml());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        redirectResponse(valid.rawQuery(),valid.destination().toString(),raw);assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        redirectResponse(valid.rawQuery(),"https://foreign.example/slo?"+valid.rawQuery(),valid.decodedXml());assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
    }
    private void redirectResponse(String rawQuery,String url,byte[] raw){
        var e=entries.getLast();entries.set(entries.size()-1,new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),"GET",url,e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),rawQuery,e.samlSummary()));decoded.put(e.id(),raw);
    }
    @Test void diagnosticPreparationCannotQueueOutboxActions()throws Exception{
        setup();Files.delete(folder.resolve("manifest.json"));var prep=(ObjectNode)json.mapper().readTree(Files.readAllBytes(folder.resolve("preparation.json")));prep.put("counterfactualCalibrationOnly",true);save("preparation.json",json.mapper().writeValueAsBytes(prep));assertTrue(reader().probeInputs(context()).isEmpty());
    }
    @Test void foreignRequestReferenceDuplicateActionOrAlteredSessionCannotCreateSuccess()throws Exception{
        setup();var request=entries.get(2);entries.add(new TranscriptEntry("tx_duplicate",RUN,request.direction(),request.timestamp(),request.correlationId(),request.method(),request.url(),request.status(),request.headers(),request.bodyRef(),request.bodyBytes(),"transcripts/"+RUN+"/tx_duplicate.saml.xml",request.decodedSamlBytes(),request.contentType(),request.rawQuery(),request.samlSummary()));decoded.put("tx_duplicate",decoded.get(request.id()));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        entries.removeLast();var raw=decoded.get(request.id());decoded.put(request.id(),new String(raw,StandardCharsets.UTF_8).replace("session-index","foreign-index").getBytes(StandardCharsets.UTF_8));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
    }
    @Test void wrongResponseCorrelationAndDeveloperMarkerNeverAdopt()throws Exception{
        setup();var response=entries.getLast();var raw=decoded.get(response.id());decoded.put(response.id(),new String(raw,StandardCharsets.UTF_8).replace("InResponseTo=\"_", "InResponseTo=\"_foreign").getBytes(StandardCharsets.UTF_8));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
        decoded.put(response.id(),raw);manifest.put("counterfactualCalibrationOnly",true);save("manifest.json",json.mapper().writeValueAsBytes(manifest));assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());
    }
    @Test void wholeReaderCounterexampleRequiresExplicitOfflinePermissionAndBoundSource()throws Exception{
        setup();prepareDiagnosticCounterexample();var content=(TranscriptContentReader)(e->decoded.get(e.id()));
        var offline=new SloRegisteredSignerEvidence(directory,content,r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),true,adapter());
        var actual=offline.evaluate(context()).orElseThrow();assertEquals(Outcome.VIOLATED,actual.outcome());assertEquals(Verdict.WARNING,Evaluator.toVerdict(Rfc2119Level.SHOULD,actual));assertEquals(true,actual.details().get("counterfactual_calibration_only"));assertEquals(false,actual.details().get("actual_product_finding"));
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());assertTrue(offline.probeInputs(context()).isEmpty());
        var wrapper=new SloRegisteredSignerObservationTestCase(new TestFallback(),directory,content,r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),true,adapter());
        assertEquals(new CaseStep.Finish(actual),wrapper.start(context()));
        var publicWrapper=new SloRegisteredSignerObservationTestCase(new TestFallback(),directory,content,r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),adapter());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,publicWrapper.start(context())).outcome().outcome());
        manifest.put("counterfactualCalibrationOnly",false);manifest.put("schema",SloRegisteredSignerEvidence.SCHEMA);save("manifest.json",json.mapper().writeValueAsBytes(manifest));
        assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context()).orElseThrow().outcome());assertEquals(Outcome.NOT_VERIFIED,offline.evaluate(context()).orElseThrow().outcome());
    }
    @Test void offlineCounterexampleWithForeignSourceRunOrAlteredNativeOrderIsNotVerified()throws Exception{
        setup();prepareDiagnosticCounterexample();var offline=new SloRegisteredSignerEvidence(directory,e->decoded.get(e.id()),r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),true,adapter());
        byte[] original=Files.readAllBytes(folder.resolve("calibration/source-manifest.json"));var source=(ObjectNode)json.mapper().readTree(original);source.put("runId",OTHER);asset(manifest,"calibration/source-manifest.json",json.mapper().writeValueAsBytes(source));manifest.withObject("calibrationProvenance").put("sourceManifestSha256",SloRegisteredSignerEvidence.hash(Files.readAllBytes(folder.resolve("calibration/source-manifest.json"))));save("manifest.json",json.mapper().writeValueAsBytes(manifest));assertEquals(Outcome.NOT_VERIFIED,offline.evaluate(context()).orElseThrow().outcome());
        asset(manifest,"calibration/source-manifest.json",original);manifest.withObject("calibrationProvenance").put("sourceManifestSha256",SloRegisteredSignerEvidence.hash(original));save("manifest.json",json.mapper().writeValueAsBytes(manifest));
        var response=entries.stream().filter(e->e.id().equals("tx_calibrated_cross_response")).findFirst().orElseThrow();entries.remove(response);entries.add(new TranscriptEntry(response.id(),response.runId(),response.direction(),NOW,response.correlationId(),response.method(),response.url(),response.status(),response.headers(),response.bodyRef(),response.bodyBytes(),response.decodedSamlRef(),response.decodedSamlBytes(),response.contentType(),response.rawQuery(),response.samlSummary()));assertEquals(Outcome.NOT_VERIFIED,offline.evaluate(context()).orElseThrow().outcome());
    }
    private void prepareDiagnosticCounterexample()throws Exception{
        byte[] originalManifest=Files.readAllBytes(folder.resolve("manifest.json"));var sourceHash=SloRegisteredSignerEvidence.hash(originalManifest);var targetHash=SloRegisteredSignerEvidence.hash(metadata);
        var input=json.mapper().createObjectNode();input.put("schema","samlscope-slo-known-signer-consumer-model-v1");input.put("runId",RUN);input.put("caseId",SloRegisteredSignerEvidence.CASE);input.put("sourceManifestSha256",sourceHash);input.put("sourceTargetMetadataSha256",targetHash);input.put("selectedOperation","accept-known-signer-regardless-of-issuer");input.put("counterfactualCalibrationOnly",true);input.put("actualProductFinding",false);
        var prep=(ObjectNode)json.mapper().readTree(Files.readAllBytes(folder.resolve("preparation.json")));prep.put("schema",SloRegisteredSignerEvidence.CALIBRATION_PREPARATION_SCHEMA);prep.put("counterfactualCalibrationOnly",true);prep.put("actualProductFinding",false);
        var provenance=prep.putObject("calibrationProvenance");provenance.put("model","known-signer-issuer-mismatch-accepted-v1");provenance.put("sourceManifestFile","calibration/source-manifest.json");provenance.put("sourceManifestSha256",sourceHash);provenance.put("sourceTargetMetadataFile","calibration/source-target-metadata.xml");provenance.put("sourceTargetMetadataSha256",targetHash);provenance.put("producerFile","calibration/producer-input.json");byte[] raw=json.mapper().writeValueAsBytes(input);provenance.put("producerSha256",SloRegisteredSignerEvidence.hash(raw));
        for(var m:List.of(prep,manifest)){asset(m,"calibration/source-manifest.json",originalManifest);asset(m,"calibration/source-target-metadata.xml",metadata);asset(m,"calibration/producer-input.json",raw);}
        manifest.put("schema",SloRegisteredSignerEvidence.CALIBRATION_SCHEMA);manifest.put("counterfactualCalibrationOnly",true);manifest.put("actualProductFinding",false);manifest.set("calibrationProvenance",provenance.deepCopy());asset(manifest,"preparation.json",json.mapper().writeValueAsBytes(prep));
        var request=entries.stream().filter(e->e.id().equals("tx_request_1")).findFirst().orElseThrow();var reply=SecureXml.parse(decoded.get("tx_logout_response"));var root=reply.getDocumentElement();for(var signature:com.samlscope.runner.cases.MetadataAlgorithmEvidence.children(root,SloRegisteredSignerEvidence.DS,"Signature"))root.removeChild(signature);root.setAttribute("ID","_calibrated_cross_response");root.setAttribute("InResponseTo","_"+request.correlationId());root.setAttribute("IssueInstant",request.timestamp().plusSeconds(1).toString());entry("tx_calibrated_cross_response",Direction.INBOUND,request.timestamp().plusSeconds(2),request.correlationId(),SLO,signedResponse(SecureXml.serialize(reply)),"LogoutResponse","_"+request.correlationId());
        acceptOtherSigner=true;save("manifest.json",json.mapper().writeValueAsBytes(manifest));
    }
    private void setup()throws Exception{
        directory=directory.toRealPath();
        folder=Files.createDirectories(directory.resolve(RUN));var store=new FilePlanKeyStore(directory.resolve("keys"),Clock.fixed(NOW,ZoneOffset.UTC));own=store.getOrCreate(PLAN);other=store.getOrCreate(OTHER_PLAN);target=store.getOrCreate("plan_22222222222222222222222222");
        metadata=bytes("<md:EntityDescriptor xmlns:md='"+SloRegisteredSignerEvidence.MD+"' xmlns:ds='"+SloRegisteredSignerEvidence.DS+"' entityID='"+TARGET+"'><md:IDPSSODescriptor protocolSupportEnumeration='"+SloRegisteredSignerEvidence.P+"'>"+key(target)+"<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+TARGET+"/sso'/><md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='"+TARGET+"/sso'/><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+TARGET+"/slo'/></md:IDPSSODescriptor></md:EntityDescriptor>");
        var prep=json.mapper().createObjectNode();prep.put("schema","samlscope-slo-registered-signer-preparation-v1");prep.put("caseId",SloRegisteredSignerEvidence.CASE);prep.put("campaignId",SloRegisteredSignerEvidence.CAMPAIGN);prep.put("runId",RUN);prep.put("adapter","test-native-slo");prep.put("targetEntityId",TARGET);prep.put("targetMetadataSha256",SloRegisteredSignerEvidence.hash(metadata));prep.put("counterfactualCalibrationOnly",false);prep.set("files",json.mapper().createObjectNode());
        var peers=prep.putArray("peers");for(int i=0;i<2;i++){String label=i==0?"primary":"secondary",run=i==0?RUN:OTHER,plan=i==0?PLAN:OTHER_PLAN,entity=i==0?ENTITY:OTHER_ENTITY;
            var p=peers.addObject();p.put("label",label);p.put("runId",run);p.put("planId",plan);p.put("entity",entity);
            asset(prep,label+"/created.json",bytes("{\"run\":{\"id\":\""+run+"\",\"planId\":\""+plan+"\"}}"));asset(prep,label+"/fixture.xml",sp(entity,i==0?own:other));}
        asset(prep,"target-metadata.xml",metadata);
        var q=new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.VALID,"_baseline",URI.create(TARGET+"/sso"),ENTITY,URI.create(ACS),NOW,own);entry("tx_baseline_request",Direction.OUTBOUND,NOW,"baseline",TARGET+"/sso",q,"AuthnRequest",null);
        var response=bytes("<p:Response xmlns:p='"+SloRegisteredSignerEvidence.P+"' xmlns:s='"+SloRegisteredSignerEvidence.S+"' ID='_baseline_response' Version='2.0' IssueInstant='"+NOW+"' InResponseTo='_baseline' Destination='"+ACS+"'><s:Issuer>"+TARGET+"</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status><s:Assertion ID='_assertion' Version='2.0' IssueInstant='"+NOW+"'><s:Issuer>"+TARGET+"</s:Issuer><s:Subject><s:NameID>user-session</s:NameID><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><s:SubjectConfirmationData InResponseTo='_baseline' Recipient='"+ACS+"'/></s:SubjectConfirmation></s:Subject><s:Conditions><s:AudienceRestriction><s:Audience>"+ENTITY+"</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement SessionIndex='session-index' AuthnInstant='"+NOW+"'/></s:Assertion></p:Response>");
        entry("tx_baseline_response",Direction.INBOUND,NOW.plusSeconds(1),"baseline",ACS,signedResponse(response),"Response","_baseline");var baseline=prep.putObject("baseline");baseline.put("requestReference","tx_baseline_request");baseline.put("responseReference","tx_baseline_response");
        byte[] prepBytes=json.mapper().writeValueAsBytes(prep);save("preparation.json",prepBytes);manifest=prep.deepCopy();manifest.put("schema",SloRegisteredSignerEvidence.SCHEMA);manifest.put("counterfactualCalibrationOnly",false);manifest.put("optionalResponseConsumerObserved",false);((ObjectNode)manifest.path("files")).put("preparation.json",SloRegisteredSignerEvidence.hash(prepBytes));
        var actualName=(org.w3c.dom.Element)SecureXml.parse(decoded.get("tx_baseline_response")).getDocumentElement().getElementsByTagNameNS(SloRegisteredSignerEvidence.S,"NameID").item(0);
        var input=new SloRegisteredSignerProbeInputs(RUN,OTHER,ENTITY,URI.create(TARGET+"/slo"),URI.create(SLO),SloRegisteredSignerEvidence.isolated(actualName),List.of("session-index"),SloRegisteredSignerEvidence.hash(prepBytes));
        var rows=manifest.putArray("probes");for(int i=0;i<3;i++){String fixture=SloRegisteredSignerComparison.FIXTURES.get(i),action=ActionIds.derive(RUN,SloRegisteredSignerEvidence.CASE,"await-fixture-"+fixture,0),id="_"+action;Instant issue=NOW.plusSeconds(10+i*10);var raw=SloRegisteredSignerFixtures.build(fixture,id,issue,input,own,other);
            var ref="tx_request_"+i;entry(ref,Direction.OUTBOUND,issue,action,TARGET+"/slo",raw,"LogoutRequest",null);var row=rows.addObject();row.put("fixture",fixture);row.put("runId",RUN);row.put("actionId",action);row.put("requestReference",ref);
            if(i==2){var reply=bytes("<p:LogoutResponse xmlns:p='"+SloRegisteredSignerEvidence.P+"' xmlns:s='"+SloRegisteredSignerEvidence.S+"' ID='_logout_response' Version='2.0' IssueInstant='"+issue+"' InResponseTo='"+id+"' Destination='"+SLO+"'><s:Issuer>"+TARGET+"</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:LogoutResponse>");entry("tx_logout_response",Direction.INBOUND,issue.plusSeconds(2),action,SLO,signedResponse(reply),"LogoutResponse",id);}}
        save("manifest.json",json.mapper().writeValueAsBytes(manifest));
    }
    private byte[] signedResponse(byte[] raw){var d=SecureXml.parse(raw);var root=d.getDocumentElement();new XmlSigner().sign(root,target,root.getElementsByTagNameNS(SloRegisteredSignerEvidence.P,"Status").item(0) instanceof org.w3c.dom.Element e?e:null);return SecureXml.serialize(d);}
    private byte[] sp(String entity,PlanCredentials credential)throws Exception{return bytes("<md:EntityDescriptor xmlns:md='"+SloRegisteredSignerEvidence.MD+"' xmlns:ds='"+SloRegisteredSignerEvidence.DS+"' entityID='"+entity+"'><md:SPSSODescriptor protocolSupportEnumeration='"+SloRegisteredSignerEvidence.P+"'>"+key(credential)+"<md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+entity+"/sp/slo'/><md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+entity+"/sp/acs' index='0'/></md:SPSSODescriptor></md:EntityDescriptor>");}
    private static String key(PlanCredentials c)throws Exception{return "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(c.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";}
    private void asset(ObjectNode m,String name,byte[] raw)throws Exception{save(name,raw);((ObjectNode)m.path("files")).put(name,SloRegisteredSignerEvidence.hash(raw));}
    private void save(String name,byte[] raw)throws Exception{var p=folder.resolve(name);Files.createDirectories(p.getParent());Files.write(p,raw);}
    private void entry(String id,Direction direction,Instant at,String action,String url,byte[] raw,String type,String correlation){var summary=new HashMap<String,Object>();summary.put("type",type);if(correlation!=null)summary.put("inResponseTo",correlation);entries.add(new TranscriptEntry(id,RUN,direction,at,action,"POST",url,200,Map.of(),null,0,"transcripts/"+RUN+"/"+id+".saml.xml",raw.length,"application/xml",null,Map.copyOf(summary)));decoded.put(id,raw);}
    private SloRegisteredSignerEvidence reader(){return new SloRegisteredSignerEvidence(directory,e->decoded.get(e.id()),r->metadata,(r,v)->Optional.of(r.equals(RUN)?own:other),adapter());}
    private SloRegisteredSignerNativeAdapter adapter(){return new SloRegisteredSignerNativeAdapter(){
        public String adapter(){return "test-native-slo";}
        public Session open(CaseContext c,Path folder,com.fasterxml.jackson.databind.JsonNode m,SloRegisteredSignerEvidence.Originals o,boolean finalProof){return new Session(){public List<EvidenceRef> registrationEvidence(){return List.of(new EvidenceRef("transcript","tx_baseline_request"));}
            public NativeUse validate(com.fasterxml.jackson.databind.JsonNode row,String fixture,TranscriptEntry q,org.w3c.dom.Element xml,byte[] bytes,TranscriptEntry r,org.w3c.dom.Element response){return new NativeUse(fixture.equals("local-normal")||acceptOtherSigner&&fixture.equals("local-other-signer")?Decision.ACCEPTED:Decision.REJECTED_SIGNATURE,q.timestamp(),q.timestamp().plusSeconds(1),List.of(new EvidenceRef("transcript",q.id())));}};}};}
    private static final class TestFallback implements com.samlscope.core.caseexec.TestCase,AttestationPrompt{
        public String id(){return SloRegisteredSignerEvidence.CASE;}public TargetRole role(){return TargetRole.IDP;}public String promptEn(){return "Approved attestation";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){throw new AssertionError("Owned native proof cannot borrow fallback");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Owned native proof cannot borrow fallback");}
    }
    private CaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String run){return List.copyOf(entries);}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No sending");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("No rewrite");}},true);}
    private static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
}
