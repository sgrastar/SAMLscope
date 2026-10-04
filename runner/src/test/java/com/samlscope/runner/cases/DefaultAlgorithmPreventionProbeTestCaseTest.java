package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.*;
import java.net.URI;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class DefaultAlgorithmPreventionProbeTestCaseTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW=Instant.parse("2026-10-03T10:00:00Z");
    private static final String MD=DefaultAlgorithmPreventionEvidence.MD,A=DefaultAlgorithmPreventionEvidence.A,P=DefaultAlgorithmPreventionEvidence.P;
    @TempDir Path folder;
    private PlanCredentials suite,target;private byte[] suiteMetadata,targetMetadata;private Element suiteXml;
    private final List<TranscriptEntry> entries=new ArrayList<>();private final Map<String,byte[]> decoded=new HashMap<>();
    private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String run){return entries;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
        public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}},complete);}
    private DefaultAlgorithmPreventionProbeTestCase test(boolean prepared,String profile)throws Exception {return test(prepared,profile,true,true);}
    private DefaultAlgorithmPreventionProbeTestCase test(boolean prepared,String profile,boolean nativeReady,boolean keyTransport)throws Exception {
        folder=folder.toRealPath();var clock=Clock.fixed(NOW,ZoneOffset.UTC);var store=new FilePlanKeyStore(folder.resolve("keys"),clock);suite=store.getOrCreate(PLAN);target=store.getOrCreate(PLAN,"target");
        var plan=new TestPlan(PLAN,"default prevention",FunctionalProfile.BROWSER_SSO_IDP,new TestPlan.Target(TargetKind.IDP,"https://target.example/idp",new TestPlan.MetadataSource(MetadataSourceKind.URL,"https://target.example/metadata")),MetadataDeliveryKind.HTTP_URL,Map.of(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),NOW,NOW);
        var metadataService=new MetadataService(URI.create("https://actual-peer.example"),store,new XmlSigner(),clock);
        suite=metadataService.credentialsForPollingVariant(plan,MetadataService.Variant.parse("control"));
        suiteMetadata=metadataService.generatePolling(plan,MetadataService.Variant.parse("control"),RUN);
        suiteXml=SecureXml.parse(suiteMetadata).getDocumentElement();
        String cert=Base64.getEncoder().encodeToString(target.certificate().getEncoded());
        targetMetadata=("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://target.example/idp'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"'><md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://target.example/sso'/><md:SingleLogoutService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://target.example/slo'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes();
        if(prepared){add("tx_fetch",new byte[]{1},Direction.INBOUND,NOW.minusSeconds(6),"https://actual-peer.example/metadata",Map.of("type","MetadataFetch"));
            add("tx_prepared",suiteMetadata,Direction.OUTBOUND,NOW.minusSeconds(5),"https://actual-peer.example/metadata",Map.of("type","MetadataPrepared","variant","control","feed","live","metadataSha256",DefaultAlgorithmPreventionEvidence.hash(suiteMetadata),"fetchTranscriptId","tx_fetch","delivery","PREPARED"));}
        if(prepared&&nativeReady)prepareNative(keyTransport);
        TestCase fallback=new Fallback();return new DefaultAlgorithmPreventionProbeTestCase(fallback,e->decoded.get(e.id()),run->targetMetadata,run->Optional.of(suite),run->profile,folder.resolve("proof"),new TestNativeAdapter());
    }
    private void prepareNative(boolean cipher)throws Exception {
        var codec=new JsonCodec().mapper();var proof=folder.resolve("proof").toAbsolutePath();Files.createDirectories(proof);
        var nativeFolder=proof.resolve(RUN+".preparation");Files.createDirectories(nativeFolder);
        byte[] raw=codec.writeValueAsBytes(Map.of("runId",RUN,"targetHash",DefaultAlgorithmPreventionEvidence.hash(targetMetadata),
                "suiteHash",DefaultAlgorithmPreventionEvidence.hash(suiteMetadata),"testNativeOriginal",true,"cipherConsumer",cipher));
        entries.removeIf(e->e.id().equals("tx_native_preparation"));add("tx_native_preparation",raw,Direction.INBOUND,NOW.minusSeconds(4),"native://default-policy",Map.of("type","NativePreparation"));
        Files.write(nativeFolder.resolve("native.json"),raw);
        var m=new LinkedHashMap<String,Object>();m.put("schema",DefaultAlgorithmPreventionEvidence.SCHEMA+"-preparation");m.put("runId",RUN);
        m.put("caseId",DefaultAlgorithmComparison.CASE);m.put("campaignId",DefaultAlgorithmComparison.CAMPAIGN);m.put("profile","browser_sso_idp");
        m.put("counterfactualCalibrationOnly",false);m.put("adapter","test-original-adapter");m.put("targetEntityId","https://target.example/idp");
        m.put("targetMetadataSha256",DefaultAlgorithmPreventionEvidence.hash(targetMetadata));m.put("suiteMetadataReference","tx_prepared");
        m.put("suiteMetadataSha256",DefaultAlgorithmPreventionEvidence.hash(suiteMetadata));m.put("files",Map.of("native.json",DefaultAlgorithmPreventionEvidence.hash(raw)));
        m.put("nativeOriginals",List.of(Map.of("reference","tx_native_preparation","sha256",DefaultAlgorithmPreventionEvidence.hash(raw))));
        Files.write(proof.resolve(RUN+".preparation.json"),codec.writeValueAsBytes(m));
    }
    private final class TestNativeAdapter implements DefaultAlgorithmNativeAdapter {
        public String adapter(){return "test-original-adapter";}
        public Optional<Preparation> prepare(CaseContext c,Path f,JsonNode m,byte[] targetBytes,byte[] suiteBytes)throws Exception {
            var raw=new JsonCodec().mapper().readTree(decoded.get("tx_native_preparation"));
            if(!RUN.equals(raw.path("runId").asText())||!raw.path("testNativeOriginal").asBoolean()
                    ||!DefaultAlgorithmPreventionEvidence.hash(targetBytes).equals(raw.path("targetHash").asText())
                    ||!DefaultAlgorithmPreventionEvidence.hash(suiteBytes).equals(raw.path("suiteHash").asText()))return Optional.empty();
            return Optional.of(new Preparation("test-policy-bound-to-original",raw.path("cipherConsumer").booleanValue(),List.of(new EvidenceRef("transcript","tx_native_preparation"))));
        }
        public Session open(CaseContext c,Path f,JsonNode m,byte[] targetBytes,byte[] suiteBytes){throw new AssertionError("Preparation must not run a final consumer proof");}
    }
    private final class Fallback implements TestCase,AttestationPrompt {
        public String id(){return DefaultAlgorithmComparison.CASE;}public TargetRole role(){return TargetRole.IDP;}
        public String promptEn(){return "Approved default algorithm prevention statement";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){throw new AssertionError("No automatic declaration or fallback login");}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("No automatic declaration");}
    }
    private void add(String id,byte[] bytes,Direction direction,Instant at,String url,Map<String,Object> summary){decoded.put(id,bytes);entries.add(new TranscriptEntry(id,RUN,direction,at,id.equals("tx_prepared")?"tx_fetch":(String)summary.get("action_id"),"POST",url,200,Map.of(),null,0,"transcripts/"+RUN+"/"+id+".saml.xml",bytes.length,"application/xml",null,summary));}
    private void recordRequest(CaseStep.AwaitInbound waiting){var action=waiting.actions().getFirst();add("tx_"+waiting.next().data().get("fixture_id"),action.payload(),Direction.OUTBOUND,NOW,action.target().toString(),Map.of("type",action.kind()==OutboundKind.LOGOUT_REQUEST?"LogoutRequest":"AuthnRequest","action_id",action.actionId(),"scenario_case_id",DefaultAlgorithmComparison.CASE,"fixture_id",waiting.next().data().get("fixture_id"),"active_probe",true));}
    private CaseEvent.BrowserObservation recordBrowser(CaseStep.AwaitInbound waiting) {
        String id="tx_browser_"+waiting.next().data().get("fixture_id"),url=waiting.actions().getFirst().target().toString(),body="<html>Native error page</html>";
        entries.add(new TranscriptEntry(id,RUN,Direction.INBOUND,NOW,waiting.actions().getFirst().actionId(),"BROWSER",url,400,Map.of(),
                "transcripts/"+RUN+"/"+id+".body",body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length,
                null,0,"text/html",null,Map.of("type","BrowserResponseObservation","http_status",400,"url",url,"failure_indicated",true)));
        return new CaseEvent.BrowserObservation(400,url,body,new EvidenceRef("transcript",id));
    }
    private byte[] normal(CaseState state)throws Exception {return normal(state,false);}
    private byte[] normal(CaseState state,boolean assertionOnly)throws Exception {
        String request=(String)state.data().get("request_id"),acs=DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString();
        var xml=SecureXml.parse(("<p:Response xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_response' Version='2.0' IssueInstant='"+NOW+"' Destination='placeholder-destination' InResponseTo='"+request+"'><a:Issuer>https://target.example/idp</a:Issuer><p:Status><p:StatusCode Value='"+DefaultAlgorithmPreventionEvidence.SUCCESS+"'/></p:Status><a:Assertion ID='_assertion' Version='2.0' IssueInstant='"+NOW+"'><a:Issuer>https://target.example/idp</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient' NameQualifier='https://target.example/idp' SPNameQualifier='"+suiteXml.getAttribute("entityID")+"'>native-known-principal</a:NameID><a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><a:SubjectConfirmationData InResponseTo='"+request+"' Recipient='placeholder-recipient'/></a:SubjectConfirmation></a:Subject><a:Conditions><a:AudienceRestriction><a:Audience>"+suiteXml.getAttribute("entityID")+"</a:Audience></a:AudienceRestriction></a:Conditions><a:AuthnStatement SessionIndex='native-session' AuthnInstant='"+NOW+"'><a:AuthnContext><a:AuthnContextClassRef>urn:password</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement></a:Assertion></p:Response>").getBytes()).getDocumentElement();
        xml.setAttribute("Destination",acs);DefaultAlgorithmPreventionEvidence.single(DefaultAlgorithmPreventionEvidence.single(DefaultAlgorithmPreventionEvidence.single(DefaultAlgorithmPreventionEvidence.single(xml,A,"Assertion"),A,"Subject"),A,"SubjectConfirmation"),A,"SubjectConfirmationData").setAttribute("Recipient",acs);
        if(assertionOnly){var assertion=DefaultAlgorithmPreventionEvidence.single(xml,A,"Assertion");new XmlSigner().sign(assertion,target,DefaultAlgorithmPreventionEvidence.single(assertion,A,"Subject"));}
        else new XmlSigner().sign(xml,target,DefaultAlgorithmPreventionEvidence.single(xml,P,"Status"));return SecureXml.serialize(xml.getOwnerDocument());
    }
    @Test void fullSixOutboxesUseOneLoginAndOriginalMetadataEndpointsAndNeverSelfDetermine()throws Exception {
        var test=test(true,"browser_sso_idp");var prepared=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));assertTrue(prepared.actions().isEmpty());
        CaseStep step=test.resume(context(true),prepared.next(),new CaseEvent.ConfigConfirmed());var observed=new ArrayList<String>();
        while(step instanceof CaseStep.AwaitInbound waiting){String fixture=(String)waiting.next().data().get("fixture_id");observed.add(fixture);recordRequest(waiting);
            assertEquals(List.of("active-probe-login-1"),test.evidenceActionKeys());assertFalse(test.requiresFreshSession(waiting.next()));assertFalse(test.plansFreshSessionBoundary());
            assertEquals(DefaultAlgorithmPreventionProbeTestCase.action(RUN,fixture),waiting.actions().getFirst().actionId());
            if(fixture.equals("sha256-control")){byte[] response=normal(waiting.next());add("tx_normal",response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));step=test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(response,new EvidenceRef("transcript","tx_normal")));}
            else {var request=SecureXml.parse(waiting.actions().getFirst().payload()).getDocumentElement();
                if(fixture.contains("encrypted-id")){var cipher=DefaultAlgorithmPreventionEvidence.single(request,A,"EncryptedID");var identity=new SamlXmlDecrypter().decrypt(cipher,target.privateKey());assertEquals("native-known-principal",identity.getTextContent());assertEquals("native-session",DefaultAlgorithmPreventionEvidence.single(request,P,"SessionIndex").getTextContent());assertFalse(waiting.next().data().toString().contains("native-known-principal"));}
                step=test.resume(context(true),waiting.next(),new CaseEvent.InboundUnavailable("Recorded native error pending"));}
        }
        assertEquals(DefaultAlgorithmComparison.REQUIRED,observed);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void missingMetadataIncompleteHistoryAndEcpDoNotInviteALogin()throws Exception {
        var test=test(false,"browser_sso_idp");assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome().outcome());
        entries.clear();test=test(true,"ecp_idp");assertInstanceOf(CaseStep.Finish.class,test.start(context(true)));assertInstanceOf(CaseStep.Finish.class,test.start(context(false)));
    }
    @Test void recorderBrowserFeedbackWithoutSamlOrActionHintCollectsAllSixInputsWithoutConcludingFromHttpErrors()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        CaseStep step=test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed());var seen=new ArrayList<String>();
        while(step instanceof CaseStep.AwaitInbound waiting) {
            String fixture=(String)waiting.next().data().get("fixture_id");seen.add(fixture);recordRequest(waiting);
            if(fixture.equals("sha256-control")) {
                byte[] response=normal(waiting.next());add("tx_normal",response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
                step=test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(response,new EvidenceRef("transcript","tx_normal")));
            }else {
                var feedback=recordBrowser(waiting);var original=entries.getLast();
                assertFalse(original.samlSummary().containsKey("action_id"));assertNull(original.decodedSamlRef());
                step=test.resume(context(true),waiting.next(),feedback);
            }
        }
        assertEquals(DefaultAlgorithmComparison.REQUIRED,seen);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void browserFeedbackRequiresItsSameRunOriginalActionAndActualRecorderFields()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed()));recordRequest(waiting);
        byte[] response=normal(waiting.next());add("tx_normal",response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
        waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(response,new EvidenceRef("transcript","tx_normal"))));
        recordRequest(waiting);var request=entries.getLast();var feedback=recordBrowser(waiting);var original=entries.getLast();var baseline=List.copyOf(entries);
        for(String defect:List.of("missing","duplicate","foreign-run","wrong-direction","wrong-method","wrong-correlation","wrong-type",
                "wrong-status","wrong-summary-status","wrong-url","wrong-summary-url","contradictory-action-hint","embedded-saml",
                "wrong-body-reference","wrong-body-length","earlier-observation","missing-request","duplicate-request")) {
            entries.clear();entries.addAll(baseline);var summary=new HashMap<String,Object>(original.samlSummary());
            String run=RUN,method=original.method(),correlation=original.correlationId(),url=original.url(),bodyRef=original.bodyRef(),samlRef=null;
            Direction direction=original.direction();Integer status=original.status();Instant time=original.timestamp();int bodyLength=original.bodyBytes(),samlLength=0;
            switch(defect) {
                case "missing"->entries.remove(original);
                case "duplicate"->entries.add(original);
                case "foreign-run"->run="run_11111111111111111111111111";
                case "wrong-direction"->direction=Direction.OUTBOUND;
                case "wrong-method"->method="POST";
                case "wrong-correlation"->correlation="foreign-action";
                case "wrong-type"->summary.put("type","Response");
                case "wrong-status"->status=200;
                case "wrong-summary-status"->summary.put("http_status",200);
                case "wrong-url"->url="https://foreign.example/error";
                case "wrong-summary-url"->summary.put("url","https://foreign.example/error");
                case "contradictory-action-hint"->summary.put("action_id","foreign-action");
                case "embedded-saml"->{samlRef="transcripts/"+RUN+"/"+original.id()+".saml.xml";samlLength=1;}
                case "wrong-body-reference"->bodyRef="transcripts/foreign/"+original.id()+".body";
                case "wrong-body-length"->bodyLength++;
                case "earlier-observation"->time=NOW.minusSeconds(1);
                case "missing-request"->entries.remove(request);
                case "duplicate-request"->entries.add(request);
                default->throw new AssertionError(defect);
            }
            int index=entries.indexOf(original);if(index>=0)entries.set(index,new TranscriptEntry(original.id(),run,direction,time,correlation,method,url,status,
                    original.headers(),bodyRef,bodyLength,samlRef,samlLength,original.contentType(),original.rawQuery(),summary));
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),waiting.next(),feedback),defect);
            assertEquals(Outcome.NOT_VERIFIED,result.outcome().outcome(),defect);
        }
    }
    @Test void untrustedOrUncorrelatedNormalResponseStopsBeforeAdditionalProbes()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed()));recordRequest(waiting);
        var root=SecureXml.parse(normal(waiting.next())).getDocumentElement();root.setAttribute("InResponseTo","_unrelated");byte[] bytes=SecureXml.serialize(root.getOwnerDocument());add("tx_wrong",bytes,Direction.INBOUND,NOW,"https://actual-peer.example/acs",Map.of("type","Response"));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(bytes,new EvidenceRef("transcript","tx_wrong")))).outcome().outcome());
    }
    @Test void recorderShapedRequestsRequireUniqueRunActionFixtureAndOriginalXmlBeforeAdvancing()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed()));
        recordRequest(waiting);var request=entries.getLast();assertFalse(request.samlSummary().containsKey("id"));
        byte[] original=decoded.get(request.id()),response=normal(waiting.next());
        add("tx_normal",response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
        var baseline=List.copyOf(entries);
        for(String defect:List.of("missing","duplicate","foreign-run","wrong-action","wrong-correlation","wrong-fixture",
                "wrong-case","wrong-type","later-request","wrong-byte-length","false-summary-id")) {
            entries.clear();entries.addAll(baseline);decoded.put(request.id(),original);
            var summary=new HashMap<String,Object>(request.samlSummary());String run=RUN,correlation=request.correlationId();
            Instant at=NOW;int length=original.length;
            switch(defect) {
                case "missing"->entries.remove(request);
                case "duplicate"->entries.add(request);
                case "foreign-run"->run="run_11111111111111111111111111";
                case "wrong-action"->summary.put("action_id","another-action");
                case "wrong-correlation"->correlation="another-action";
                case "wrong-fixture"->summary.put("fixture_id","rsa-md5");
                case "wrong-case"->summary.put("scenario_case_id","another-case");
                case "wrong-type"->summary.put("type","LogoutRequest");
                case "later-request"->at=NOW.plusSeconds(1);
                case "wrong-byte-length"->length++;
                case "false-summary-id"->{
                    summary.put("id",waiting.next().data().get("request_id"));
                    var root=SecureXml.parse(original).getDocumentElement();root.setAttribute("ID","_unrelated");
                    var changed=SecureXml.serialize(root.getOwnerDocument());decoded.put(request.id(),changed);length=changed.length;
                }
                default->throw new AssertionError(defect);
            }
            if(!Set.of("missing","duplicate").contains(defect)) {
                int index=entries.indexOf(request);entries.set(index,new TranscriptEntry(request.id(),run,request.direction(),at,correlation,
                        request.method(),request.url(),request.status(),request.headers(),request.bodyRef(),request.bodyBytes(),
                        request.decodedSamlRef(),length,request.contentType(),request.rawQuery(),summary));
            }
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),waiting.next(),
                    new CaseEvent.InboundMessage(response,new EvidenceRef("transcript","tx_normal"))),defect);
            assertEquals(Outcome.NOT_VERIFIED,result.outcome().outcome(),defect);
        }
    }
    @Test void cipherPreparationRechecksTheAuthenticatedRequestInsteadOfTrustingAnEarlierSummary()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed()));
        recordRequest(waiting);var authenticatedRequest=entries.getLast();byte[] response=normal(waiting.next());
        add("tx_normal",response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
        waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(response,new EvidenceRef("transcript","tx_normal"))));
        for(int index=1;index<3;index++) {
            recordRequest(waiting);waiting=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),waiting.next(),new CaseEvent.InboundUnavailable("native original pending")));
        }
        assertEquals("rsa-md5",waiting.next().data().get("fixture_id"));recordRequest(waiting);
        entries.add(authenticatedRequest);
        var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),waiting.next(),new CaseEvent.InboundUnavailable("native original pending")));
        assertEquals(Outcome.NOT_VERIFIED,result.outcome().outcome());
        assertTrue(entries.stream().noneMatch(e->"LogoutRequest".equals(e.samlSummary().get("type"))));
    }
    @Test void aLaterAuthenticSignatureResponseBindsCipherInputsToItsOwnOriginalRequest()throws Exception {
        var test=test(true,"browser_sso_idp");var config=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        CaseStep step=test.resume(context(true),config.next(),new CaseEvent.ConfigConfirmed());var seen=new ArrayList<String>();
        while(step instanceof CaseStep.AwaitInbound waiting) {
            String fixture=(String)waiting.next().data().get("fixture_id");seen.add(fixture);recordRequest(waiting);
            if(Set.of("sha256-control","md5-digest","rsa-md5").contains(fixture)) {
                byte[] response=normal(waiting.next());String reference="tx_response_"+fixture;
                add(reference,response,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
                step=test.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(response,new EvidenceRef("transcript",reference)));
            }else {
                if(fixture.contains("encrypted-id"))assertEquals("tx_response_rsa-md5",waiting.next().data().get("authenticated_response"));
                step=test.resume(context(true),waiting.next(),new CaseEvent.InboundUnavailable("native original pending"));
            }
        }
        assertEquals(DefaultAlgorithmComparison.REQUIRED,seen);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void absentForeignUnhashedOrCounterfactualNativePreparationEmitsNoAction()throws Exception {
        var t=test(true,"browser_sso_idp",false,true);assertInstanceOf(CaseStep.Finish.class,t.start(context(true)));
        prepareNative(true);Path manifest=folder.resolve("proof").resolve(RUN+".preparation.json");byte[] original=Files.readAllBytes(manifest);
        for(String changed:List.of(new String(original).replace(RUN,"run_11111111111111111111111111"),
                new String(original).replace("\"counterfactualCalibrationOnly\":false","\"counterfactualCalibrationOnly\":true"),
                new String(original).replace("test-original-adapter","unknown-native-adapter"))) {
            Files.writeString(manifest,changed);assertInstanceOf(CaseStep.Finish.class,t.start(context(true)));
        }
        Files.write(manifest,original);decoded.put("tx_native_preparation","tampered".getBytes());assertInstanceOf(CaseStep.Finish.class,t.start(context(true)));
    }
    @Test void signatureOnlyPreparationUsesFourInputsAndAcceptsAuthenticAssertionWithoutOuterSignature()throws Exception {
        var t=test(true,"browser_sso_idp",true,false);var targetXml=SecureXml.parse(targetMetadata).getDocumentElement();
        var role=DefaultAlgorithmPreventionEvidence.single(targetXml,MD,"IDPSSODescriptor");
        role.removeChild(DefaultAlgorithmPreventionEvidence.single(role,MD,"SingleLogoutService"));
        DefaultAlgorithmPreventionEvidence.single(role,MD,"KeyDescriptor").setAttribute("use","signing");
        targetMetadata=SecureXml.serialize(targetXml.getOwnerDocument());prepareNative(false);
        var prepared=assertInstanceOf(CaseStep.AwaitConfig.class,t.start(context(true)));CaseStep step=t.resume(context(true),prepared.next(),new CaseEvent.ConfigConfirmed());
        var seen=new ArrayList<String>();while(step instanceof CaseStep.AwaitInbound waiting){String fixture=(String)waiting.next().data().get("fixture_id");seen.add(fixture);recordRequest(waiting);
            if(fixture.equals("sha256-control")){byte[] reply=normal(waiting.next(),true);add("tx_assertion_only",reply,Direction.INBOUND,NOW,DefaultAlgorithmPreventionEvidence.endpoint(suiteXml,"AssertionConsumerService").toString(),Map.of("type","Response"));
                step=t.resume(context(true),waiting.next(),new CaseEvent.InboundMessage(reply,new EvidenceRef("transcript","tx_assertion_only")));}
            else step=t.resume(context(true),waiting.next(),new CaseEvent.InboundUnavailable("native original collection pending"));
        }
        assertEquals(DefaultAlgorithmComparison.REQUIRED.subList(0,4),seen);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
    }
    @Test void malformedOwnedReceiptNeverCallsDeclarationOrEmitsAnOutbox()throws Exception {
        var test=test(true,"browser_sso_idp");Files.createDirectories(folder.resolve("proof").resolve(RUN));Files.writeString(folder.resolve("proof").resolve(RUN).resolve("manifest.json"),"{}");
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),CaseState.initial(),new CaseEvent.Attested("true","declaration"))).outcome().outcome());assertFalse(test.evidenceStatus(context(true)).ready());
    }

    @Test void aBrowserDisabledPlanCannotEmitPreparedNativeProbes()throws Exception {
        var test=test(true,"browser_sso_idp");
        var waiting=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        var c=context(true);
        var disabled=new DefaultCaseContext(c.runId(),c.targetRole(),c.clock(),c.parameters(),
                new TestPlan.Interaction(false,false),c.reachability(),c.transcript(),c.transcriptComplete());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(disabled)).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,
                test.resume(disabled,waiting.next(),new CaseEvent.ConfigConfirmed())).outcome().outcome());
    }
}
