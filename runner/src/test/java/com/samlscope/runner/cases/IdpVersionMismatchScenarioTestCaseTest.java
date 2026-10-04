package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.CaseExecutionService;
import com.samlscope.runner.CaseTimeoutService;
import com.samlscope.runner.TestCaseRegistry;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;

class IdpVersionMismatchScenarioTestCaseTest {
    static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",PLAN="plan_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW=Instant.parse("2026-10-03T19:00:00Z");
    static final URI SSO=URI.create("https://target.example/sso"),ACS=URI.create("https://suite.example/acs?mdv=control&run="+RUN);
    @TempDir Path folder;
    PlanCredentials suite,target;byte[] metadata;IdpVersionMismatchScenarioTestCase test;
    List<TranscriptEntry> entries=new ArrayList<>();Map<String,byte[]> bytes=new HashMap<>();
    final IdpErrorProbeConfiguration config=new IdpErrorProbeConfiguration(SSO,"https://suite.example/sp",ACS,Duration.ofMinutes(2),true,true,false);
    @BeforeEach void setup()throws Exception{
        folder=folder.toRealPath();var keys=new FilePlanKeyStore(folder.resolve("keys"),Clock.fixed(NOW,ZoneOffset.UTC));suite=keys.getOrCreate(PLAN);target=keys.getOrCreate(PLAN,"target");
        var d=SecureXml.newDocument();var root=d.createElementNS(IdpVersionMismatchScenarioTestCase.MD,"md:EntityDescriptor");root.setAttribute("entityID","https://target.example/idp");d.appendChild(root);
        var role=d.createElementNS(IdpVersionMismatchScenarioTestCase.MD,"md:IDPSSODescriptor");role.setAttribute("protocolSupportEnumeration",IdpVersionMismatchScenarioTestCase.P);root.appendChild(role);var key=d.createElementNS(IdpVersionMismatchScenarioTestCase.MD,"md:KeyDescriptor");role.appendChild(key);
        var info=d.createElementNS("http://www.w3.org/2000/09/xmldsig#","ds:KeyInfo");key.appendChild(info);var data=d.createElementNS("http://www.w3.org/2000/09/xmldsig#","ds:X509Data");info.appendChild(data);
        var cert=d.createElementNS("http://www.w3.org/2000/09/xmldsig#","ds:X509Certificate");cert.setTextContent(Base64.getEncoder().encodeToString(target.certificate().getEncoded()));data.appendChild(cert);metadata=SecureXml.serialize(d);
        test=new IdpVersionMismatchScenarioTestCase(r->config,r->Optional.of(suite),e->bytes.get(e.id()),r->metadata,r->Optional.of(suite.privateKey()),folder.resolve("proof"));
    }
    CaseContext context(boolean browser){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),new TestPlan.Interaction(browser,false),Reachability.CONFIRMED,new TranscriptRecorder(){
        public List<TranscriptEntry> list(String r){return entries;}
        public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
        public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> s){throw new UnsupportedOperationException();}},true);}
    TranscriptEntry request(String fixture){String action=ActionIds.derive(RUN,test.id(),"await-fixture-"+fixture,0);byte[] raw=IdpVersionMismatchScenarioTestCase.fixture(fixture,"_"+action,config,NOW,suite);
        var e=new TranscriptEntry("tx_"+fixture,RUN,Direction.OUTBOUND,NOW,action,"POST",SSO.toString(),null,Map.of(),null,0,"decoded/"+fixture,raw.length,"application/xml",null,
                Map.of("type","AuthnRequest","scenario_case_id",test.id(),"fixture_id",fixture,"action_id",action));entries.add(e);bytes.put(e.id(),raw);return e;}
    TranscriptEntry response(TranscriptEntry req,String status,boolean outer)throws Exception{
        var d=SecureXml.newDocument();var root=d.createElementNS(IdpVersionMismatchScenarioTestCase.P,"samlp:Response");root.setAttribute("ID","_reply_"+req.id());root.setAttribute("InResponseTo","_"+req.correlationId());root.setAttribute("Destination",ACS.toString());root.setAttribute("Version","2.0");root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:samlp",IdpVersionMismatchScenarioTestCase.P);root.setAttributeNS("http://www.w3.org/2000/xmlns/","xmlns:saml",IdpVersionMismatchScenarioTestCase.A);d.appendChild(root);
        var issuer=d.createElementNS(IdpVersionMismatchScenarioTestCase.A,"saml:Issuer");issuer.setTextContent("https://target.example/idp");root.appendChild(issuer);
        var st=d.createElementNS(IdpVersionMismatchScenarioTestCase.P,"samlp:Status");root.appendChild(st);var code=d.createElementNS(IdpVersionMismatchScenarioTestCase.P,"samlp:StatusCode");code.setAttribute("Value",IdpVersionMismatchScenarioTestCase.STATUS+status);st.appendChild(code);
        if(status.equals("Success")){var assertion=d.createElementNS(IdpVersionMismatchScenarioTestCase.A,"saml:Assertion");assertion.setAttribute("ID","_assertion_"+req.id());assertion.setAttribute("Version","2.0");root.appendChild(assertion);var ai=d.createElementNS(IdpVersionMismatchScenarioTestCase.A,"saml:Issuer");ai.setTextContent(issuer.getTextContent());assertion.appendChild(ai);new XmlSigner().sign(assertion,target,null);}
        if(outer)new XmlSigner().sign(root,target,null);byte[] raw=SecureXml.serialize(d);var e=new TranscriptEntry("tx_response_"+req.id(),RUN,Direction.INBOUND,NOW.plusSeconds(1),root.getAttribute("InResponseTo"),"POST",ACS.toString(),200,Map.of(),null,0,"decoded/reply",raw.length,"application/xml",null,Map.of("type","Response","inResponseTo",root.getAttribute("InResponseTo")));entries.add(e);bytes.put(e.id(),raw);return e;
    }
    void controls()throws Exception{response(request("baseline-success"),"Success",false);response(request("invalid-issue-instant"),"Responder",true);}
    CaseOutcome outcome(){return assertInstanceOf(CaseStep.Finish.class,test.start(context(false))).outcome();}
    @Test void actualSignedResponsesCoverAllVariantsAndWrongTopLevelMutantIsDetected()throws Exception{
        controls();var old=request("version-1-1");var response=response(old,"VersionMismatch",true);assertEquals(Outcome.SATISFIED,outcome().outcome());
        entries.remove(response);response(old,"Responder",true);assertEquals(Outcome.VIOLATED,outcome().outcome());
    }
    @Test void nonVersionControlIsRequiredAndCannotIndependentlyCreateAProductViolation()throws Exception{
        response(request("baseline-success"),"Success",false);response(request("invalid-issue-instant"),"VersionMismatch",true);response(request("version-1-1"),"VersionMismatch",true);
        assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void missingNormalControlUnsignedErrorAndForeignResponseCannotComplete()throws Exception{
        response(request("invalid-issue-instant"),"Responder",true);response(request("version-1-1"),"VersionMismatch",true);assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
        response(request("baseline-success"),"Success",false);var reply=entries.get(3);bytes.put(reply.id(),new byte[]{1});assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void recorderBackedNativeVersionTerminalUsesApprovedExceptionButBareErrorDoesNot()throws Exception{
        controls();var req=request("version-1-1");terminal(req);assertEquals(Outcome.SATISFIED_WITH_NOTE,outcome().outcome());
        Files.delete(folder.resolve("proof").resolve(RUN+".json"));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void nonVersionHttpTerminalCanSatisfyControlWithoutAnInventedSamlResponse()throws Exception{
        response(request("baseline-success"),"Success",false);terminal(request("invalid-issue-instant"));terminal(request("version-1-1"));
        assertEquals(Outcome.SATISFIED_WITH_NOTE,outcome().outcome());
        Files.delete(folder.resolve("proof").resolve(RUN).resolve("utils-before.php"));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void terminalProofRejectsLabelChangesForeignRequestSourceAndGenericHttpFailure()throws Exception{
        controls();var req=request("version-1-1");terminal(req);Path manifest=folder.resolve("proof").resolve(RUN+".json");var mapper=new JsonCodec().mapper();byte[] valid=Files.readAllBytes(manifest);
        for(String defect:List.of("runId","targetMetadataSha256","adapter","counterfactualCalibrationOnly")){
            var m=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.readTree(valid);if(defect.equals("counterfactualCalibrationOnly"))m.put(defect,true);else m.put(defect,"foreign");Files.write(manifest,mapper.writeValueAsBytes(m));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome(),defect);
        }
        Files.write(manifest,valid);Files.writeString(folder.resolve("proof").resolve(RUN).resolve("version-1-1-body.txt"),"Generic internal error");assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void duplicateOrForeignRunRecorderEntryFailsClosed()throws Exception{
        controls();response(request("version-1-1"),"VersionMismatch",true);var original=List.copyOf(entries);entries.add(entries.getFirst());assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
        entries.clear();entries.addAll(original);var e=entries.removeLast();entries.add(new TranscriptEntry(e.id(),"run_11111111111111111111111111",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void readOnlyReadyEvidenceWorksWhenBrowserDisabledAndReevaluationNeedsNewTranscript()throws Exception{
        controls();response(request("version-1-1"),"VersionMismatch",true);var result=outcome();assertEquals(Outcome.SATISFIED,result.outcome());assertTrue(test.evidenceStatus(context(false)).ready());
        var old=CaseOutcome.notVerified("old","old");assertTrue(test.reevaluateRecordedEvidence(context(false),old).isPresent());
        var same=new CaseOutcome(Outcome.NOT_VERIFIED,"old","old","old",result.evidence(),Map.of());assertTrue(test.reevaluateRecordedEvidence(context(false),same).isEmpty());
        assertTrue(test.reevaluateRecordedEvidence(context(false),result).isEmpty());
    }
    @Test void deterministicValidVersionFixturesAndBrowserDisabledNeverSend()throws Exception{
        var finish=assertInstanceOf(CaseStep.Finish.class,test.start(context(false)));assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());
        var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));assertEquals("baseline-success",first.next().data().get("fixture_id"));
        var xml=SecureXml.parse(first.actions().getFirst().payload()).getDocumentElement();assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,suite.certificate()));assertEquals("_"+first.actions().getFirst().actionId(),xml.getAttribute("ID"));
    }
    @Test void actualScenarioLifecycleRequiresEveryOriginalAndDoesNotSendAfterCompletion()throws Exception{
        var c=context(true);var step=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(c));
        for(String fixture:IdpVersionMismatchScenarioTestCase.REQUIRED){
            assertEquals(fixture,step.next().data().get("fixture_id"));var req=request(fixture);
            var response=response(req,fixture.equals("baseline-success")?"Success":fixture.equals("version-1-1")?"VersionMismatch":"Requester",!fixture.equals("baseline-success"));
            var next=test.resume(c,step.next(),new CaseEvent.InboundMessage(bytes.get(response.id()),new EvidenceRef("transcript",response.id())));
            if(fixture.equals("version-1-1")){assertEquals(Outcome.SATISFIED,assertInstanceOf(CaseStep.Finish.class,next).outcome().outcome());}
            else step=assertInstanceOf(CaseStep.AwaitInbound.class,next);
        }
        assertInstanceOf(CaseStep.Finish.class,test.start(c));
    }
    @Test void legacyBrowserStateIsNotProjectedIntoCurrentScenarioForAnyPendingEvent(){
        var legacy=new CaseState("await-browser",Map.of("case_id",test.id()));
        for(CaseEvent event:List.of(new CaseEvent.TimedOut(Duration.ofMinutes(2)),new CaseEvent.Aborted("operator-cancelled"),
                new CaseEvent.InboundUnavailable("no-response"),new CaseEvent.RetryInbound(),new CaseEvent.TranscriptReady())){
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),legacy,event));
            assertEquals(Outcome.NOT_VERIFIED,result.outcome().outcome());
            assertEquals("version_state_schema_incompatible",result.outcome().notVerifiedReason());
            assertTrue(result.outcome().evidence().isEmpty());
        }
    }
    @Test void missingOrMistypedCurrentStateCannotThrowOrIssueReplacementRequests(){
        var wait=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));var state=wait.next();
        for(String key:state.data().keySet()){
            var data=new HashMap<String,Object>(state.data());data.remove(key);
            var finish=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),new CaseState(state.phase(),data),new CaseEvent.TimedOut(Duration.ofMinutes(2))));
            assertEquals("version_state_schema_incompatible",finish.outcome().notVerifiedReason(),key);
        }
        for(var change:Map.<String,Object>of("evidence",List.of(7),"fixture_index",0.5,"fixture_attempt",-1,
                "expected_response_correlation","_foreign","fixture_id","version-1-1","scenario_case_id","other").entrySet()){
            var data=new HashMap<String,Object>(state.data());data.put(change.getKey(),change.getValue());
            assertEquals("version_state_schema_incompatible",assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),new CaseState(state.phase(),data),new CaseEvent.RetryInbound())).outcome().notVerifiedReason(),change.getKey());
        }
        assertEquals("version_state_schema_incompatible",assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),new CaseState("foreign-phase",state.data()),new CaseEvent.TimedOut(Duration.ofMinutes(2)))).outcome().notVerifiedReason());
    }
    @Test void completeCurrentStateRetainsTimeoutAndDefinitionChangeSemantics(){
        var state=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true))).next();
        var finish=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),state,new CaseEvent.TimedOut(Duration.ofMinutes(2))));
        assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());assertEquals("delivery_or_response_unknown",finish.outcome().notVerifiedReason());
        assertEquals(120L,finish.outcome().details().get("waited_seconds"));
        var changed=new HashMap<String,Object>(state.data());changed.put("scenario_fingerprint","sha256:"+"0".repeat(64));
        assertEquals("scenario_definition_changed",assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),new CaseState(state.phase(),changed),new CaseEvent.RetryInbound())).outcome().notVerifiedReason());
    }
    @Test void ordinaryTimeoutServiceClosesOldWaitExactlyOnceWithoutNewOutboxOrTranscript(){
        var legacy=new CaseState("await-browser",Map.of("case_id",test.id()));
        var current=new CaseExecution[]{new CaseExecution(RUN,test.id(),0,CaseExecutionStatus.WAITING_BROWSER,legacy,
                new WaitCondition(WaitCondition.Kind.BROWSER,null,SSO,null,NOW.minusSeconds(1)),null,NOW.minusSeconds(120))};
        var repository=new CaseExecutionRepository(){
            public Optional<CaseExecution> find(String run,String id){return RUN.equals(run)&&test.id().equals(id)?Optional.of(current[0]):Optional.empty();}
            public List<CaseExecution> list(String run){return List.of(current[0]);}
            public boolean apply(long revision,CaseExecution next,List<OutboundAction> actions){assertTrue(actions.isEmpty());assertEquals(current[0].revision(),revision);current[0]=next;return true;}
            public List<OutboxEntry> listOutbox(String run){return List.of();}
            public Optional<OutboxEntry> findOutbox(String action){return Optional.empty();}
            public boolean transitionOutbox(String action,OutboxStatus expected,OutboxStatus next,Map<String,Object> result,String ref,Instant at){throw new AssertionError("No sends");}
            public int recoverSendingAsUnknownDelivery(Instant at){throw new AssertionError("No outbox changes");}
        };
        var timeout=new CaseTimeoutService(repository,new TestCaseRegistry(List.of(test)),new CaseExecutionService(repository));
        var result=timeout.expireReady(RUN,context(true));assertEquals(1,result.size());
        assertEquals(CaseExecutionStatus.FINISHED,result.getFirst().status());assertEquals(1,result.getFirst().revision());
        assertEquals(legacy,result.getFirst().state());assertEquals("version_state_schema_incompatible",result.getFirst().outcome().notVerifiedReason());
        assertTrue(timeout.expireReady(RUN,context(true)).isEmpty());assertTrue(entries.isEmpty());assertTrue(repository.listOutbox(RUN).isEmpty());
    }
    @Test void actualRecorderRequestIdCorrelationAdvancesNormalWhileActionLabelsCannotBorrowIt()throws Exception{
        var c=context(true);var step=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(c));
        var req=request("baseline-success");var reply=response(req,"Success",false);
        assertEquals("_"+req.correlationId(),reply.correlationId());
        assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(c,step.next(),new CaseEvent.InboundMessage(bytes.get(reply.id()),new EvidenceRef("transcript",reply.id()))));
        for(String correlation:List.of(req.correlationId(),"_action_foreign","_"+ActionIds.derive("run_11111111111111111111111111",test.id(),"await-fixture-baseline-success",0))){
            entries.set(1,new TranscriptEntry(reply.id(),reply.runId(),reply.direction(),reply.timestamp(),correlation,reply.method(),reply.url(),reply.status(),reply.headers(),reply.bodyRef(),reply.bodyBytes(),reply.decodedSamlRef(),reply.decodedSamlBytes(),reply.contentType(),reply.rawQuery(),reply.samlSummary()));
            var finish=assertInstanceOf(CaseStep.Finish.class,test.resume(c,step.next(),new CaseEvent.InboundMessage(bytes.get(reply.id()),new EvidenceRef("transcript",reply.id()))));
            assertEquals("version_observation_unbound",finish.outcome().notVerifiedReason());
        }
    }
    @Test void sameRequestIdCorrelationCannotHideForeignXmlOrAmbiguousResponses()throws Exception{
        var c=context(true);var step=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(c));var req=request("baseline-success");var reply=response(req,"Success",false);
        byte[] raw=bytes.get(reply.id());var xml=SecureXml.parse(raw);xml.getDocumentElement().setAttribute("InResponseTo","_foreign");bytes.put(reply.id(),SecureXml.serialize(xml));
        assertEquals("version_observation_unbound",assertInstanceOf(CaseStep.Finish.class,test.resume(c,step.next(),new CaseEvent.InboundMessage(bytes.get(reply.id()),new EvidenceRef("transcript",reply.id())))).outcome().notVerifiedReason());
        bytes.put(reply.id(),raw);entries.add(new TranscriptEntry("tx_other_reply",RUN,reply.direction(),reply.timestamp(),reply.correlationId(),reply.method(),reply.url(),reply.status(),reply.headers(),reply.bodyRef(),reply.bodyBytes(),"decoded/duplicate",raw.length,reply.contentType(),reply.rawQuery(),reply.samlSummary()));bytes.put("tx_other_reply",raw);
        assertEquals("version_observation_unbound",assertInstanceOf(CaseStep.Finish.class,test.resume(c,step.next(),new CaseEvent.InboundMessage(raw,new EvidenceRef("transcript",reply.id())))).outcome().notVerifiedReason());
    }
    @Test void unknownDeliveryOrWrongActionCannotBorrowValidSamlReplies()throws Exception{
        controls();response(request("version-1-1"),"VersionMismatch",true);var original=List.copyOf(entries);var first=entries.removeFirst();
        var summary=new HashMap<String,Object>(first.samlSummary());summary.put("delivery","UNKNOWN_DELIVERY");entries.addFirst(new TranscriptEntry(first.id(),first.runId(),first.direction(),first.timestamp(),first.correlationId(),first.method(),first.url(),first.status(),first.headers(),first.bodyRef(),first.bodyBytes(),first.decodedSamlRef(),first.decodedSamlBytes(),first.contentType(),first.rawQuery(),summary));
        assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());entries.clear();entries.addAll(original);var e=entries.removeLast();entries.add(new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),"other-action",e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void newNativeCaptureOriginalAllowsLateReevaluationWhileRelabelledOrForeignCaptureDoesNot()throws Exception{
        controls();terminal(request("version-1-1"));var result=outcome();assertEquals(Outcome.SATISFIED_WITH_NOTE,result.outcome());
        var before=new CaseOutcome(Outcome.NOT_VERIFIED,"old","old","old",result.evidence().stream().filter(e->!e.reference().startsWith("tx_capture")).toList(),Map.of());
        assertTrue(test.reevaluateRecordedEvidence(context(false),before).isPresent());
        var manifest=folder.resolve("proof").resolve(RUN+".json");var mapper=new JsonCodec().mapper();var m=(com.fasterxml.jackson.databind.node.ObjectNode)mapper.readTree(Files.readAllBytes(manifest));((com.fasterxml.jackson.databind.node.ObjectNode)m.path("terminals").get(0)).put("captureReference","foreign");Files.write(manifest,mapper.writeValueAsBytes(m));assertEquals(Outcome.NOT_VERIFIED,outcome().outcome());
    }
    @Test void unavailableConfigurationEndsWithoutBrowserActions(){
        var absent=new IdpVersionMismatchScenarioTestCase(r->null,r->Optional.empty(),e->null,r->null,r->Optional.empty(),folder.resolve("proof"));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,absent.start(context(true))).outcome().outcome());
    }
    @Test void unboundRegistryInstanceIssuesNothingAndLateNativeBindingPreservesSamlPath()throws Exception{
        var unbound=new IdpVersionMismatchScenarioTestCase(r->config,r->Optional.of(suite),e->bytes.get(e.id()),r->Optional.of(suite.privateKey()));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,unbound.start(context(true))).outcome().outcome());
        test=unbound.withNativeEvidence(folder.resolve("proof"),e->bytes.get(e.id()),r->metadata);
        controls();response(request("version-1-1"),"VersionMismatch",true);assertEquals(Outcome.SATISFIED,outcome().outcome());
    }
    @Test void nativeMountArrayOrderIsIgnoredWhileSourceCoverageAndContentChangesAreRejected()throws Exception{
        var mapper=new JsonCodec().mapper();var a=mapper.createObjectNode();var mounts=mapper.createArrayNode();
        for(String destination:List.of("/var/simplesamlphp/metadata/saml20-sp-remote.php","/var/simplesamlphp/config/config-override.php")){
            var row=mapper.createObjectNode();row.put("Destination",destination);row.put("Source","/host"+destination);row.put("Type","bind");row.put("RW",false);row.put("Mode","ro");row.put("Propagation","rprivate");mounts.add(row);
        }
        a.put("containerId","a".repeat(64));a.set("mounts",mounts);var b=a.deepCopy();var reverse=mapper.createArrayNode();reverse.add(mounts.get(1).deepCopy());reverse.add(mounts.get(0).deepCopy());b.set("mounts",reverse);
        assertEquals(VersionMismatchTerminalEvidence.normalizedRuntime(a),VersionMismatchTerminalEvidence.normalizedRuntime(b));
        ((com.fasterxml.jackson.databind.node.ObjectNode)reverse.get(0)).put("RW",true);assertNotEquals(VersionMismatchTerminalEvidence.normalizedRuntime(a),VersionMismatchTerminalEvidence.normalizedRuntime(b));
        ((com.fasterxml.jackson.databind.node.ObjectNode)reverse.get(0)).put("Destination","/var/simplesamlphp/vendor");assertThrows(IllegalArgumentException.class,()->VersionMismatchTerminalEvidence.normalizedRuntime(b));
    }
    void terminal(TranscriptEntry req)throws Exception{
        Path proof=folder.resolve("proof"),side=proof.resolve(RUN);Files.createDirectories(side);var mapper=new JsonCodec().mapper();var files=new ArrayList<Map<String,Object>>();var terminals=new ArrayList<Map<String,Object>>();
        Path manifest=proof.resolve(RUN+".json");if(Files.exists(manifest)){var prior=mapper.readTree(Files.readAllBytes(manifest));for(var row:prior.path("terminals"))terminals.add(mapper.convertValue(row,new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>(){}));for(var row:prior.path("files"))files.add(mapper.convertValue(row,new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>(){}));}
        String fixture=String.valueOf(req.samlSummary().get("fixture_id")),browserId="tx_browser_"+fixture;
        byte[] body=("<html>Exception: "+(fixture.equals("version-1-1")?"Unsupported version: 1.1":"Invalid SAML2 timestamp passed to xsDateTimeToTimestamp: not-a-saml-timestamp")+"</html>").getBytes(StandardCharsets.UTF_8);String bodyRef="transcripts/"+RUN+"/"+browserId+".body";Path physical=folder.resolve(bodyRef);Files.createDirectories(physical.getParent());Files.write(physical,body);
        var browser=new TranscriptEntry(browserId,RUN,Direction.INBOUND,NOW.plusSeconds(3),req.correlationId(),"BROWSER",SSO.toString(),500,Map.of(),bodyRef,body.length,null,0,"text/html",null,Map.of("type","BrowserResponseObservation","http_status",500,"url",SSO.toString()));entries.add(browser);
        var http=Map.ofEntries(Map.entry("runId",RUN),Map.entry("requestId","_"+req.correlationId()),Map.entry("requestSha256",VersionMismatchTerminalEvidence.hash(bytes.get(req.id()))),Map.entry("actionId",req.correlationId()),Map.entry("method","POST"),Map.entry("requestUrl",SSO.toString()),Map.entry("responseUrl",SSO.toString()),Map.entry("responseStatus",500),Map.entry("responseBodySha256",VersionMismatchTerminalEvidence.hash(body)),Map.entry("responseBodyBytes",body.length),Map.entry("samlResponseFormPresent",false),Map.entry("startedAt",NOW.plusSeconds(1).toString()),Map.entry("completedAt",NOW.plusSeconds(2).toString()));
        byte[] source=Objects.requireNonNull(getClass().getResourceAsStream("/version-mismatch/ssp-Message.php")).readAllBytes();
        byte[] utils=Objects.requireNonNull(getClass().getResourceAsStream("/version-mismatch/ssp-Utils.php")).readAllBytes();
        byte[] runtime=mapper.writeValueAsBytes(Map.of("utilsClassSourceSha256",VersionMismatchTerminalEvidence.SSP_UTILS_SHA,"utilsClassFile","/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Utils.php","containerId","a".repeat(64),"imageId","sha256:"+"b".repeat(64),"mounts",List.of(),"messageClassSourceSha256",VersionMismatchTerminalEvidence.SSP_MESSAGE_SHA,"messageClassFile","/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/Message.php"));
        var original=Map.of(fixture+"-body.txt",body,fixture+"-http.json",mapper.writeValueAsBytes(http),"source-before.php",source,"source-after.php",source,"utils-before.php",utils,"utils-after.php",utils,"runtime-before.json",runtime,"runtime-after.json",runtime);
        for(var item:original.entrySet()){Files.write(side.resolve(item.getKey()),item.getValue());files.removeIf(row->item.getKey().equals(row.get("file")));files.add(Map.of("file",item.getKey(),"sha256",VersionMismatchTerminalEvidence.hash(item.getValue()),"size",item.getValue().length));}
        byte[] capture=mapper.writeValueAsBytes(Map.ofEntries(Map.entry("schema","samlscope-native-version-terminal-capture-v1"),Map.entry("runId",RUN),Map.entry("caseId",test.id()),Map.entry("fixtureId",fixture),Map.entry("requestReference",req.id()),Map.entry("requestId","_"+req.correlationId()),Map.entry("requestSha256",VersionMismatchTerminalEvidence.hash(bytes.get(req.id()))),Map.entry("browserReference",browser.id()),Map.entry("targetMetadataSha256",VersionMismatchTerminalEvidence.hash(metadata)),Map.entry("nativeHttpSha256",VersionMismatchTerminalEvidence.hash(mapper.writeValueAsBytes(http))),Map.entry("bodySha256",VersionMismatchTerminalEvidence.hash(body)),Map.entry("messageSourceSha256",VersionMismatchTerminalEvidence.SSP_MESSAGE_SHA),Map.entry("utilsSourceSha256",VersionMismatchTerminalEvidence.SSP_UTILS_SHA),Map.entry("runtimeBeforeSha256",VersionMismatchTerminalEvidence.hash(runtime)),Map.entry("runtimeAfterSha256",VersionMismatchTerminalEvidence.hash(runtime))));
        String captureId="tx_capture_"+fixture,captureFile=fixture+"-capture.json";Files.write(side.resolve(captureFile),capture);files.add(Map.of("file",captureFile,"sha256",VersionMismatchTerminalEvidence.hash(capture),"size",capture.length));
        bytes.put(captureId,capture);entries.add(new TranscriptEntry(captureId,RUN,Direction.INBOUND,NOW.plusSeconds(4),null,"POST","https://suite.example/paos",204,Map.of(),null,0,"transcripts/"+RUN+"/"+captureId+".saml.xml",capture.length,"application/json",null,Map.of()));
        terminals.add(Map.of("fixtureId",fixture,"requestReference",req.id(),"browserReference",browser.id(),"bodyFile",fixture+"-body.txt","nativeHttpFile",fixture+"-http.json","captureReference",captureId,"captureFile",captureFile));
        var m=Map.ofEntries(Map.entry("schema",VersionMismatchTerminalEvidence.SCHEMA),Map.entry("runId",RUN),Map.entry("caseId",test.id()),Map.entry("terminals",terminals),Map.entry("counterfactualCalibrationOnly",false),Map.entry("targetMetadataSha256",VersionMismatchTerminalEvidence.hash(metadata)),Map.entry("adapter","simplesamlphp-native-message-version"),Map.entry("utilsBeforeFile","utils-before.php"),Map.entry("utilsAfterFile","utils-after.php"),Map.entry("sourceBeforeFile","source-before.php"),Map.entry("sourceAfterFile","source-after.php"),Map.entry("runtimeBeforeFile","runtime-before.json"),Map.entry("runtimeAfterFile","runtime-after.json"),Map.entry("files",files));Files.write(proof.resolve(RUN+".json"),mapper.writeValueAsBytes(m));
    }
}
