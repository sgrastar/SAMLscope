package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

class IdpBasicLogoutScenarioTestCaseTest {
    @TempDir Path directory;
    private static final Instant NOW=Instant.parse("2026-09-15T00:00:00Z");
    private static final String RUN="run_0123456789ABCDEFGHJKMNPQRS",P=SamlLogoutRequestFactory.PROTOCOL,A=SamlLogoutRequestFactory.ASSERTION;
    private static final URI ACS=URI.create("https://suite.example/acs"),SLO=URI.create("https://suite.example/slo");
    private static final String TARGET="https://idp.example",SUITE="https://suite.example";
    private PlanCredentials suite,target,wrong;
    private List<com.samlscope.core.transcript.TranscriptEntry> recorded = List.of();
    private IdpBasicLogoutScenarioTestCase.Configuration configuration;
    @Test void explicitSoapPropagationCollectsSignedSessionIntoDeterministicEnvelopeButNeverConcludesFromFinalResponseAlone() {
        fixture();
        configuration = new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(), URI.create(TARGET + "/SAML2/SOAP/SLO"),
                SLO, TARGET, suite, List.of(target.certificate()));
        var bodies = new HashMap<String, byte[]>();
        var test = IdpBasicLogoutScenarioTestCase.soapPropagation(ignored -> configuration, e -> bodies.get(e.id()));
        var first = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context(true)));
        var next = assertInstanceOf(CaseStep.AwaitInbound.class, test.resume(context(true), first.next(),
                inbound(login(first.next(), "transient", false, false, true, 1), "login")));
        var action = next.actions().getFirst();
        assertEquals(OutboundKind.LOGOUT_PROBE, action.kind()); assertFalse(action.requiresEphemeralCredential());
        var envelope = SecureXml.parse(action.payload()).getDocumentElement();
        assertEquals("http://schemas.xmlsoap.org/soap/envelope/", envelope.getNamespaceURI());
        var request = (Element) envelope.getElementsByTagNameNS(P, "LogoutRequest").item(0);
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(request, suite.certificate()));
        assertEquals(configuration.logoutEndpoint().toString(), request.getAttribute("Destination"));
        assertEquals("_" + action.actionId(), request.getAttribute("ID"));
        var reply = logoutResponse(next.next(), "Success", "none"); bodies.put("actual-soap", reply);
        recorded = List.of(new com.samlscope.core.transcript.TranscriptEntry("actual-soap", RUN,
                com.samlscope.core.transcript.Direction.INBOUND, NOW, action.actionId(), "POST", configuration.logoutEndpoint().toString(), 200,
                Map.of(), "body", 1, "decoded", reply.length, "text/xml", null,
                Map.of("probe_transport", "direct-soap", "saml_message", "LogoutResponse")));
        var result = assertInstanceOf(CaseStep.Finish.class, test.resume(context(true), next.next(),
                inbound("actual-soap".getBytes(StandardCharsets.UTF_8), "actual-soap")));
        assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome());
        assertEquals("slo.propagation.native-chain-pending", result.outcome().reasonCode());
    }
    @Test void soapResponseCannotBorrowForeignWrongTargetUnknownDeliveryOrWrongRecordedContent() {
        fixture(); var bodies = new HashMap<String, byte[]>();
        var test = IdpBasicLogoutScenarioTestCase.soapPropagation(ignored -> configuration, e -> bodies.get(e.id()));
        var first = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context(true)));
        var next = assertInstanceOf(CaseStep.AwaitInbound.class, test.resume(context(true), first.next(),
                inbound(login(first.next(), "transient", false, false, true, 1), "login")));
        var action = next.actions().getFirst(); var reply = logoutResponse(next.next(), "Success", "none"); bodies.put("actual-soap", reply);
        for (var mutation : List.of("foreign-run", "foreign-action", "wrong-target", "unknown-status", "wrong-transport", "wrong-size", "wrong-delivery-bytes")) {
            recorded = List.of(new com.samlscope.core.transcript.TranscriptEntry("actual-soap", mutation.equals("foreign-run") ? "foreign" : RUN,
                    com.samlscope.core.transcript.Direction.INBOUND, NOW, mutation.equals("foreign-action") ? "foreign-action" : action.actionId(),
                    "POST", mutation.equals("wrong-target") ? "https://foreign.example" : configuration.logoutEndpoint().toString(), mutation.equals("unknown-status") ? null : 200,
                    Map.of(), "body", 1, "decoded", mutation.equals("wrong-size") ? reply.length + 1 : reply.length, "text/xml", null,
                    Map.of("probe_transport", mutation.equals("wrong-transport") ? "browser" : "direct-soap", "saml_message", "LogoutResponse")));
            var result = assertInstanceOf(CaseStep.Finish.class, test.resume(context(true), next.next(),
                    inbound((mutation.equals("wrong-delivery-bytes") ? "foreign" : "actual-soap").getBytes(StandardCharsets.UTF_8), "actual-soap")));
            assertEquals(Outcome.NOT_VERIFIED, result.outcome().outcome(), mutation);
            assertNotEquals("slo.propagation.native-chain-pending", result.outcome().reasonCode(), mutation);
        }
    }
    @Test void soapPreparationAndTwoTrialLifecycleRegistersAllFourPeersWithoutEarlyConclusion() {
        fixture(); var bodies = new HashMap<String,byte[]>(); var rows = new ArrayList<com.samlscope.core.transcript.TranscriptEntry>();
        var issuer = "https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS";
        configuration = new IdpBasicLogoutScenarioTestCase.Configuration(new IdpErrorProbeConfiguration(configuration.login().ssoEndpoint(), issuer,
                URI.create(issuer+"/sp/acs/0"),Duration.ofMinutes(5),true,true,true),configuration.logoutEndpoint(),SLO,TARGET,suite,List.of(target.certificate()));
        var recorder = new com.samlscope.core.transcript.TranscriptRecorder() {
            public com.samlscope.core.transcript.TranscriptEntry record(com.samlscope.core.transcript.TranscriptInput in) {
                var id="tx-"+rows.size(); var e=new com.samlscope.core.transcript.TranscriptEntry(id,in.runId(),in.direction(),in.timestamp(),in.correlationId(),in.method(),in.url(),in.status(),in.headers(),id+"body",in.body().length,id+"decoded",in.decodedSaml().length,in.contentType(),in.rawQuery(),in.samlSummary());
                rows.add(e);bodies.put(id,in.decodedSaml());return e;
            }
            public com.samlscope.core.transcript.TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
            public List<com.samlscope.core.transcript.TranscriptEntry> list(String run){return rows;}
        };
        var context=new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        TestCase observer=new TestCase(){public String id(){return SoapSloPropagationTestCase.ID;}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){return new CaseStep.Finish(CaseOutcome.notVerified("missing","missing"));}public CaseStep resume(CaseContext c,CaseState st,CaseEvent ev){return start(c);}};
        var meta=("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='"+TARGET+"'><md:IDPSSODescriptor><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:SOAP' Location='"+TARGET+"/SOAP/SLO'/></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        var test=new SoapSloPropagationTestCase(observer,ignored->configuration,e->bodies.get(e.id())).withTargetMetadata(ignored->meta);
        var step=test.start(context);assertInstanceOf(CaseStep.AwaitConfig.class,step);assertEquals(2,rows.size());
        assertEquals(Set.of("slo-propagation-soap-failure","slo-propagation-soap-all-success"),rows.stream().map(e->e.samlSummary().get("variant")).collect(java.util.stream.Collectors.toSet()));
        var actions=new HashSet<String>();
        for(var trial:List.of("failure","all-success")) {
            var config=assertInstanceOf(CaseStep.AwaitConfig.class,step);
            assertSoapConfigurationProjectsServerInstructions(test, config);
            step=test.resume(context,config.next(),new CaseEvent.ConfigConfirmed());
            for(var participant:List.of("primary","fail","remain","remain2")) {
                var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,step);var action=waiting.actions().getFirst();assertEquals(OutboundKind.AUTHN_REQUEST,action.kind());assertTrue(actions.add(action.actionId()));
                assertEquals(participant.equals("primary"),test.requiresFreshSession(waiting.next()));
                var req=SecureXml.parse(action.payload()).getDocumentElement();assertEquals(issuer+(participant.equals("primary")?"":"/sp-"+participant),req.getElementsByTagNameNS(A,"Issuer").item(0).getTextContent());
                var reply=SecureXml.parse(login(waiting.next(),"transient",false,false,true,1));reply.getDocumentElement().setAttribute("Destination",configuration.login().registeredAcs().toString());var bytes=SecureXml.serialize(reply);
                var tx=recorder.record(new com.samlscope.core.transcript.TranscriptInput(RUN,com.samlscope.core.transcript.Direction.INBOUND,NOW,action.actionId(),"POST",configuration.login().registeredAcs().toString(),200,Map.of(),bytes,"text/xml",null,bytes,Map.of()));
                step=test.resume(context,waiting.next(),inbound(bytes,tx.id()));
            }
            var waiting=assertInstanceOf(CaseStep.AwaitInbound.class,step);var action=waiting.actions().getFirst();assertEquals(OutboundKind.LOGOUT_PROBE,action.kind());assertTrue(actions.add(action.actionId()));assertFalse(test.requiresFreshSession(waiting.next()));
            var reply=SecureXml.parse(logoutResponse(waiting.next(),"Success","unsigned"));reply.getDocumentElement().removeAttribute("Destination");sign(reply.getDocumentElement(),target);var bytes=SecureXml.serialize(reply);
            var tx=recorder.record(new com.samlscope.core.transcript.TranscriptInput(RUN,com.samlscope.core.transcript.Direction.INBOUND,NOW,action.actionId(),"POST",action.target().toString(),200,Map.of(),bytes,"text/xml",null,bytes,Map.of("probe_transport","direct-soap","saml_message","LogoutResponse")));
            step=test.resume(context,waiting.next(),inbound(tx.id().getBytes(StandardCharsets.UTF_8),tx.id()));
        }
        assertEquals(10,actions.size());assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,step).outcome().outcome());
        assertFalse(rows.stream().anyMatch(e->e.samlSummary().containsKey("password")));
    }
    @Test void partialGenericLogoutEvidenceCannotAutomaticallyConfirmNextSoapTrial() {
        fixture();
        var reply = logoutResponse(new CaseState("logout", Map.of("request_id", "_origin")), "Success", "none");
        var factory = new SamlLogoutRequestFactory();
        var origin = factory.sign(factory.build("_origin", configuration.logoutEndpoint(), SUITE,
                parse("<a:NameID xmlns:a='" + A + "'>user</a:NameID>"), List.of("session-0"),
                NOW.minusSeconds(1), null, false), suite);
        recorded = List.of(new com.samlscope.core.transcript.TranscriptEntry("partial-origin", RUN,
                com.samlscope.core.transcript.Direction.OUTBOUND, NOW.minusSeconds(1), "origin", "POST", configuration.logoutEndpoint().toString(), null,
                Map.of(), "origin-body", origin.length, "origin-decoded", origin.length, "text/xml", null, Map.of("type", "LogoutRequest")),
                new com.samlscope.core.transcript.TranscriptEntry("partial-final", RUN,
                com.samlscope.core.transcript.Direction.INBOUND, NOW, "origin", "POST", SLO.toString(), 200,
                Map.of(), "body", reply.length, "decoded", reply.length, "text/xml", null, Map.of("type", "LogoutResponse")));
        var fallback = new BrowserEvidenceTestCase(new AttestedOutcomeTestCase(SoapSloPropagationTestCase.ID,
                TargetRole.IDP, "logout", Duration.ofMinutes(5),
                List.of(AttestationOption.notVerified("unavailable", "slo.unavailable", "unavailable"))),
                URI.create(SUITE), "Collect logout evidence", Duration.ofMinutes(5));
        var observer = new LogoutBrowserEvidenceTestCase(fallback, e -> e.id().equals("partial-origin") ? origin : reply,
                ignored -> Optional.of(TARGET), ignored -> List.of(target.certificate()));
        assertTrue(observer.evidenceStatus(context(true)).ready(), "Reproduce generic partial-evidence readiness");
        var test = new SoapSloPropagationTestCase(observer, ignored -> {
            throw new AssertionError("Partial evidence must not auto-confirm configuration or issue a login");
        }, e -> reply);
        var step = new CaseStep.AwaitConfig(new CaseState("soap-slo-propagation-v1-all-success",
                Map.of("soap_definition", "soap-slo-propagation-v1", "soap_trial", "all-success", "soap_phase", "configure")),
                List.of(), "slo.propagation.soap.apply-prepared-metadata", Duration.ofMinutes(15));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertSoapConfigurationProjectsServerInstructions(test, step);
    }
    private void assertSoapConfigurationProjectsServerInstructions(SoapSloPropagationTestCase test, CaseStep.AwaitConfig step) {
        var execution = new CaseExecution(RUN, test.id(), 0, CaseExecutionStatus.WAITING_CONFIG, step.next(),
                new WaitCondition(WaitCondition.Kind.CONFIG, step.instructionKey(), null, null, NOW.plus(step.ttl())), null, NOW);
        var repository = new CaseExecutionRepository() {
            public Optional<CaseExecution> find(String run, String id) { return Optional.of(execution); }
            public List<CaseExecution> list(String run) { assertEquals(RUN, run); return List.of(execution); }
            public boolean apply(long revision, CaseExecution next, List<OutboundAction> actions) { throw new AssertionError("Projection must not change state or issue actions"); }
            public List<OutboxEntry> listOutbox(String run) { return List.of(); }
            public Optional<OutboxEntry> findOutbox(String id) { return Optional.empty(); }
            public boolean transitionOutbox(String id, OutboxStatus expected, OutboxStatus next,
                    Map<String,Object> result, String ref, Instant at) { throw new AssertionError("Projection must not send"); }
            public int recoverSendingAsUnknownDelivery(Instant at) { throw new AssertionError("Projection must not change delivery"); }
        };
        var pending = new com.samlscope.runner.PendingInteractionService(repository,
                new com.samlscope.runner.TestCaseRegistry(List.of(test))).pending(RUN);
        var registry = new com.samlscope.runner.TestCaseRegistry(List.of(test));
        var automation = new com.samlscope.runner.ProtocolEvidenceAutomationService(repository, registry,
                new com.samlscope.runner.CaseExecutionService(repository), ignored -> context(true));
        assertEquals(0, automation.status(RUN).readyCases());
        assertTrue(automation.evaluateReady(RUN).completed().isEmpty());
        assertSame(execution, repository.find(RUN, test.id()).orElseThrow());
        assertTrue(repository.listOutbox(RUN).isEmpty());
        assertEquals(com.samlscope.runner.InteractionQuery.Kind.CONFIGURATION,
                new com.samlscope.runner.PendingInteractionService(repository, registry).pending(RUN).getFirst().kind());
        assertEquals(1, pending.size());
        var prompt = pending.getFirst();
        assertEquals(com.samlscope.runner.InteractionQuery.Kind.CONFIGURATION, prompt.kind());
        assertEquals(step.instructionKey(), prompt.promptKey());
        assertEquals(test.instructionEn(), prompt.promptEn());
        assertTrue(prompt.promptEn().contains("MetadataPrepared"));
        assertEquals(List.of("confirmed", "capability_absent", "target_config_unavailable", "capability_undetermined"), prompt.answerValues());
        assertEquals(com.samlscope.runner.InteractionQuery.CompletionMode.TRANSCRIPT_OR_OPERATOR, prompt.completionMode());
        assertNull(prompt.startUrl()); assertEquals(NOW.plus(step.ttl()), prompt.expiresAt());
        assertTrue(step.actions().isEmpty()); assertEquals(0, execution.revision());
        assertEquals(CaseExecutionStatus.WAITING_CONFIG, execution.status());
    }
    @Test void soapWrapperCannotRequestLoginWithoutFixedTargetSoapAdvertisementOrBrowserPermission() {
        fixture();TestCase observer=new TestCase(){public String id(){return SoapSloPropagationTestCase.ID;}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){return new CaseStep.Finish(CaseOutcome.notVerified("missing","missing"));}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return start(c);}};
        var test=new SoapSloPropagationTestCase(observer,ignored->configuration,e->new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome().outcome());
        var noSoap=("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' entityID='"+TARGET+"'><md:IDPSSODescriptor/></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.withTargetMetadata(ignored->noSoap).start(context(true))).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.withTargetMetadata(ignored->noSoap).resume(context(true),CaseState.initial(),new CaseEvent.ConfigConfirmed())).outcome().outcome());
    }
    private IdpBasicLogoutScenarioTestCase fixture() {
        if(suite==null) {
            var keys=new FilePlanKeyStore(directory,Clock.fixed(NOW,ZoneOffset.UTC));
            suite=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","suite");
            target=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","target");
            wrong=keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","wrong");
            configuration=new IdpBasicLogoutScenarioTestCase.Configuration(new IdpErrorProbeConfiguration(
                    URI.create(TARGET+"/sso"),SUITE,ACS,Duration.ofMinutes(5),true,true,true),
                    URI.create(TARGET+"/slo"),SLO,TARGET,suite,List.of(target.certificate()));
        }
        return new IdpBasicLogoutScenarioTestCase(ignored->configuration);
    }
    private CaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new com.samlscope.core.transcript.TranscriptRecorder() {
                    public com.samlscope.core.transcript.TranscriptEntry record(com.samlscope.core.transcript.TranscriptInput input) {throw new UnsupportedOperationException();}
                    public com.samlscope.core.transcript.TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) {throw new UnsupportedOperationException();}
                    public List<com.samlscope.core.transcript.TranscriptEntry> list(String run) {return recorded;}
                },complete);
    }
    private CaseEvent.InboundMessage inbound(byte[] xml,String id) { return new CaseEvent.InboundMessage(xml,new EvidenceRef("transcript",id)); }
    private Element parse(String xml) { return SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8)).getDocumentElement(); }
    private void sign(Element root,PlanCredentials keys) {
        Element before=null;
        for(var n=root.getFirstChild();n!=null;n=n.getNextSibling())
            if(n instanceof Element e && !"Issuer".equals(e.getLocalName())) {before=e;break;}
        new XmlSigner().sign(root,keys,before);
    }
    private Element response(CaseState state,String type,String destination,String status,String content) {
        return parse("<p:"+type+" xmlns:p='"+P+"' xmlns:a='"+A+"' ID='_response' Version='2.0' IssueInstant='"+NOW
                +"' Destination='"+destination+"' InResponseTo='"+state.data().get("request_id")+"'><a:Issuer>"+TARGET+"</a:Issuer>"
                +"<p:Status><p:StatusCode Value='"+"urn:oasis:names:tc:SAML:2.0:status:"+status+"'/></p:Status>"+content+"</p:"+type+">");
    }
    private byte[] login(CaseState state,String format,boolean encryptedAssertion,boolean encryptedName,boolean signAssertion,int indexes) {
        var assertion=parse("<a:Assertion xmlns:a='"+A+"' ID='_assertion' Version='2.0' IssueInstant='"+NOW+"'><a:Issuer>"+TARGET
                +"</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:"+format+"' NameQualifier='"+TARGET
                +"' SPNameQualifier='"+SUITE+"'> user-😀 </a:NameID></a:Subject>"
                +java.util.stream.IntStream.range(0,indexes).mapToObj(i->"<a:AuthnStatement AuthnInstant='"+NOW+"' SessionIndex='session-"+i
                +"'><a:AuthnContext><a:AuthnContextClassRef>urn:password</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>").collect(java.util.stream.Collectors.joining())
                +"</a:Assertion>");
        var encryption=new SamlEncryptionFixtureFactory();var algorithms=SamlEncryptionFixtureFactory.matrix().getFirst();
        if(encryptedName) {
            var name=(Element)assertion.getElementsByTagNameNS(A,"NameID").item(0);
            var encrypted=encryption.encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedID,name,suite.certificate().getPublicKey(),algorithms);
            name.getParentNode().replaceChild(assertion.getOwnerDocument().importNode(encrypted,true),name);
        }
        if(signAssertion)sign(assertion,target);
        var root=response(state,"Response",ACS.toString(),"Success","");
        var child=encryptedAssertion ? encryption.encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,assertion,suite.certificate().getPublicKey(),algorithms) : assertion;
        root.appendChild(root.getOwnerDocument().importNode(child,true));
        if(!signAssertion)sign(root,target);
        return SecureXml.serialize(root.getOwnerDocument());
    }
    private byte[] logoutResponse(CaseState state,String status,String mutation) {
        var root=response(state,"LogoutResponse",SLO.toString(),status,"");
        if(mutation.equals("destination"))root.setAttribute("Destination","https://other.example/slo");
        if(mutation.equals("correlation"))root.setAttribute("InResponseTo","_other");
        if(mutation.equals("issuer"))root.getElementsByTagNameNS(A,"Issuer").item(0).setTextContent("https://other.example");
        if(!mutation.equals("unsigned"))sign(root,mutation.equals("wrong-key") ? wrong : target);
        if(mutation.equals("tampered"))root.setAttribute("Destination","https://tampered.example");
        return SecureXml.serialize(root.getOwnerDocument());
    }
    @Test void authenticatedSessionMatrixProducesSignedSynchronousLogoutAndPreservesIssuedIdentity() {
        var test=fixture();
        for(var format:List.of("persistent","transient","unspecified"))for(var encryptedAssertion:List.of(false,true))
        for(var encryptedName:List.of(false,true))for(var assertionSignature:List.of(false,true))for(var indexes:List.of(1,2)) {
            var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
            assertTrue(test.requiresFreshSession(first.next()));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(first.actions().getFirst().payload()).getDocumentElement(),suite.certificate()));
            var next=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),
                    inbound(login(first.next(),format,encryptedAssertion,encryptedName,assertionSignature,indexes),"login")));
            assertFalse(test.requiresFreshSession(next.next()));
            var action=next.actions().getFirst();assertEquals(OutboundKind.LOGOUT_REQUEST,action.kind());
            var xml=SecureXml.parse(action.payload()).getDocumentElement();
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,suite.certificate()));
            assertTrue(SamlSchemaValidation.isValid(xml,SamlSchemaValidation.SchemaKind.PROTOCOL));
            assertEquals(" user-😀 ",xml.getElementsByTagNameNS(A,"NameID").item(0).getTextContent());
            assertEquals(indexes,xml.getElementsByTagNameNS(P,"SessionIndex").getLength());
            assertEquals(0,xml.getElementsByTagNameNS(SamlLogoutRequestFactory.ASYNC,"Asynchronous").getLength());
            assertFalse(next.next().data().toString().contains("user-😀"));
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),inbound(logoutResponse(next.next(),"Success","none"),"logout")));
            assertEquals(Outcome.SATISFIED,result.outcome().outcome());
            assertEquals(List.of(new EvidenceRef("transcript","login"),new EvidenceRef("transcript","logout")),result.outcome().evidence());
        }
    }
    @Test void redirectReceiverMatrixForcesRedirectWithoutChangingSessionControls() {
        fixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT);
        var test=new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.REDIRECT_ID,ignored->configuration);
        for(var format:List.of("persistent","transient","unspecified"))for(var encryptedAssertion:List.of(false,true))
        for(var encryptedName:List.of(false,true))for(var assertionSignature:List.of(false,true))for(var indexes:List.of(1,2)) {
            var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
            assertTrue(test.requiresFreshSession(first.next()));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(first.actions().getFirst().payload()).getDocumentElement(),suite.certificate()));
            var next=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),
                    inbound(login(first.next(),format,encryptedAssertion,encryptedName,assertionSignature,indexes),"login")));
            assertFalse(test.requiresFreshSession(next.next()));
            assertEquals(com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT,test.outboundBinding(next.next()));
            var action=next.actions().getFirst();assertEquals(OutboundKind.LOGOUT_REQUEST,action.kind());
            var xml=SecureXml.parse(action.payload()).getDocumentElement();
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml,suite.certificate()));
            assertTrue(SamlSchemaValidation.isValid(xml,SamlSchemaValidation.SchemaKind.PROTOCOL));
            assertEquals(" user-😀 ",xml.getElementsByTagNameNS(A,"NameID").item(0).getTextContent());
            assertEquals(indexes,xml.getElementsByTagNameNS(P,"SessionIndex").getLength());
            assertEquals(0,xml.getElementsByTagNameNS(SamlLogoutRequestFactory.ASYNC,"Asynchronous").getLength());
            assertFalse(next.next().data().toString().contains("user-😀"));
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),inbound(logoutResponse(next.next(),"Success","none"),"logout")));
            assertEquals(Outcome.SATISFIED,result.outcome().outcome());
            assertEquals(List.of(new EvidenceRef("transcript","login"),new EvidenceRef("transcript","logout")),result.outcome().evidence());
        }
    }
    @Test void explicitErrorsAreNotConfusedWithSessionTerminationAndUnknownDeliveryNeverFailsTheProduct() {
        var test=fixture();var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        var next=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),inbound(login(first.next(),"persistent",false,false,false,1),"login")));
        for(var status:List.of("Success","Responder","Requester","VersionMismatch"))for(var mutation:List.of("none","destination","correlation","issuer","unsigned","wrong-key","tampered")) {
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),inbound(logoutResponse(next.next(),status,mutation),"logout")));
            var expected=switch(mutation) {case "none"->Outcome.SATISFIED;case "destination","correlation"->Outcome.VIOLATED;default->Outcome.NOT_VERIFIED;};
            assertEquals(expected,result.outcome().outcome(),status+":"+mutation);
        }
        for(var state:List.of(first.next(),next.next()))for(CaseEvent event:List.of(new CaseEvent.Aborted("terminal page"),new CaseEvent.TimedOut(Duration.ofMinutes(5)),new CaseEvent.InboundUnavailable("unknown delivery")))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),state,event)).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(false),next.next(),inbound(logoutResponse(next.next(),"Success","none"),"logout"))).outcome().outcome());
    }
    @Test void missingSessionAndControlEvidenceCannotProduceALogoutRequest() {
        var test=fixture();var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),first.next(),inbound(login(first.next(),"persistent",false,false,false,0),"control"))).outcome().outcome());
        for(var mutation:List.of("wrong-correlation","wrong-destination","wrong-key","malformed")) {
            var xml=SecureXml.parse(login(first.next(),"persistent",false,false,false,1)).getDocumentElement();
            if(mutation.equals("wrong-correlation"))xml.setAttribute("InResponseTo","_other");
            if(mutation.equals("wrong-destination"))xml.setAttribute("Destination","https://other.example/acs");
            if(mutation.equals("wrong-key"))xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0).setTextContent("AAAA");
            var bytes=mutation.equals("malformed") ? "<invalid".getBytes(StandardCharsets.UTF_8) : SecureXml.serialize(xml.getOwnerDocument());
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),first.next(),inbound(bytes,"control"))).outcome().outcome());
        }
        var original=configuration;
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(original.login(),null,SLO,TARGET,suite,original.targetSigningCertificates());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome().outcome());
    }

    @Test void redirectReceiverStatusAndSignatureControlsAreSeparateFromBasicResponseExistence() {
        fixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT);
        var test=new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.REDIRECT_ID,ignored->configuration);
        var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        var second=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),
                inbound(login(first.next(),"persistent",false,false,false,1),"login")));
        for(var status:List.of("Success","Requester","Responder","VersionMismatch"))
        for(var mutation:List.of("none","destination","correlation","issuer","unsigned","wrong-key","tampered")) {
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),second.next(),
                    inbound(logoutResponse(second.next(),status,mutation),"response"))).outcome();
            var expected=List.of("issuer","unsigned","wrong-key","tampered").contains(mutation)?Outcome.NOT_VERIFIED
                    : !mutation.equals("none") || !status.equals("Success")?Outcome.VIOLATED:Outcome.SATISFIED;
            assertEquals(expected,result.outcome(),status+"/"+mutation);
        }
        var basic=fixture();var basicFirst=assertInstanceOf(CaseStep.AwaitInbound.class,basic.start(context(true)));
        assertNotEquals(first.actions().getFirst().actionId(),basicFirst.actions().getFirst().actionId());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,
                basic.resume(context(true),second.next(),inbound(logoutResponse(second.next(),"Success","none"),"cross-case"))).outcome().outcome());
    }

    @Test void redirectReceiverDoesNotSubstitutePostWhenRedirectConfigurationIsUnavailable() {
        fixture();var test=new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.REDIRECT_ID,ignored->configuration);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome().outcome());
        assertThrows(IllegalArgumentException.class,()->new IdpBasicLogoutScenarioTestCase("unapproved",ignored->configuration));
    }

    private IdpBasicLogoutScenarioTestCase encryptedFixture() {
        fixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                com.samlscope.runner.BrowserFrontChannelScenario.Binding.HTTP_POST,target.certificate().getPublicKey());
        return new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,ignored->configuration);
    }

    @Test void encryptedIdentifierMatrixRequiresWrongKeyRejectionBeforeFreshValidKeyProbe() {
        for (var caseId : List.of(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID, IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID)) {
        encryptedFixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                configuration.logoutBinding(),target.certificate().getPublicKey(),List.of(target.certificate().getPublicKey(),wrong.certificate().getPublicKey()));
        var test=new IdpBasicLogoutScenarioTestCase(caseId,ignored->configuration);
        var recipient=caseId.equals(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID)?wrong:target;
        for(var format:List.of("persistent","transient","unspecified"))for(var encryptedAssertion:List.of(false,true))
        for(var encryptedName:List.of(false,true))for(var assertionSignature:List.of(false,true))for(var indexes:List.of(1,2)) {
            var controlLogin=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
            assertTrue(test.requiresFreshSession(controlLogin.next()));
            var control=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),controlLogin.next(),
                    inbound(login(controlLogin.next(),format,encryptedAssertion,encryptedName,assertionSignature,indexes),"control-login")));
            var badRoot=SecureXml.parse(control.actions().getFirst().payload()).getDocumentElement();
            var badIdentifier=(Element)badRoot.getElementsByTagNameNS(A,"EncryptedID").item(0);
            assertNotNull(badIdentifier);
            assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(badIdentifier,target.privateKey()));
            assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(badIdentifier,wrong.privateKey()));
            assertEquals(" user-😀 ",new SamlXmlDecrypter().decrypt(badIdentifier,suite.privateKey()).getTextContent());
            var fresh=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),control.next(),
                    inbound(logoutResponse(control.next(),"Requester","none"),"key-rejection")));
            assertTrue(test.requiresFreshSession(fresh.next()));
            assertNotEquals(fresh.actions().getFirst().actionId(),controlLogin.actions().getFirst().actionId());
            var valid=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),fresh.next(),
                    inbound(login(fresh.next(),format,encryptedAssertion,encryptedName,assertionSignature,indexes),"valid-login")));
            var root=SecureXml.parse(valid.actions().getFirst().payload()).getDocumentElement();
            assertEquals(0,root.getElementsByTagNameNS(A,"NameID").getLength());
            var encrypted=(Element)root.getElementsByTagNameNS(A,"EncryptedID").item(0);
            assertEquals(" user-😀 ",new SamlXmlDecrypter().decrypt(encrypted,recipient.privateKey()).getTextContent());
            assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(encrypted,suite.privateKey()));
            if (recipient==wrong) assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(encrypted,target.privateKey()));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,suite.certificate()));
            assertTrue(SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.PROTOCOL));
            assertFalse(valid.next().data().toString().contains("user-😀"));
            for(var status:List.of("Success","Requester","Responder","VersionMismatch")) {
                var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),valid.next(),
                        inbound(logoutResponse(valid.next(),status,"none"),"decrypted"))).outcome();
                assertEquals(status.equals("Success")?Outcome.SATISFIED:Outcome.VIOLATED,result.outcome());
                assertEquals(4,result.evidence().size());
            }
        }
        }
    }

    @Test void encryptedIdentifierCannotPassOnBlindAcceptanceOrUnverifiableControl() {
        for (var caseId : List.of(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID, IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID)) {
        encryptedFixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                configuration.logoutBinding(),target.certificate().getPublicKey(),List.of(target.certificate().getPublicKey(),wrong.certificate().getPublicKey()));
        var test=new IdpBasicLogoutScenarioTestCase(caseId,ignored->configuration);var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        var next=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),inbound(login(first.next(),"persistent",false,false,false,1),"login")));
        for(var mutation:List.of("destination","correlation","issuer","unsigned","wrong-key","tampered")) {
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),
                    inbound(logoutResponse(next.next(),"Success",mutation),"control"))).outcome();
            assertEquals(Outcome.NOT_VERIFIED,result.outcome(),mutation);
        }
        var fresh=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),next.next(),
                inbound(logoutResponse(next.next(),"Success","none"),"accepted-unknown-key")));
        assertTrue(test.requiresFreshSession(fresh.next()));
        assertEquals(Boolean.TRUE,fresh.next().data().get("negative_control_failed"));
        var normal=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),fresh.next(),
                inbound(login(fresh.next(),"persistent",false,false,false,1),"registered-key-login")));
        assertEquals(Boolean.TRUE,normal.next().data().get("negative_control_failed"));
        var normalRequest=SecureXml.parse(normal.actions().getFirst().payload()).getDocumentElement();
        var encrypted=(Element)normalRequest.getElementsByTagNameNS(A,"EncryptedID").item(0);
        var recipient=caseId.equals(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID)?wrong:target;
        assertEquals(" user-😀 ",new SamlXmlDecrypter().decrypt(encrypted,recipient.privateKey()).getTextContent());
        assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(encrypted,suite.privateKey()));
        for(String status:List.of("Success","Requester","Responder")) {
            var outcome=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),normal.next(),
                    inbound(logoutResponse(normal.next(),status,"none"),"registered-key-result"))).outcome();
            assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());
            assertTrue(outcome.reasonCode().endsWith("negative-control-failed"));
            assertEquals(Boolean.TRUE,outcome.details().get("negative_control_failed"));
            assertEquals(4,outcome.evidence().size());
        }
        for(var event:List.<CaseEvent>of(new CaseEvent.Aborted("stopped"),new CaseEvent.TimedOut(Duration.ofSeconds(1)),new CaseEvent.InboundUnavailable("no response")))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),event)).outcome().outcome());
        }
    }

    @Test void legacyEncryptedScenarioStateCannotContinueUnderTheNewDefinition() {
        var test=encryptedFixture();var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        var old=new LinkedHashMap<String,Object>(first.next().data());old.put("definition","slo-basic-v5");
        var outcome=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),
                new CaseState("slo-basic-v5-login-control",old),inbound(login(first.next(),"transient",false,false,false,1),"legacy"))).outcome();
        assertEquals(Outcome.NOT_VERIFIED,outcome.outcome());assertEquals("slo.basic.scenario-changed",outcome.reasonCode());
    }

    @Test void multipleKeysRequireDistinctRegisteredRecipientsAndExcludeControlKey() {
        encryptedFixture();
        for (var keys : List.of(List.<java.security.PublicKey>of(), List.of(target.certificate().getPublicKey()),
                List.of(target.certificate().getPublicKey(),target.certificate().getPublicKey()),
                List.of(target.certificate().getPublicKey(),suite.certificate().getPublicKey()),
                List.of(suite.certificate().getPublicKey(),target.certificate().getPublicKey()))) {
            configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                    configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                    configuration.logoutBinding(),target.certificate().getPublicKey(),keys);
            var test=new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID,ignored->configuration);
            var result=assertInstanceOf(CaseStep.Finish.class,test.start(context(true))).outcome();
            assertEquals(Outcome.NOT_VERIFIED,result.outcome());
            assertEquals("slo.encrypted-id.multiple-keys.configuration-unavailable",result.reasonCode());
        }
    }

    @Test void effectiveEncryptionKeysChooseTheRegisteredRecipientAndReportTheirSource() throws Exception {
        record Scenario(String caseId,List<java.security.PublicKey> published,List<java.security.PublicKey> effective,
                PlanCredentials recipient,String source) {}
        fixture();
        var targetKey=target.certificate().getPublicKey();var wrongKey=wrong.certificate().getPublicKey();
        var suiteKey=suite.certificate().getPublicKey();
        var scenarios=List.of(
                new Scenario(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,List.of(targetKey),List.of(targetKey,wrongKey),target,"published-metadata"),
                new Scenario(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,List.of(),List.of(targetKey),target,"supplemental-input"),
                new Scenario(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,List.of(targetKey),List.of(suiteKey,targetKey),target,"published-metadata"),
                new Scenario(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID,List.of(targetKey),List.of(targetKey,wrongKey),wrong,"supplemental-input"),
                new Scenario(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID,List.of(targetKey,wrongKey),List.of(targetKey,wrongKey),wrong,"published-metadata"));
        for(var scenario:scenarios) {
            configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                    configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                    com.samlscope.runner.BrowserFrontChannelScenario.Binding.HTTP_POST,targetKey,
                    scenario.effective(),scenario.published());
            var test=new IdpBasicLogoutScenarioTestCase(scenario.caseId(),ignored->configuration);
            var controlLogin=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
            var control=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),controlLogin.next(),
                    inbound(login(controlLogin.next(),"persistent",false,false,false,1),"control-login")));
            var bad=(Element)SecureXml.parse(control.actions().getFirst().payload()).getDocumentElement()
                    .getElementsByTagNameNS(A,"EncryptedID").item(0);
            assertEquals(" user-😀 ",new SamlXmlDecrypter().decrypt(bad,suite.privateKey()).getTextContent());
            var fresh=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),control.next(),
                    inbound(logoutResponse(control.next(),"Requester","none"),"key-rejection")));
            var valid=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),fresh.next(),
                    inbound(login(fresh.next(),"persistent",false,false,false,1),"valid-login")));
            var encrypted=(Element)SecureXml.parse(valid.actions().getFirst().payload()).getDocumentElement()
                    .getElementsByTagNameNS(A,"EncryptedID").item(0);
            assertEquals(" user-😀 ",new SamlXmlDecrypter().decrypt(encrypted,scenario.recipient().privateKey()).getTextContent());
            assertThrows(RuntimeException.class,()->new SamlXmlDecrypter().decrypt(encrypted,suite.privateKey()));
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),valid.next(),
                    inbound(logoutResponse(valid.next(),"Success","none"),"decrypted"))).outcome();
            assertEquals(Outcome.SATISFIED,result.outcome());
            assertEquals(4,result.evidence().size());
            assertEquals(List.of(scenario.source()),result.details().get("decryption_key_source"));
        }
    }

    @Test void rejectedEncryptedIdentifierStillReportsWhichFixedInputSuppliedTheKey() {
        var test=encryptedFixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                configuration.logoutBinding(),target.certificate().getPublicKey(),List.of(target.certificate().getPublicKey()),
                List.of());
        test=new IdpBasicLogoutScenarioTestCase(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID,ignored->configuration);
        var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        var second=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),
                inbound(login(first.next(),"persistent",false,false,false,1),"control-login")));
        var third=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),second.next(),
                inbound(logoutResponse(second.next(),"Requester","none"),"rejected-control")));
        var fourth=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),third.next(),
                inbound(login(third.next(),"persistent",false,false,false,1),"login")));
        var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),fourth.next(),
                inbound(logoutResponse(fourth.next(),"Requester","none"),"rejected"))).outcome();
        assertEquals(Outcome.VIOLATED,result.outcome());
        assertEquals(List.of("supplemental-input"),result.details().get("decryption_key_source"));
    }

    @Test void redirectResponseTrustRequiresTheSameRecordedInboundMessage() {
        var test=fixture();
        for(var status:List.of("Success","Requester","Responder","VersionMismatch"))
        for(var fault:List.of("none","different-xml","different-run","outbound","post","bad-signature","wrong-key","duplicate-entry","missing-entry","missing-query")) {
            recorded=List.of();
            var login=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
            var logout=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),login.next(),
                    inbound(login(login.next(),"persistent",false,false,false,1),"login-evidence")));
            var encoded=new com.samlscope.saml.binding.SignedRedirectEncoder().encode(SLO,
                    logoutResponse(logout.next(),status,"none"),"relay",fault.equals("wrong-key")?wrong:target);
            var query=encoded.rawQuery();
            if(fault.equals("bad-signature"))query=query.replace("Signature=","Signature=x");
            if(fault.equals("missing-query"))query=null;
            var xml=encoded.decodedXml();
            if(fault.equals("different-xml"))xml=new String(xml,StandardCharsets.UTF_8).replace("_response","_different").getBytes(StandardCharsets.UTF_8);
            var entry=new com.samlscope.core.transcript.TranscriptEntry("tx-redirect",fault.equals("different-run")?"other":RUN,
                    fault.equals("outbound")?com.samlscope.core.transcript.Direction.OUTBOUND:com.samlscope.core.transcript.Direction.INBOUND,
                    NOW,"correlation",fault.equals("post")?"POST":"GET",SLO.toString(),200,Map.of(),null,0,"decoded",xml.length,null,query,Map.of());
            recorded=fault.equals("missing-entry")?List.of():fault.equals("duplicate-entry")?List.of(entry,entry):List.of(entry);
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),logout.next(),inbound(xml,"tx-redirect"))).outcome();
            assertEquals(fault.equals("none")?Outcome.SATISFIED:Outcome.NOT_VERIFIED,result.outcome(),status+"/"+fault);
        }
    }

    @Test void logoutBindingIsPersistedWithoutChangingTheLoginTransport() {
        var test=fixture();
        configuration=new IdpBasicLogoutScenarioTestCase.Configuration(configuration.login(),configuration.logoutEndpoint(),
                configuration.suiteLogoutEndpoint(),configuration.targetIssuer(),suite,List.of(target.certificate()),
                com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT);
        var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        assertEquals(com.samlscope.runner.BrowserFrontChannelScenario.Binding.HTTP_POST,test.outboundBinding(first.next()));
        var second=assertInstanceOf(CaseStep.AwaitInbound.class,test.resume(context(true),first.next(),
                inbound(login(first.next(),"persistent",false,false,false,1),"control")));
        assertEquals(com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT,test.outboundBinding(second.next()));
    }

    @Test void authenticButInvalidControlStructureAndVersionAreNotSessionEvidence() {
        var test=fixture();var first=assertInstanceOf(CaseStep.AwaitInbound.class,test.start(context(true)));
        for(var mutation:List.of("version","encrypted-structure","incorrect-status-namespace","error-status")) {
            var root=SecureXml.parse(login(first.next(),"persistent",false,false,false,1)).getDocumentElement();
            var signature=root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature").item(0);
            root.removeChild(signature);
            if(mutation.equals("version"))root.setAttribute("Version","3.0");
            else if(mutation.equals("incorrect-status-namespace") || mutation.equals("error-status")) {
                ((Element)root.getElementsByTagNameNS(P,"StatusCode").item(0)).setAttribute("Value",
                        mutation.equals("incorrect-status-namespace") ? P+":status:Success" : "urn:oasis:names:tc:SAML:2.0:status:Responder");
            } else {
                var assertion=(Element)root.getElementsByTagNameNS(A,"Assertion").item(0);assertion.removeAttribute("Version");
                var encrypted=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,
                        assertion,suite.certificate().getPublicKey(),SamlEncryptionFixtureFactory.matrix().getFirst());
                root.replaceChild(root.getOwnerDocument().importNode(encrypted,true),assertion);
            }
            sign(root,target);
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),first.next(),
                    inbound(SecureXml.serialize(root.getOwnerDocument()),"invalid-control"))).outcome().outcome(),mutation);
        }
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.start(context(false))).outcome().outcome());
    }
}
