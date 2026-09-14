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
        for(var mutation:List.of("none","destination","correlation","issuer","unsigned","wrong-key","tampered")) {
            var result=assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),
                    inbound(logoutResponse(next.next(),"Success",mutation),"control"))).outcome();
            assertEquals(Outcome.NOT_VERIFIED,result.outcome(),mutation);
        }
        for(var event:List.<CaseEvent>of(new CaseEvent.Aborted("stopped"),new CaseEvent.TimedOut(Duration.ofSeconds(1)),new CaseEvent.InboundUnavailable("no response")))
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),next.next(),event)).outcome().outcome());
        }
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
