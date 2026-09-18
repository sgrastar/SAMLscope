package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class AttributeNameConfigurationTestCaseTest {
    @TempDir java.nio.file.Path directory;
    private static final String RUN="run_test",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private final List<TranscriptEntry> entries=new ArrayList<>();private final Map<String,byte[]> bodies=new HashMap<>();
    private byte[] metadata;private PlanCredentials key;
    private void fixture(boolean urn,boolean arbitrary,boolean unknown,boolean encrypted) throws Exception {
        entries.clear();bodies.clear();
        key=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        metadata=("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://idp.example'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        var request=("<p:AuthnRequest xmlns:p='"+P+"' ID='_request' AssertionConsumerServiceURL='https://suite.example/acs'/>").getBytes(StandardCharsets.UTF_8);
        add("request",Direction.OUTBOUND,"https://idp.example/sso",request,Map.of("type","AuthnRequest"));
        String format=unknown?AttributeNameConfigurationTestCase.CUSTOM_FORMAT:"urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
        var assertion=SecureXml.parse(("<s:Assertion xmlns:s='"+S+"' ID='_assertion'><s:Issuer>https://idp.example</s:Issuer><s:AttributeStatement>"+
                (urn?"<s:Attribute Name='"+AttributeNameConfigurationTestCase.URN_NAME+"' NameFormat='"+format+"'/>":"")+
                (arbitrary?"<s:Attribute Name='"+AttributeNameConfigurationTestCase.STRING_NAME+"' NameFormat='"+format+"'/>":"")+"</s:AttributeStatement></s:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        var response=SecureXml.parse(("<p:Response xmlns:p='"+P+"' xmlns:s='"+S+"' ID='_response' InResponseTo='_request' Destination='https://suite.example/acs'><s:Issuer>https://idp.example</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:Response>").getBytes(StandardCharsets.UTF_8));
        if(encrypted){
            new XmlSigner().sign(assertion,key,null);
            assertion=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,assertion,key.certificate().getPublicKey(),new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,SamlEncryptionFixtureFactory.Digest.SHA256,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
        }
        var root=response.getDocumentElement();root.appendChild(response.importNode(assertion,true));new XmlSigner().sign(root,key,null);
        add("response",Direction.INBOUND,"https://suite.example/acs",SecureXml.serialize(response),Map.of("type","Response","normalFlowAccepted",true));
    }
    private void add(String id,Direction direction,String url,byte[] body,Map<String,Object> summary){
        bodies.put(id,body);entries.add(new TranscriptEntry(id,RUN,direction,Instant.EPOCH.plusSeconds(entries.size()),null,"POST",url,200,Map.of(),null,0,id,body.length,null,null,summary));
    }
    private CaseContext context(boolean complete){
        var recorder=new TranscriptRecorder(){
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}
            public List<TranscriptEntry> list(String run){return entries;}
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    private AttributeNameConfigurationTestCase testCase(){
        var fallback=new ConfigurationGateTestCase(new InformationalChoiceTestCase(AttributeNameConfigurationTestCase.ID,TargetRole.IDP),"input","Prepare attributes",Duration.ofHours(1),ConfigurationFailureSemantics.TEST_PRECONDITION);
        return new AttributeNameConfigurationTestCase(fallback,e->bodies.get(e.decodedSamlRef()),run->metadata,run->Optional.of(key.privateKey()));
    }
    @Test void plainAndEncryptedAssertionsRequireAllApprovedVariants() throws Exception {
        for(boolean encrypted:List.of(false,true)){
            fixture(true,true,true,encrypted);assertEquals(Outcome.SATISFIED,testCase().observe(context(true)).outcome());
            fixture(false,true,true,encrypted);assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(true)).outcome());
            fixture(true,false,true,encrypted);assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(true)).outcome());
            fixture(true,true,false,encrypted);assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(true)).outcome());
        }
    }
    @Test void preparationConfirmationDoesNotManufactureCapability() throws Exception {
        fixture(true,true,false,false);var test=testCase();var awaiting=assertInstanceOf(CaseStep.AwaitConfig.class,test.start(context(true)));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test.resume(context(true),awaiting.next(),new CaseEvent.ConfigConfirmed())).outcome().outcome());
    }
    @Test void signatureCorrelationAndHistoryFailuresRemainUnverified() throws Exception {
        fixture(true,true,true,false);assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(false)).outcome());
        var original=bodies.get("response");
        for(var pair:List.of(List.of("https://idp.example","https://attacker.example"),List.of("InResponseTo=\"_request\"","InResponseTo=\"_other\""),List.of("https://suite.example/acs","https://other.example/acs"))){
            bodies.put("response",new String(original,StandardCharsets.UTF_8).replace(pair.get(0),pair.get(1)).getBytes(StandardCharsets.UTF_8));
            assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(true)).outcome());
        }
        bodies.put("response",original);entries.add(entries.getFirst());
        assertEquals(Outcome.NOT_VERIFIED,testCase().observe(context(true)).outcome());
    }
}
