package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class MetadataAlgorithmEvidenceTest {
    @TempDir java.nio.file.Path directory;
    private static final String RUN="run_test", MD="urn:oasis:names:tc:SAML:2.0:metadata", S="urn:oasis:names:tc:SAML:2.0:assertion", P="urn:oasis:names:tc:SAML:2.0:protocol";
    private final List<TranscriptEntry> entries=new ArrayList<>();private final Map<String,byte[]> bodies=new HashMap<>();
    private byte[] target;
    private PlanCredentials cryptoKey;
    private void fixture(boolean ignoreRole) throws Exception { fixture(ignoreRole,false); }
    private void fixture(boolean ignoreRole,boolean encrypted) throws Exception {
        var key=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        cryptoKey=key;
        String encryptionKey=encrypted?"<md:KeyDescriptor use='encryption'><ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>":"";
        target=("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://idp.example'><md:IDPSSODescriptor protocolSupportEnumeration='"+P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        for(var variant:MetadataAlgorithmSelection.required(MetadataAlgorithmSelection.ROLE)) {
            var input=MetadataAlgorithmSelection.INPUTS.get(variant);var destination="https://suite.example/acs?mdv="+variant+"&run="+RUN;
            var xmlDestination=destination.replace("&","&amp;");var requestId="_"+variant;
            var metadata=("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:alg='urn:oasis:names:tc:SAML:metadata:algsupport' entityID='https://suite.example/entity'>"+extensions(input.entity())+"<md:SPSSODescriptor protocolSupportEnumeration='"+P+"'>"+extensions(input.role())+encryptionKey+"<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+xmlDestination+"' index='0'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
            String fetch="fetch-"+variant;
            add(fetch,Direction.INBOUND,"https://suite.example/metadata",null,null,Map.of("type","MetadataFetch","variant",variant));
            add("prepared-"+variant,Direction.OUTBOUND,"https://suite.example/metadata",fetch,metadata,Map.of("type","MetadataPrepared","variant",variant,"delivery","PREPARED","fetchTranscriptId",fetch,"metadataSha256",HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(metadata))));
            byte[] request=("<p:AuthnRequest xmlns:p='"+P+"' xmlns:s='"+S+"' ID='"+requestId+"' AssertionConsumerServiceURL='"+xmlDestination+"'><s:Issuer>https://suite.example/entity</s:Issuer></p:AuthnRequest>").getBytes(StandardCharsets.UTF_8);
            add("request-"+variant,Direction.OUTBOUND,"https://idp.example/sso",null,request,Map.of("type","AuthnRequest","variant",variant,"metadataSignatureControl","valid","metadataSignatureGroup","poll_test:"+entries.size()));
            var doc=SecureXml.parse(("<p:Response xmlns:p='"+P+"' xmlns:s='"+S+"' ID='_response_"+variant+"' InResponseTo='"+requestId+"' Destination='"+xmlDestination+"'><s:Issuer>https://idp.example</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:Response>").getBytes(StandardCharsets.UTF_8));
            var root=doc.getDocumentElement();root.setIdAttribute("ID",true);
            if(encrypted) {
                var plain=SecureXml.parse(("<s:Assertion xmlns:s='"+S+"'><s:Issuer>https://idp.example</s:Issuer></s:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
                var wrapper=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,plain,key.certificate().getPublicKey(),
                        new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES256_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,SamlEncryptionFixtureFactory.Digest.SHA256,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
                root.appendChild(doc.importNode(wrapper,true));
            }
            var ds=input.role().digests().isEmpty() || ignoreRole?input.entity().digests():input.role().digests();
            var ss=input.role().signatures().isEmpty() || ignoreRole?input.entity().signatures():input.role().signatures();
            var factory=XMLSignatureFactory.getInstance("DOM");
            var reference=factory.newReference("#"+root.getAttribute("ID"),factory.newDigestMethod(ds.isEmpty()?MetadataAlgorithmSelection.D256:ds.getFirst(),null),List.of(factory.newTransform(Transform.ENVELOPED,(TransformParameterSpec)null),factory.newTransform(CanonicalizationMethod.EXCLUSIVE,(TransformParameterSpec)null)),null,null);
            var info=factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,(C14NMethodParameterSpec)null),factory.newSignatureMethod(ss.isEmpty()?MetadataAlgorithmSelection.S256:ss.getFirst(),null),List.of(reference));
            factory.newXMLSignature(info,null).sign(new DOMSignContext(key.privateKey(),root));
            add("response-"+variant,Direction.INBOUND,destination,requestId,SecureXml.serialize(doc),Map.of("type","Response","metadataProbeAccepted",true));
        }
    }
    private String extensions(MetadataAlgorithmSelection.Methods methods) {
        if(methods.digests().isEmpty() && methods.signatures().isEmpty())return "";
        var xml=new StringBuilder("<md:Extensions>");for(var d:methods.digests())xml.append("<alg:DigestMethod Algorithm='").append(d).append("'/>");for(var s:methods.signatures())xml.append("<alg:SigningMethod Algorithm='").append(s).append("'/>");return xml.append("</md:Extensions>").toString();
    }
    private void add(String id,Direction direction,String url,String correlation,byte[] body,Map<String,Object> summary) {
        if(body!=null)bodies.put(id,body);
        entries.add(new TranscriptEntry(id,RUN,direction,Instant.EPOCH.plusSeconds(entries.size()),correlation,"GET",url,200,Map.of(),null,0,body==null?null:id,body==null?0:body.length,null,null,summary));
    }
    private com.samlscope.core.caseexec.CaseContext context() {
        var recorder=new TranscriptRecorder() {
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}
            public List<TranscriptEntry> list(String run){return entries;}
        };
        return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
    }
    private com.samlscope.core.evaluation.CaseOutcome observe() {
        return MetadataAlgorithmEvidence.observe(MetadataAlgorithmSelection.ROLE,context(),e->bodies.get(e.decodedSamlRef()),target);
    }
    @Test void producerUsesOriginalSignedExchangeAndMatchingVariantKey() throws Exception {
        fixture(false,true);
        var evidence=new MetadataEncryptionAlgorithmEvidence(e->bodies.get(e.decodedSamlRef()),run->target,(run,variant)->Optional.of(cryptoKey));
        var observations=evidence.observe(context());
        assertEquals(MetadataAlgorithmSelection.required(MetadataAlgorithmSelection.ROLE).size(),observations.size());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG04-b-idp-01",observations).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-d-idp-01",observations).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-c-idp-01",observations).isEmpty());
        var wrong=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","wrong");
        assertTrue(new MetadataEncryptionAlgorithmEvidence(e->bodies.get(e.decodedSamlRef()),run->target,(run,variant)->Optional.of(wrong)).observe(context()).isEmpty());
        var original=bodies.get("response-control");
        bodies.put("response-control",new String(original,StandardCharsets.UTF_8).replace("https://idp.example","https://wrong.example").getBytes(StandardCharsets.UTF_8));
        assertTrue(evidence.observe(context()).isEmpty());
        bodies.put("response-control",original);
        bodies.put("prepared-control","broken".getBytes(StandardCharsets.UTF_8));
        assertTrue(evidence.observe(context()).isEmpty());
    }

    @Test void nativePreparationMustBeConfirmedBeforeAnOutcomeIsAssigned() throws Exception {
        fixture(false);
        var fallback=new ConfigurationGateTestCase(new InformationalChoiceTestCase(MetadataAlgorithmSelection.ROLE,TargetRole.IDP),
            "input","Prepare native metadata",Duration.ofHours(1),com.samlscope.core.caseexec.ConfigurationFailureSemantics.TEST_PRECONDITION);
        var testCase=new MetadataAlgorithmConfigurationTestCase(fallback,e->bodies.get(e.decodedSamlRef()),r->target);
        var waiting=assertInstanceOf(com.samlscope.core.caseexec.CaseStep.AwaitConfig.class,testCase.start(context()));
        assertFalse(testCase.evidenceStatus(context()).ready());
        var finished=assertInstanceOf(com.samlscope.core.caseexec.CaseStep.Finish.class,testCase.resume(context(),waiting.next(),new com.samlscope.core.caseexec.CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.SATISFIED,finished.outcome().outcome());
        assertEquals(true,finished.outcome().details().get("configuration_confirmed"));
    }
    @Test void cryptographicMatrixDetectsRoleFallback() throws Exception {
        fixture(false);assertEquals(Outcome.SATISFIED,observe().outcome());
        entries.clear();bodies.clear();fixture(true);assertEquals(Outcome.VIOLATED,observe().outcome());
    }
    @Test void corruptedResponseOrMetadataCannotBecomeProductViolation() throws Exception {
        fixture(true);var key="response-algorithm-role-both-384";var original=bodies.get(key);
        bodies.put(key,new String(original,StandardCharsets.UTF_8).replace("https://idp.example","https://wrong.example").getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED,observe().outcome());bodies.put(key,original);
        key="prepared-algorithm-role-both-384";bodies.put(key,"broken".getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED,observe().outcome());
    }
}
