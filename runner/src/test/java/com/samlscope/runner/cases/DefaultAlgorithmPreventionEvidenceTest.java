package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.net.URI;
import java.util.*;
import java.time.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DefaultAlgorithmPreventionEvidenceTest {
    @TempDir Path directory;
    private DefaultAlgorithmPreventionEvidence reader()throws Exception{return new DefaultAlgorithmPreventionEvidence(directory.toRealPath(),
            entry->{throw new AssertionError("Unqualified native proof must not read protocol bytes");},
            run->{throw new AssertionError("Unqualified proof must fail before metadata access");},
            run->{throw new AssertionError("Unqualified proof must never obtain a credential");},run->"browser_sso_idp");}
    private String manifest(String extra){return "{\"schema\":\""+DefaultAlgorithmPreventionEvidence.SCHEMA+"\",\"runId\":\""+ClockSkewEvidenceTestCaseTest.RUN
            +"\",\"caseId\":\""+DefaultAlgorithmPreventionEvidence.CASE+"\",\"campaignId\":\""+DefaultAlgorithmPreventionEvidence.CAMPAIGN
            +"\",\"counterfactualCalibrationOnly\":false"+extra+"}";}
    @Test void malformedOwnedFileAndSymlinkStayOwnedAndNeverPromoteOrReadTarget()throws Exception {
        String run=ClockSkewEvidenceTestCaseTest.RUN;var r=reader();assertFalse(r.exists(run));Files.writeString(directory.resolve(run),"not a folder");assertTrue(r.exists(run));
        assertTrue(r.evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());Files.delete(directory.resolve(run));var peer=Files.createDirectory(directory.resolve("peer"));
        Files.createSymbolicLink(directory.resolve(run),peer);assertTrue(r.exists(run));assertTrue(r.evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
    }
    @Test void foreignRunAndBorrowedSourceRunFailBeforeAnyNativeAdapterOrKeyAccess()throws Exception {
        var folder=Files.createDirectory(directory.resolve(ClockSkewEvidenceTestCaseTest.RUN));
        for(var text:List.of(manifest("").replace(ClockSkewEvidenceTestCaseTest.RUN,"run_11111111111111111111111111"),manifest(",\"sourceRunId\":\"run_11111111111111111111111111\""))) {
            Files.writeString(folder.resolve("manifest.json"),text);assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
        }
    }
    @Test void receiptFlagDoesNotEnableOfflineCalibrationInProduction()throws Exception {
        var folder=Files.createDirectory(directory.resolve(ClockSkewEvidenceTestCaseTest.RUN));Files.writeString(folder.resolve("manifest.json"),manifest("").replace("false","true"));
        assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
    }
    @Test void falseDefaultPolicyAndRestoreLabelsCannotReplaceOriginalsOrHashes()throws Exception {
        var folder=Files.createDirectory(directory.resolve(ClockSkewEvidenceTestCaseTest.RUN));
        for(var extra:List.of(",\"defaultPolicy\":true,\"restored\":true",",\"files\":{\"native.json\":\""+"0".repeat(64)+"\"}")) {
            Files.writeString(folder.resolve("native.json"),"{\"policyDefault\":true}");Files.writeString(folder.resolve("manifest.json"),manifest(extra));
            assertTrue(reader().evaluate(ClockSkewEvidenceTestCaseTest.context(true)).isEmpty());
        }
    }
    @Test void dualRoleMetadataKeepsSpLogoutResponseEndpointSeparateFromIdpReceiver() {
        var entity=SecureXml.parse(("<md:EntityDescriptor xmlns:md='"+DefaultAlgorithmPreventionEvidence.MD+"'>"
                +"<md:IDPSSODescriptor><md:SingleLogoutService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://peer.example/idp/slo'/></md:IDPSSODescriptor>"
                +"<md:SPSSODescriptor><md:SingleLogoutService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://peer.example/sp/slo'/></md:SPSSODescriptor>"
                +"</md:EntityDescriptor>").getBytes()).getDocumentElement();
        assertEquals(URI.create("https://peer.example/sp/slo"),DefaultAlgorithmPreventionEvidence.endpoint(entity,"SPSSODescriptor","SingleLogoutService"));
        assertEquals(URI.create("https://peer.example/idp/slo"),DefaultAlgorithmPreventionEvidence.endpoint(entity,"IDPSSODescriptor","SingleLogoutService"));
        assertThrows(IllegalArgumentException.class,()->DefaultAlgorithmPreventionEvidence.endpoint(entity,"SingleLogoutService"));
    }
    @Test void missingSpLogoutEndpointCannotBorrowTheIdpEndpoint() {
        for(String role:List.of("","<md:SPSSODescriptor/>","<md:SPSSODescriptor><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://peer.example/sp/slo'/></md:SPSSODescriptor>")) {
            var entity=SecureXml.parse(("<md:EntityDescriptor xmlns:md='"+DefaultAlgorithmPreventionEvidence.MD+"'>"
                    +"<md:IDPSSODescriptor><md:SingleLogoutService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='https://peer.example/idp/slo'/></md:IDPSSODescriptor>"
                    +role+"</md:EntityDescriptor>").getBytes()).getDocumentElement();
            assertThrows(IllegalArgumentException.class,()->DefaultAlgorithmPreventionEvidence.endpoint(entity,"SPSSODescriptor","SingleLogoutService"));
        }
    }
    @Test void signedRedirectWithFixedCallbackQueryAndXmlSignedPostBothValidate()throws Exception {
        var f=replyFixture();var encoded=new SignedRedirectEncoder().encode(URI.create(CALLBACK),f.reply(),"original-relay",f.targetKey());
        assertDoesNotThrow(()->validate(f,entry("GET",encoded.destination().toString(),encoded.rawQuery(),encoded.decodedXml()),encoded.decodedXml(),true));
        assertFalse(DefaultAlgorithmPreventionEvidence.targetTrusted(xml(encoded.decodedXml()),f.targetMetadata()));
        var doc=SecureXml.parse(f.reply());new XmlSigner().sign(doc.getDocumentElement(),f.targetKey(),null);byte[] signed=SecureXml.serialize(doc);
        assertDoesNotThrow(()->validate(f,entry("POST",CALLBACK,null,signed),signed,true));
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("POST",CALLBACK,null,f.reply()),f.reply(),true));
    }
    @Test void redirectProofRejectsTamperedQueryWrongSignerAndBorrowedDecodedMessage()throws Exception {
        var f=replyFixture();var encoder=new SignedRedirectEncoder();var signed=encoder.encode(URI.create(CALLBACK),f.reply(),"original-relay",f.targetKey());
        String changed=signed.rawQuery().replace("RelayState=original-relay","RelayState=foreign-relay");
        String changedUrl=signed.destination().toString().replace(signed.rawQuery(),changed);
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",changedUrl,changed,signed.decodedXml()),signed.decodedXml(),true));
        var wrong=encoder.encode(URI.create(CALLBACK),f.reply(),"original-relay",f.otherKey());
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",wrong.destination().toString(),wrong.rawQuery(),wrong.decodedXml()),wrong.decodedXml(),true));
        var different=SecureXml.parse(signed.decodedXml());different.getDocumentElement().setAttribute("ID","_different_response");byte[] bytes=SecureXml.serialize(different);
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",signed.destination().toString(),signed.rawQuery(),bytes),bytes,true));
    }
    @Test void redirectCallbackRequiresActualUriRawQueryAndTheAdvertisedSpBinding()throws Exception {
        var f=replyFixture();var signed=new SignedRedirectEncoder().encode(URI.create(CALLBACK),f.reply(),"original-relay",f.targetKey());
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",signed.destination().toString().replace("/sp/slo","/other/slo"),signed.rawQuery(),signed.decodedXml()),signed.decodedXml(),true));
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",signed.destination().toString().replace("run=run_000","run=run_111"),signed.rawQuery().replace("run=run_000","run=run_111"),signed.decodedXml()),signed.decodedXml(),true));
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",signed.destination().toString(),signed.rawQuery()+"&extra=unrecorded",signed.decodedXml()),signed.decodedXml(),true));
        var suite=xml(SecureXml.serialize(f.suite().getOwnerDocument()));
        var sp=(Element)suite.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor").item(0);
        for(var e:DefaultAlgorithmPreventionEvidence.children(sp,DefaultAlgorithmPreventionEvidence.MD,"SingleLogoutService"))
            if(e.getAttribute("Binding").endsWith("HTTP-Redirect"))sp.removeChild(e);
        var idp=suite.getOwnerDocument().createElementNS(DefaultAlgorithmPreventionEvidence.MD,"md:IDPSSODescriptor");suite.appendChild(idp);
        var borrowed=suite.getOwnerDocument().createElementNS(DefaultAlgorithmPreventionEvidence.MD,"md:SingleLogoutService");borrowed.setAttribute("Binding","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");borrowed.setAttribute("Location",CALLBACK);idp.appendChild(borrowed);
        var missing=new ReplyFixture(f.targetKey(),f.otherKey(),f.targetMetadata(),suite,f.request(),f.reply());
        assertThrows(IllegalArgumentException.class,()->validate(missing,entry("GET",signed.destination().toString(),signed.rawQuery(),signed.decodedXml()),signed.decodedXml(),true));
    }
    @Test void logoutResponseLocationIsBoundAndAuthnResponsesRemainPostOnly()throws Exception {
        var f=replyFixture();var sp=(Element)f.suite().getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor").item(0);
        for(var e:DefaultAlgorithmPreventionEvidence.children(sp,DefaultAlgorithmPreventionEvidence.MD,"SingleLogoutService")){
            e.setAttribute("ResponseLocation",CALLBACK);e.setAttribute("Location","https://suite.example/sp/request-only");
        }
        var signed=new SignedRedirectEncoder().encode(URI.create(CALLBACK),f.reply(),null,f.targetKey());
        assertDoesNotThrow(()->validate(f,entry("GET",signed.destination().toString(),signed.rawQuery(),signed.decodedXml()),signed.decodedXml(),true));
        byte[] response=new String(f.reply(),java.nio.charset.StandardCharsets.UTF_8).replace("LogoutResponse","Response").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var authn=new SignedRedirectEncoder().encode(URI.create(CALLBACK),response,null,f.targetKey());
        assertThrows(IllegalArgumentException.class,()->validate(f,entry("GET",authn.destination().toString(),authn.rawQuery(),authn.decodedXml()),authn.decodedXml(),false));
    }
    private static final String CALLBACK="https://suite.example/sp/slo?mdv=control&run=run_00000000000000000000000000";
    private record ReplyFixture(PlanCredentials targetKey,PlanCredentials otherKey,Element targetMetadata,Element suite,Element request,byte[] reply){}
    private ReplyFixture replyFixture()throws Exception{
        var store=new FilePlanKeyStore(directory.resolve("reply-keys"),Clock.fixed(Instant.parse("2026-10-03T16:00:00Z"),ZoneOffset.UTC));
        var key=store.getOrCreate("plan_22222222222222222222222222");var other=store.getOrCreate("plan_33333333333333333333333333");
        String md=DefaultAlgorithmPreventionEvidence.MD,p=DefaultAlgorithmPreventionEvidence.P,a=DefaultAlgorithmPreventionEvidence.A,ds=DefaultAlgorithmPreventionEvidence.DS,dest=CALLBACK.replace("&","&amp;");
        var target=xml(("<md:EntityDescriptor xmlns:md='"+md+"' xmlns:ds='"+ds+"' entityID='https://idp.example'><md:IDPSSODescriptor protocolSupportEnumeration='"+p+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>").getBytes());
        var suite=xml(("<md:EntityDescriptor xmlns:md='"+md+"'><md:SPSSODescriptor><md:SingleLogoutService Binding='"+DefaultAlgorithmPreventionEvidence.POST+"' Location='"+dest+"'/><md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='"+dest+"'/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes());
        var request=xml(("<p:LogoutRequest xmlns:p='"+p+"' ID='_input'/>").getBytes());
        byte[] reply=("<p:LogoutResponse xmlns:p='"+p+"' xmlns:a='"+a+"' ID='_response' Version='2.0' InResponseTo='_input' Destination='"+dest+"'><a:Issuer>https://idp.example</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Responder'/></p:Status></p:LogoutResponse>").getBytes();
        return new ReplyFixture(key,other,target,suite,request,reply);
    }
    private static Element xml(byte[] bytes){return SecureXml.parse(bytes).getDocumentElement();}
    private static TranscriptEntry entry(String method,String url,String query,byte[] raw){return new TranscriptEntry("tx_reply",ClockSkewEvidenceTestCaseTest.RUN,Direction.INBOUND,Instant.parse("2026-10-03T16:00:00Z"),null,method,url,200,Map.of(),null,0,"transcripts/"+ClockSkewEvidenceTestCaseTest.RUN+"/tx_reply.saml.xml",raw.length,"application/xml",query,Map.of("type","LogoutResponse"));}
    private static void validate(ReplyFixture f,TranscriptEntry entry,byte[] raw,boolean logout)throws Exception{
        DefaultAlgorithmPreventionEvidence.validateReply(entry,xml(raw),raw,f.request(),f.suite(),f.targetMetadata(),logout);
    }
}
