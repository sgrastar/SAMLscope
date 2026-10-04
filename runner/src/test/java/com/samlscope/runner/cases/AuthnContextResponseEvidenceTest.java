package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class AuthnContextResponseEvidenceTest {
    @TempDir java.nio.file.Path directory;
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
    private record Fixture(Element response,Element metadata,PlanCredentials key) {}
    private Element parse(String value) {return SecureXml.parse(value.getBytes(StandardCharsets.UTF_8)).getDocumentElement();}
    private Fixture fixture(String context,boolean encrypted,boolean error) throws Exception {
        var key=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var metadata=parse("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://sp.example'>"
            +"<md:SPSSODescriptor><md:KeyDescriptor use='encryption'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
            +Base64.getEncoder().encodeToString(key.certificate().getEncoded())+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:SPSSODescriptor></md:EntityDescriptor>");
        var response=parse("<p:Response xmlns:p='"+P+"' xmlns:s='"+S+"' ID='_response' InResponseTo='_request' Destination='https://sp.example/acs'>"
            +"<s:Issuer>https://idp.example</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:"+(error?"Responder":"Success")+"'/></p:Status></p:Response>");
        if(context!=null) {
            var assertion=parse("<s:Assertion xmlns:s='"+S+"' ID='_assertion'><s:Issuer>https://idp.example</s:Issuer>"
                +"<s:Subject><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'><s:SubjectConfirmationData InResponseTo='_request' Recipient='https://sp.example/acs'/></s:SubjectConfirmation></s:Subject>"
                +"<s:Conditions><s:AudienceRestriction><s:Audience>https://sp.example</s:Audience></s:AudienceRestriction></s:Conditions>"
                +"<s:AuthnStatement><s:AuthnContext>"+context+"</s:AuthnContext></s:AuthnStatement></s:Assertion>");
            new XmlSigner().sign(assertion,key,null);
            if(encrypted) assertion=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,assertion,key.certificate().getPublicKey(),
                new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,
                    SamlEncryptionFixtureFactory.Digest.SHA256,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
            response.appendChild(response.getOwnerDocument().importNode(assertion,true));
        }
        new XmlSigner().sign(response,key,null);return new Fixture(response,metadata,key);
    }
    private AuthnContextResponseEvidence.Observation read(Fixture f) {
        return AuthnContextResponseEvidence.read(f.response(),"https://idp.example",List.of(f.key().certificate()),f.metadata(),Optional.of(f.key()),"_request","https://sp.example/acs");
    }
    @Test void classAndDeclarationRemainSeparateAfterDecryption() throws Exception {
        for(boolean encrypted:List.of(false,true)) {
            var result=read(fixture("<s:AuthnContextClassRef>urn:class</s:AuthnContextClassRef><s:AuthnContextDeclRef>urn:declaration</s:AuthnContextDeclRef>",encrypted,false));
            assertEquals(AuthnContextResponseEvidence.ResponseKind.SUCCESS,result.kind());
            assertEquals(Optional.of("urn:class"),result.classReference());assertEquals(Optional.of("urn:declaration"),result.declarationReference());
            assertFalse(result.toString().contains("urn:declaration"));
        }
    }
    @Test void signedErrorIsDistinctFromSuccessfulSelectionAndMalformedEvidence() throws Exception {
        var error=read(fixture(null,false,true));assertEquals(AuthnContextResponseEvidence.ResponseKind.ERROR,error.kind());
        assertTrue(error.classReference().isEmpty());assertTrue(error.declarationReference().isEmpty());
        for(String invalid:List.of("","<s:AuthnContextClassRef>urn:a</s:AuthnContextClassRef><s:AuthnContextClassRef>urn:b</s:AuthnContextClassRef>",
                "<s:AuthnContextDecl/><s:AuthnContextDeclRef>urn:a</s:AuthnContextDeclRef>")) {
            var f=fixture(invalid,true,false);assertThrows(IllegalArgumentException.class,()->read(f));
        }
        var withAssertion=fixture("<s:AuthnContextClassRef>urn:a</s:AuthnContextClassRef>",true,true);
        assertThrows(IllegalArgumentException.class,()->read(withAssertion));
        var tampered=fixture(null,false,true);tampered.response().setAttribute("Destination","https://other.example");
        assertThrows(IllegalArgumentException.class,()->read(tampered));
    }
}
