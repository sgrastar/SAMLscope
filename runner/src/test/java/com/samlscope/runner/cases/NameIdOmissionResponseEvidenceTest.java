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

class NameIdOmissionResponseEvidenceTest {
    @TempDir java.nio.file.Path directory;
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata";
    private record Fixture(Element response, Element metadata, PlanCredentials key) {}
    private Element parse(String xml) { return SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8)).getDocumentElement(); }
    private Element encrypt(Element element, PlanCredentials key, SamlEncryptionFixtureFactory.Wrapper wrapper) {
        return new SamlEncryptionFixtureFactory().encrypt(wrapper, element, key.certificate().getPublicKey(),
                new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES128_GCM,
                    SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11, SamlEncryptionFixtureFactory.Digest.SHA256,
                    SamlEncryptionFixtureFactory.Mgf.DEFAULT));
    }
    private Fixture fixture(boolean name, boolean encryptedName, boolean encryptedAssertion,
                            boolean subjectPresent, boolean duplicate) throws Exception {
        var key=new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var metadata=parse("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://sp.example'>"
            +"<md:SPSSODescriptor><md:KeyDescriptor use='encryption'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
            +Base64.getEncoder().encodeToString(key.certificate().getEncoded())
            +"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:SPSSODescriptor></md:EntityDescriptor>");
        var assertion=parse("<s:Assertion xmlns:s='"+S+"' ID='_assertion'><s:Issuer>https://idp.example</s:Issuer>"
            +(subjectPresent?"<s:Subject><s:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
            +"<s:SubjectConfirmationData InResponseTo='_request' Recipient='https://sp.example/acs'/>"
            +"</s:SubjectConfirmation></s:Subject>":"")
            +"<s:Conditions><s:AudienceRestriction><s:Audience>https://sp.example</s:Audience></s:AudienceRestriction></s:Conditions></s:Assertion>");
        if (name && subjectPresent) {
            var identifier=parse("<s:NameID xmlns:s='"+S+"'>synthetic-principal</s:NameID>");
            if(encryptedName) identifier=encrypt(identifier,key,SamlEncryptionFixtureFactory.Wrapper.EncryptedID);
            var subject=(Element)assertion.getElementsByTagNameNS(S,"Subject").item(0);
            subject.insertBefore(assertion.getOwnerDocument().importNode(identifier,true),subject.getFirstChild());
            if(duplicate) subject.insertBefore(assertion.getOwnerDocument().importNode(identifier,true),subject.getFirstChild());
        }
        new XmlSigner().sign(assertion,key,null);
        if(encryptedAssertion) assertion=encrypt(assertion,key,SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion);
        var response=parse("<p:Response xmlns:p='"+P+"' xmlns:s='"+S+"' ID='_response' InResponseTo='_request' Destination='https://sp.example/acs'>"
            +"<s:Issuer>https://idp.example</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:Response>");
        response.appendChild(response.getOwnerDocument().importNode(assertion,true));new XmlSigner().sign(response,key,null);
        return new Fixture(response,metadata,key);
    }
    private NameIdOmissionResponseEvidence.Presence read(Fixture f) {
        return NameIdOmissionResponseEvidence.read(f.response(),"https://idp.example",List.of(f.key().certificate()),
            f.metadata(),Optional.of(f.key()),"_request","https://sp.example/acs");
    }
    @Test void omissionAndVisibleOrEncryptedNameIdRemainDistinct() throws Exception {
        for(boolean encryptedAssertion:List.of(false,true)) {
            assertEquals(NameIdOmissionResponseEvidence.Presence.OMITTED,read(fixture(false,false,encryptedAssertion,true,false)));
            assertEquals(NameIdOmissionResponseEvidence.Presence.NAME_ID,read(fixture(true,false,encryptedAssertion,true,false)));
            assertEquals(NameIdOmissionResponseEvidence.Presence.NAME_ID,read(fixture(true,true,encryptedAssertion,true,false)));
        }
    }
    @Test void missingSubjectDuplicateAndUnverifiedResponsesNeverProveOmission() throws Exception {
        for(Fixture f:List.of(fixture(false,false,true,false,false),fixture(true,true,true,true,true))) {
            assertThrows(IllegalArgumentException.class,()->read(f));
        }
        var f=fixture(false,false,true,true,false);
        assertThrows(IllegalArgumentException.class,()->NameIdOmissionResponseEvidence.read(f.response(),"https://idp.example",
            List.of(f.key().certificate()),f.metadata(),Optional.empty(),"_request","https://sp.example/acs"));
        assertThrows(IllegalArgumentException.class,()->NameIdOmissionResponseEvidence.read(f.response(),"https://idp.example",
            List.of(f.key().certificate()),f.metadata(),Optional.of(f.key()),"_other","https://sp.example/acs"));
        f.response().setAttribute("Destination","https://tampered.example");
        var failure=assertThrows(IllegalArgumentException.class,()->read(f));
        assertNull(failure.getCause());assertFalse(failure.toString().contains("synthetic-principal"));
    }
}
