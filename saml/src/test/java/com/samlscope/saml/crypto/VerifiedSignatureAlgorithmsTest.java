package com.samlscope.saml.crypto;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.normal.SecureXml;

class VerifiedSignatureAlgorithmsTest {
    @TempDir java.nio.file.Path directory;
    private static final String ISSUER="https://idp.example";
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    private final VerifiedSignatureAlgorithms reader=new VerifiedSignatureAlgorithms();
    private PlanCredentials key(String id) { return new FilePlanKeyStore(directory,Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS",id); }
    private Element response() {
        return SecureXml.parse(("<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:s='urn:oasis:names:tc:SAML:2.0:assertion' ID='_response'>"
                +"<s:Issuer>"+ISSUER+"</s:Issuer><p:Status/><s:Assertion ID='_assertion'><s:Issuer>"+ISSUER+"</s:Issuer></s:Assertion></p:Response>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
    }
    private Element assertion(Element root) { return (Element)root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Assertion").item(0); }
    @Test void readsOnlyVerifiedDirectSignaturesAndUsesPinnedKeys() {
        var good=key("good");var wrong=key("wrong");var root=response();
        new XmlSigner().sign(assertion(root),good,null);new XmlSigner().sign(root,good,null);
        var found=reader.read(root,ISSUER,List.of(wrong.certificate(),good.certificate()));
        assertEquals(List.of("Response","Assertion"),found.stream().map(VerifiedSignatureAlgorithms.Observation::element).toList());
        assertTrue(found.stream().allMatch(o -> o.signatureAlgorithm().equals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
                && o.digestAlgorithm().equals("http://www.w3.org/2001/04/xmlenc#sha256")));
        assertTrue(reader.read(root,ISSUER,List.of(wrong.certificate())).isEmpty(),"Do not trust embedded KeyInfo");
        assertTrue(reader.read(root,"https://other.example",List.of(good.certificate())).isEmpty());
        assertion(root).setAttribute("tampered","true");
        assertTrue(reader.read(root,ISSUER,List.of(good.certificate())).isEmpty());
    }
    @Test void duplicateIdsAndPartialXPathSignaturesCannotSupplyEvidence() {
        var good=key("good");var root=response();new XmlSigner().sign(root,good,null);
        assertion(root).setAttribute("ID","_response");
        assertTrue(reader.read(root,ISSUER,List.of(good.certificate())).isEmpty());
        root=response();
        new XmlSigner().sign(root,good,null,new XmlSigner.SignatureOptions(true,List.of(
                XmlSigner.TransformSpec.algorithm(DS+"enveloped-signature"),
                XmlSigner.TransformSpec.xpath("not(ancestor-or-self::samlp:Status)"),
                XmlSigner.TransformSpec.algorithm("http://www.w3.org/2001/10/xml-exc-c14n#"))));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,good.certificate()));
        assertTrue(reader.read(root,ISSUER,List.of(good.certificate())).isEmpty());
    }
    @Test void unsignedContainerCannotBorrowItsAssertionsSignature() {
        var good=key("good");var root=response();
        new XmlSigner().sign(assertion(root),good,null);
        var found=reader.read(root,ISSUER,List.of(good.certificate()));
        assertEquals(1,found.size());assertEquals("Assertion",found.getFirst().element());
        var method=(Element)root.getElementsByTagNameNS(DS,"SignatureMethod").item(0);
        method.setAttribute("Algorithm","http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
        assertTrue(reader.read(root,ISSUER,List.of(good.certificate())).isEmpty());
    }
}
