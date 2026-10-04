package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.crypto.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class SamlDefaultAlgorithmFixturesTest {
    @TempDir Path folder;
    private static final Instant NOW=Instant.parse("2026-10-03T11:00:00Z");
    private static final URI DEST=URI.create("https://idp.example/sso"),ACS=URI.create("https://suite.example/acs");
    private static final String ISSUER="https://suite.example/sp",DS="http://www.w3.org/2000/09/xmldsig#";
    private PlanCredentials key(){return new FilePlanKeyStore(folder,Clock.fixed(NOW,ZoneOffset.UTC)).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");}
    private byte[] build(SamlDefaultAlgorithmFixtures.Fixture fixture,PlanCredentials key){return new SamlDefaultAlgorithmFixtures().authnRequest(fixture,"_weak-algorithm-input",DEST,ISSUER,ACS,NOW,key);}
    @Test void weakDigestAndSignatureRemainIndependentMathematicallyValidInputs() {
        var key=key();
        for(var fixture:List.of(SamlDefaultAlgorithmFixtures.Fixture.MD5_DIGEST,SamlDefaultAlgorithmFixtures.Fixture.RSA_MD5)) {
            var root=SecureXml.parse(build(fixture,key)).getDocumentElement();
            assertEquals(fixture==SamlDefaultAlgorithmFixtures.Fixture.MD5_DIGEST?SamlDefaultAlgorithmFixtures.MD5_DIGEST:SamlDefaultAlgorithmFixtures.SHA256_DIGEST,
                    ((Element)root.getElementsByTagNameNS(DS,"DigestMethod").item(0)).getAttribute("Algorithm"));
            assertEquals(fixture==SamlDefaultAlgorithmFixtures.Fixture.RSA_MD5?SamlDefaultAlgorithmFixtures.RSA_MD5:SamlDefaultAlgorithmFixtures.RSA_SHA256,
                    ((Element)root.getElementsByTagNameNS(DS,"SignatureMethod").item(0)).getAttribute("Algorithm"));
            assertTrue(new SamlDefaultAlgorithmFixtures().hasValidInputSignature(fixture,root,key.certificate()),fixture.name());
            assertTrue(new SamlDefaultAlgorithmFixtures().hasValidInputDigests(fixture,root),fixture.name());
            root.setAttribute("AssertionConsumerServiceURL","https://unrelated.example/acs");
            assertFalse(new SamlDefaultAlgorithmFixtures().hasValidInputSignature(fixture,root,key.certificate()),fixture.name());
        }
    }
    @Test void onlyAlgorithmAndResultingSignatureBytesChangeFromTheSameNormalRequest() {
        var key=key();var normal=withoutSignature(build(SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL,key));
        for(var fixture:SamlDefaultAlgorithmFixtures.Fixture.values())assertArrayEquals(normal,withoutSignature(build(fixture,key)),fixture.name());
    }
    @Test void normalAndBadSignatureControlsPreserveExistingFactoryBytesAndDefaultAlgorithms() {
        var key=key();var factory=new SamlSignedRequestFactory();
        assertArrayEquals(factory.build(SamlSignedRequestFactory.Fixture.VALID,"_weak-algorithm-input",DEST,ISSUER,ACS,NOW,key),build(SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL,key));
        assertArrayEquals(factory.build(SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE,"_weak-algorithm-input",DEST,ISSUER,ACS,NOW,key),build(SamlDefaultAlgorithmFixtures.Fixture.INVALID_SHA256_SIGNATURE,key));
        var bad=SecureXml.parse(build(SamlDefaultAlgorithmFixtures.Fixture.INVALID_SHA256_SIGNATURE,key)).getDocumentElement();
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(bad));
        assertFalse(new XmlSignatureVerifier().hasValidEnvelopedSignature(bad,key.certificate()));
    }
    @Test void fixtureMathValidatorCannotBeUsedToRelaxAnOrdinaryAuthenticationInput() {
        var key=key();var helper=new SamlDefaultAlgorithmFixtures();var weak=SecureXml.parse(build(SamlDefaultAlgorithmFixtures.Fixture.MD5_DIGEST,key)).getDocumentElement();
        assertFalse(helper.hasValidInputSignature(SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL,weak,key.certificate()));
        assertFalse(helper.hasValidInputDigests(SamlDefaultAlgorithmFixtures.Fixture.SHA256_CONTROL,weak));
        weak.setAttribute("ID","_foreign-reference");assertFalse(helper.hasValidInputSignature(SamlDefaultAlgorithmFixtures.Fixture.MD5_DIGEST,weak,key.certificate()));
        var assertion=SecureXml.parse("<a:Assertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_not-an-input'/>".getBytes()).getDocumentElement();
        assertFalse(helper.hasValidInputSignature(SamlDefaultAlgorithmFixtures.Fixture.RSA_MD5,assertion,key.certificate()));
    }
    @Test void rsa15AndOaepCipherControlsEncryptTheSameActualIdentifierForTheSameRecipient() {
        var key=key();var name=SecureXml.parse("<saml:NameID xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">same-authenticated-identifier</saml:NameID>".getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
        var factory=new SamlLogoutRequestFactory();
        for(var transport:List.of(SamlEncryptionFixtureFactory.Transport.RSA_1_5,SamlEncryptionFixtureFactory.Transport.RSA_OAEP)) {
            var encrypted=factory.encryptedIdentifier(name,key.certificate().getPublicKey(),new SamlEncryptionFixtureFactory.Algorithms(
                    SamlEncryptionFixtureFactory.Content.AES128_GCM,transport,SamlEncryptionFixtureFactory.Digest.DEFAULT,SamlEncryptionFixtureFactory.Mgf.DEFAULT));
            var decoded=new SamlXmlDecrypter().decrypt(encrypted,key.privateKey());
            assertEquals(name.getTextContent(),decoded.getTextContent());assertEquals(name.getAttribute("Format"),decoded.getAttribute("Format"));
            assertEquals(transport.uri(),((Element)encrypted.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","EncryptedKey").item(0))
                    .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#","EncryptionMethod").item(0).getAttributes().getNamedItem("Algorithm").getNodeValue());
        }
    }
    private static byte[] withoutSignature(byte[] bytes) {
        var doc=SecureXml.parse(bytes);var root=doc.getDocumentElement();var signature=root.getElementsByTagNameNS(DS,"Signature").item(0);
        root.removeChild(signature);return SecureXml.serialize(doc);
    }
}
