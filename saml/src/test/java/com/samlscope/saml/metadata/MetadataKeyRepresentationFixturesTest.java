package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import java.util.*;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class MetadataKeyRepresentationFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final String DS="http://www.w3.org/2000/09/xmldsig#";
    @Test void mixedRepresentationHasOneIdenticalPublicKeyAndValidMetadataSignature() throws Exception {
        var clock=Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"),ZoneOffset.UTC);
        var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),new FilePlanKeyStore(directory,clock),new XmlSigner(),clock);
        var doc=SecureXml.parse(service.generatePolling(plan,MetadataService.Variant.KEYVALUE_AND_X509,"run_probe"));
        var role=(Element)doc.getElementsByTagNameNS(MetadataService.MD,"SPSSODescriptor").item(0);
        assertEquals(1,role.getElementsByTagNameNS(MetadataService.MD,"KeyDescriptor").getLength());
        var cert=(java.security.cert.X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(role.getElementsByTagNameNS(DS,"X509Certificate").item(0).getTextContent())));
        var rsa=(RSAPublicKey)cert.getPublicKey();
        assertEquals(rsa.getModulus(),new BigInteger(1,Base64.getMimeDecoder().decode(role.getElementsByTagNameNS(DS,"Modulus").item(0).getTextContent())));
        assertEquals(rsa.getPublicExponent(),new BigInteger(1,Base64.getMimeDecoder().decode(role.getElementsByTagNameNS(DS,"Exponent").item(0).getTextContent())));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(doc.getDocumentElement(),cert));
        assertArrayEquals(service.credentialsForPollingVariant(plan,MetadataService.Variant.ENTITY_ROOT).certificate().getPublicKey().getEncoded(),cert.getPublicKey().getEncoded());
    }
    @Test void twoEncryptionKeysAreDistinctAndRuntimeReceiverMatchesLastAdvertisedKey() throws Exception {
        var clock=Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"),ZoneOffset.UTC);
        var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),new FilePlanKeyStore(directory,clock),new XmlSigner(),clock);
        var doc=SecureXml.parse(service.generatePolling(plan,MetadataService.Variant.MULTIPLE_ENCRYPTION_KEYS,"run_probe"));
        var role=(Element)doc.getElementsByTagNameNS(MetadataService.MD,"SPSSODescriptor").item(0);
        var descriptors=role.getElementsByTagNameNS(MetadataService.MD,"KeyDescriptor");
        var encryption=new ArrayList<java.security.cert.X509Certificate>();
        for(int i=0;i<descriptors.getLength();i++) {
            var descriptor=(Element)descriptors.item(i);
            if(descriptor.getAttribute("use").equals("encryption"))encryption.add((java.security.cert.X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(descriptor.getElementsByTagNameNS(DS,"X509Certificate").item(0).getTextContent()))));
        }
        assertEquals(2,encryption.size());assertFalse(Arrays.equals(encryption.get(0).getPublicKey().getEncoded(),encryption.get(1).getPublicKey().getEncoded()));
        assertArrayEquals(encryption.get(1).getPublicKey().getEncoded(),service.decryptionCredentialsForPollingVariant(plan,MetadataService.Variant.MULTIPLE_ENCRYPTION_KEYS).certificate().getPublicKey().getEncoded());
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(doc.getDocumentElement(),encryption.get(0)));
    }

    @Test void multipleEncryptionFixtureSignsRequestsWithAdvertisedSigningKeyAndKeepsLastReceiver() throws Exception {
        var clock=Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"),ZoneOffset.UTC);
        var plan=SamlTestFixtures.idpPlan();
        var service=new MetadataService(URI.create("https://peer.example"),new FilePlanKeyStore(directory,clock),new XmlSigner(),clock);
        var variant=MetadataService.Variant.MULTIPLE_ENCRYPTION_KEYS;
        for(boolean polling:List.of(false,true)) {
            var metadata=SecureXml.parse(polling?service.generatePolling(plan,variant,"run_probe"):service.generate(plan,variant,"run_probe"));
            var role=(Element)metadata.getElementsByTagNameNS(MetadataService.MD,"SPSSODescriptor").item(0);
            var descriptors=role.getElementsByTagNameNS(MetadataService.MD,"KeyDescriptor");
            var signing=new ArrayList<java.security.cert.X509Certificate>();var encryption=new ArrayList<java.security.cert.X509Certificate>();
            for(int i=0;i<descriptors.getLength();i++) {
                var descriptor=(Element)descriptors.item(i);
                var cert=(java.security.cert.X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(
                    new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(descriptor.getElementsByTagNameNS(DS,"X509Certificate").item(0).getTextContent())));
                ("signing".equals(descriptor.getAttribute("use"))?signing:encryption).add(cert);
            }
            assertEquals(1,signing.size());assertEquals(2,encryption.size());
            var signer=polling?service.credentialsForPollingVariant(plan,variant):service.credentialsForVariant(plan,variant);
            var receiver=polling?service.decryptionCredentialsForPollingVariant(plan,variant):service.decryptionCredentialsForVariant(plan,variant);
            assertArrayEquals(signing.getFirst().getPublicKey().getEncoded(),signer.certificate().getPublicKey().getEncoded());
            assertArrayEquals(encryption.getLast().getPublicKey().getEncoded(),receiver.certificate().getPublicKey().getEncoded());
            assertFalse(Arrays.equals(signer.certificate().getPublicKey().getEncoded(),receiver.certificate().getPublicKey().getEncoded()));
            var factory=new com.samlscope.saml.normal.SamlSignedRequestFactory();
            var valid=SecureXml.parse(factory.build(com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID,
                "_mdiop_valid",URI.create("https://idp.example/sso"),role.getParentNode().getAttributes().getNamedItem("entityID").getNodeValue(),
                URI.create("https://peer.example/acs"),clock.instant(),signer)).getDocumentElement();
            var invalid=SecureXml.parse(factory.build(com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE,
                "_mdiop_invalid",URI.create("https://idp.example/sso"),"https://peer.example",URI.create("https://peer.example/acs"),clock.instant(),signer)).getDocumentElement();
            var verifier=new XmlSignatureVerifier();
            assertTrue(verifier.hasValidEnvelopedSignature(valid,signing.getFirst()));
            assertFalse(verifier.hasValidEnvelopedSignature(valid,receiver.certificate()));
            assertTrue(verifier.hasValidEnvelopedReferenceDigests(invalid));
            assertFalse(verifier.hasValidEnvelopedSignature(invalid,signing.getFirst()));
        }
    }
}
