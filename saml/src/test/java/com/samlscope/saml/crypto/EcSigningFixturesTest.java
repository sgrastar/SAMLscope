package com.samlscope.saml.crypto;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Element;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.saml.normal.SecureXml;

class EcSigningFixturesTest {
    @TempDir Path directory;
    private final Clock clock = Clock.fixed(Instant.parse("2026-09-14T00:00:00Z"), ZoneOffset.UTC);

    @Test void ecKeysPersistSeparatelyFromExistingRsaKeysAndRemainSigningOnly() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var store = new FilePlanKeyStore(directory, clock);
        var rsa = store.getOrCreate(plan.id(), "shared");
        var ec = store.getOrCreateEc(plan.id(), "shared");
        var reopened = new FilePlanKeyStore(directory, clock).getOrCreateEc(plan.id(), "shared");
        assertEquals("EC", ec.privateKey().getAlgorithm());
        assertArrayEquals(ec.privateKey().getEncoded(), reopened.privateKey().getEncoded());
        assertArrayEquals(ec.certificate().getEncoded(), reopened.certificate().getEncoded());
        assertArrayEquals(rsa.privateKey().getEncoded(), store.getOrCreate(plan.id(), "shared").privateKey().getEncoded());
        ec.certificate().verify(ec.certificate().getPublicKey());
        assertTrue(ec.certificate().getKeyUsage()[0]);
        assertFalse(ec.certificate().getKeyUsage()[2]);
        var key = directory.resolve("keys").resolve(plan.id()).resolve("shared/ec-p256/signing-key.pk8");
        if (Files.getFileStore(key).supportsFileAttributeView("posix")) {
            assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), Files.getPosixFilePermissions(key));
        }
        assertThrows(IllegalArgumentException.class, () -> store.getOrCreateEc(plan.id(), "../escape"));
    }

    @Test void metadataAdvertisesTheActualEcSigningKeyWithAnIndependentRsaEncryptionKey() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var store = new FilePlanKeyStore(directory, clock);
        var metadata = new MetadataService(URI.create("https://suite.example"), store, new XmlSigner(), clock);
        for (boolean polling : List.of(false, true)) {
            for (var variant : List.of(MetadataService.Variant.ECDSA_SHA256,
                    MetadataService.Variant.ECDSA_SHA256_INVALID_SIGNATURE)) {
                var credentials = polling ? metadata.credentialsForPollingVariant(plan, variant)
                        : metadata.credentialsForVariant(plan, variant);
                var bytes = polling ? metadata.generatePolling(plan, variant, "run_0123456789ABCDEFGHJKMNPQRS")
                        : metadata.generate(plan, variant, "run_0123456789ABCDEFGHJKMNPQRS");
                var doc = SecureXml.parse(bytes);
                var role = (Element) doc.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
                var keys = role.getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor");
                assertEquals(2, keys.getLength());
                for (int i = 0; i < keys.getLength(); i++) {
                    var descriptor = (Element) keys.item(i);
                    var cert = (java.security.cert.X509Certificate) java.security.cert.CertificateFactory.getInstance("X.509")
                            .generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(
                                    descriptor.getElementsByTagNameNS(MetadataService.DS, "X509Certificate").item(0).getTextContent())));
                    if ("signing".equals(descriptor.getAttribute("use"))) {
                        assertArrayEquals(credentials.certificate().getPublicKey().getEncoded(), cert.getPublicKey().getEncoded());
                        assertEquals("EC", cert.getPublicKey().getAlgorithm());
                    } else {
                        assertEquals("encryption", descriptor.getAttribute("use"));
                        assertEquals("RSA", cert.getPublicKey().getAlgorithm());
                    }
                }
                var request = SecureXml.parse(new SamlSignedRequestFactory().build(variant.requestFixture(), "_ec_test",
                        URI.create("https://idp.example/sso"), "https://suite.example/sp",
                        URI.create("https://suite.example/acs"), clock.instant(), credentials));
                request.getDocumentElement().setIdAttribute("ID", true);
                var signatureElement = (Element) request.getElementsByTagNameNS(MetadataService.DS, "Signature").item(0);
                var signature = new XMLSignature(signatureElement, "");
                assertEquals(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, signature.getSignedInfo().getSignatureMethodURI());
                assertEquals(variant == MetadataService.Variant.ECDSA_SHA256,
                        signature.checkSignatureValue(credentials.certificate()));
                if (variant == MetadataService.Variant.ECDSA_SHA256) {
                    request.getDocumentElement().setAttribute("Destination", "https://other.example/sso");
                    assertFalse(signature.checkSignatureValue(credentials.certificate()));
                }
            }
        }
        assertTrue(MetadataService.preloadedCampaignVariants().contains(MetadataService.Variant.ECDSA_SHA256));
        assertFalse(MetadataService.preloadedCampaignVariants().contains(MetadataService.Variant.ECDSA_SHA256_INVALID_SIGNATURE));
        assertArrayEquals(metadata.credentialsForPollingVariant(plan, MetadataService.Variant.ECDSA_SHA256)
                        .certificate().getPublicKey().getEncoded(),
                metadata.credentialsForPollingVariant(plan, MetadataService.Variant.ECDSA_SHA256_INVALID_SIGNATURE)
                        .certificate().getPublicKey().getEncoded());
    }
}
