package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlSchemaValidation;
import com.samlscope.saml.normal.SecureXml;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataRevocationFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final Instant NOW = Instant.parse("2026-10-02T00:00:00Z");
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private FilePlanKeyStore keys() { return new FilePlanKeyStore(directory, clock); }
    private MetadataService service() { return new MetadataService(URI.create("https://peer.example"), keys(), new XmlSigner(), clock); }
    private X509Certificate cert(String text) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(text)));
    }
    private String text(Element root, String ns, String local) {
        var values = root.getElementsByTagNameNS(ns, local);
        assertTrue(values.getLength() > 0);
        return values.item(0).getTextContent();
    }

    @Test void revokedOriginalHasRealIssuerSignedCrlAndMatchingRoleSerial() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var variant = MetadataService.Variant.parse("certificate-revoked");
        var root = SecureXml.parse(service().generate(plan, variant, "run_revocation")).getDocumentElement();
        var issuer = cert(text(root, MetadataRevocationFixtures.NS, "IssuerCertificate"));
        assertTrue(issuer.getBasicConstraints() >= 0);
        issuer.verify(issuer.getPublicKey());
        var crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(text(root, MetadataRevocationFixtures.NS, "CRL"))));
        crl.verify(issuer.getPublicKey());
        assertEquals(issuer.getSubjectX500Principal(), crl.getIssuerX500Principal());
        assertTrue(crl.getThisUpdate().toInstant().isBefore(NOW));
        assertTrue(crl.getNextUpdate().toInstant().isAfter(NOW));
        for (String role : List.of("SPSSODescriptor", "IDPSSODescriptor")) {
            var roleElement = (Element) root.getElementsByTagNameNS(MetadataService.MD, role).item(0);
            var accepted = cert(text(roleElement, MetadataService.DS, "X509Certificate"));
            accepted.verify(issuer.getPublicKey());
            accepted.checkValidity(java.util.Date.from(NOW));
            assertEquals(issuer.getSubjectX500Principal(), accepted.getIssuerX500Principal());
            assertTrue(crl.isRevoked(accepted));
            assertArrayEquals(accepted.getPublicKey().getEncoded(), keys().getOrCreate(plan.id()).certificate().getPublicKey().getEncoded());
        }
        // The issuer proof is not an additional accepted role key.
        assertEquals(4, root.getElementsByTagNameNS(MetadataService.MD, "KeyDescriptor").getLength());
        assertEquals(java.util.Optional.empty(), SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, issuer));
    }

    @Test void unreachableCertificateReallyAdvertisesLocalCdpAndOcsp() throws Exception {
        var variant = MetadataService.Variant.parse("certificate-revocation-unreachable");
        var root = SecureXml.parse(service().generate(SamlTestFixtures.idpPlan(), variant, "run_revocation")).getDocumentElement();
        var sp = (Element) root.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        var role = cert(text(sp, MetadataService.DS, "X509Certificate"));
        var points = CRLDistPoint.getInstance(ASN1OctetString.getInstance(role.getExtensionValue(Extension.cRLDistributionPoints.getId())).getOctets());
        var names = org.bouncycastle.asn1.x509.GeneralNames.getInstance(points.getDistributionPoints()[0].getDistributionPoint().getName());
        var cdp = URI.create(names.getNames()[0].getName().toString());
        var aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(role.getExtensionValue(Extension.authorityInfoAccess.getId())).getOctets());
        assertEquals(AccessDescription.id_ad_ocsp, aia.getAccessDescriptions()[0].getAccessMethod());
        var ocsp = URI.create(aia.getAccessDescriptions()[0].getAccessLocation().getName().toString());
        assertEquals("samlscope-reference-suite", cdp.getHost());
        assertEquals(18481, cdp.getPort());
        assertEquals(cdp.resolve("unavailable.ocsp"), ocsp);
        assertEquals(0, root.getElementsByTagNameNS(MetadataRevocationFixtures.NS, "CRL").getLength());
        assertEquals(java.util.Optional.empty(), SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA));
    }

    @Test void scalarCryptoIsDeterministicAndRuntimeUsesSamePublicKey() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        for (String id : List.of("certificate-revoked", "certificate-revocation-unreachable")) {
            var variant = MetadataService.Variant.parse(id);
            var primary = keys().getOrCreate(plan.id());
            var first = MetadataRevocationFixtures.certificate(primary, variant, NOW);
            var second = MetadataRevocationFixtures.certificate(primary, variant, NOW.plusSeconds(10));
            assertArrayEquals(first.getEncoded(), second.getEncoded());
            assertArrayEquals(service().generate(plan, variant, "run_revocation"), service().generate(plan, variant, "run_revocation"));
            assertArrayEquals(first.getPublicKey().getEncoded(), service().credentialsForVariant(plan, variant).certificate().getPublicKey().getEncoded());
            var polling = SecureXml.parse(service().generatePolling(plan, variant, "run_revocation")).getDocumentElement();
            var role = (Element) polling.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
            var accepted = cert(text(role, MetadataService.DS, "X509Certificate"));
            assertArrayEquals(accepted.getPublicKey().getEncoded(), service().credentialsForPollingVariant(plan, variant).certificate().getPublicKey().getEncoded());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(polling, accepted));
        }
    }
}
