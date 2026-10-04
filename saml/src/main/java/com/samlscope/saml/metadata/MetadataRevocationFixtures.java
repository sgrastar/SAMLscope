package com.samlscope.saml.metadata;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashSet;
import javax.xml.XMLConstants;
import com.samlscope.saml.crypto.PlanCredentials;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Public, signed revocation inputs; neither fixture adds a product-side trust anchor. */
public final class MetadataRevocationFixtures {
    public static final String NS = "urn:samlscope:test:certificate-revocation";
    private static final String REVOKED = "certificate-revoked";
    private static final String UNREACHABLE = "certificate-revocation-unreachable";
    private static final X500Name ISSUER = new X500Name("CN=SAMLscope fixture revocation CA,O=SAMLscope");

    private MetadataRevocationFixtures() {}

    public static boolean supports(MetadataService.Variant variant) {
        return REVOKED.equals(variant.id()) || UNREACHABLE.equals(variant.id());
    }

    public static X509Certificate certificate(PlanCredentials primary, MetadataService.Variant variant,
                                              Instant now) {
        if (!supports(variant)) throw new IllegalArgumentException("Unsupported revocation fixture");
        try {
            var subject = new X500Name("CN=SAMLscope metadata revocation fixture,O=SAMLscope");
            var serial = serial(primary, variant.id());
            var builder = new JcaX509v3CertificateBuilder(ISSUER, serial,
                    primary.certificate().getNotBefore(), primary.certificate().getNotAfter(),
                    subject, primary.certificate().getPublicKey());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            if (UNREACHABLE.equals(variant.id())) {
                // This local port is checked as closed by the native campaign. A timeout or
                // refusal at this endpoint alone is never a target verdict.
                var path = "http://samlscope-reference-suite:18481/samlscope-revocation/" + serial.toString(16);
                var name = new DistributionPointName(new GeneralNames(new GeneralName(
                        GeneralName.uniformResourceIdentifier, path + "/unavailable.crl")));
                builder.addExtension(Extension.cRLDistributionPoints, false,
                        new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(name, null, null) }));
                builder.addExtension(Extension.authorityInfoAccess, false,
                        new AuthorityInformationAccess(AccessDescription.id_ad_ocsp,
                                new GeneralName(GeneralName.uniformResourceIdentifier, path + "/unavailable.ocsp")));
            }
            return convert(builder, primary);
        } catch (Exception invalid) {
            throw new IllegalStateException("Cannot generate public revocation certificate", invalid);
        }
    }

    public static Element apply(Document document, Element root, PlanCredentials primary,
                                MetadataService.Variant variant, Instant now) {
        if (!supports(variant)) return root;
        try {
            root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:rev", NS);
            Element extensions = null;
            for (var child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof Element element && MetadataService.MD.equals(element.getNamespaceURI())
                        && "Extensions".equals(element.getLocalName())) extensions = element;
            }
            if (extensions == null) {
                extensions = document.createElementNS(MetadataService.MD, "md:Extensions");
                root.insertBefore(extensions, root.getFirstChild());
            }
            var original = document.createElementNS(NS, "rev:RevocationOriginals");
            original.setAttribute("variant", variant.id());
            extensions.appendChild(original);
            // The issuer is a public fixture original, not another role's accepted key.
            var ca = new JcaX509v3CertificateBuilder(ISSUER, serial(primary, "revocation-issuer"),
                    Date.from(primary.certificate().getNotBefore().toInstant().minus(1, ChronoUnit.DAYS)),
                    Date.from(primary.certificate().getNotAfter().toInstant().plus(1, ChronoUnit.DAYS)),
                    ISSUER, primary.certificate().getPublicKey());
            ca.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            ca.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            text(document, original, "IssuerCertificate", Base64.getEncoder().encodeToString(convert(ca, primary).getEncoded()));
            if (REVOKED.equals(variant.id())) {
                // Fix dates and serials to the Plan's existing certificate. RSA PKCS#1
                // signatures are deterministic, so repeated preparation preserves bytes.
                var issuance = primary.certificate().getNotBefore().toInstant();
                var crl = new X509v2CRLBuilder(ISSUER, Date.from(issuance.plusSeconds(1)));
                crl.setNextUpdate(primary.certificate().getNotAfter());
                var serials = new LinkedHashSet<BigInteger>();
                var certificates = root.getElementsByTagNameNS(MetadataService.DS, "X509Certificate");
                for (int index = 0; index < certificates.getLength(); index++) {
                    var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                            new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certificates.item(index).getTextContent())));
                    if (!ISSUER.equals(X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded()))) {
                        throw new IllegalArgumentException("Role certificate issuer differs from revocation fixture");
                    }
                    certificate.verify(primary.certificate().getPublicKey());
                    serials.add(certificate.getSerialNumber());
                }
                if (serials.isEmpty()) throw new IllegalArgumentException("No role certificate to revoke");
                for (var serial : serials) crl.addCRLEntry(serial, Date.from(issuance), CRLReason.keyCompromise);
                var signed = crl.build(new JcaContentSignerBuilder("SHA256withRSA").build(primary.privateKey()));
                text(document, original, "CRL", Base64.getEncoder().encodeToString(signed.getEncoded()));
            }
            return root;
        } catch (Exception invalid) {
            throw new IllegalStateException("Cannot attach public revocation originals", invalid);
        }
    }

    private static X509Certificate convert(JcaX509v3CertificateBuilder builder, PlanCredentials signer) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(signer.privateKey())));
    }

    private static BigInteger serial(PlanCredentials primary, String label) throws Exception {
        var digest = MessageDigest.getInstance("SHA-256");
        digest.update(primary.certificate().getPublicKey().getEncoded());
        digest.update(label.getBytes(StandardCharsets.UTF_8));
        return new BigInteger(1, java.util.Arrays.copyOf(digest.digest(), 19)).add(BigInteger.ONE);
    }

    private static void text(Document document, Element parent, String name, String value) {
        var child = document.createElementNS(NS, "rev:" + name);
        child.setTextContent(value);
        parent.appendChild(child);
    }
}
