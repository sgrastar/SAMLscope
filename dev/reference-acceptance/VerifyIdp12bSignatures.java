import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Independently verifies the signed/unsigned wire matrix against the published Suite certificate. */
public final class VerifyIdp12bSignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static void main(String[] args) throws Exception {
        if (args.length < 3 || (args.length - 1) % 2 != 0) {
            throw new IllegalArgumentException("metadata followed by request/boolean pairs required");
        }
        var metadata = parse(Files.readAllBytes(Path.of(args[0]))).getDocumentElement();
        var encodedCertificates = new HashSet<String>();
        var spDescriptors = metadata.getElementsByTagNameNS(MD, "SPSSODescriptor");
        for (int descriptorIndex = 0; descriptorIndex < spDescriptors.getLength(); descriptorIndex++) {
            var descriptor = (Element) spDescriptors.item(descriptorIndex);
            var keyDescriptors = descriptor.getElementsByTagNameNS(MD, "KeyDescriptor");
            for (int keyIndex = 0; keyIndex < keyDescriptors.getLength(); keyIndex++) {
                var keyDescriptor = (Element) keyDescriptors.item(keyIndex);
                if (!"signing".equals(keyDescriptor.getAttribute("use"))) continue;
                var certificates = keyDescriptor.getElementsByTagNameNS(DS, "X509Certificate");
                for (int certIndex = 0; certIndex < certificates.getLength(); certIndex++) {
                    encodedCertificates.add(certificates.item(certIndex).getTextContent().replaceAll("\\s+", ""));
                }
            }
        }
        if (encodedCertificates.size() != 1) {
            throw new IllegalArgumentException("Metadata must contain exactly one distinct SP signing certificate");
        }
        var encoded = encodedCertificates.iterator().next();
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        var certSha = sha(certificate.getEncoded());
        for (int i = 1; i < args.length; i += 2) {
            var document = parse(Files.readAllBytes(Path.of(args[i])));
            var request = document.getDocumentElement();
            if (!P.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName())) {
                throw new IllegalArgumentException("Not an AuthnRequest: " + args[i]);
            }
            boolean expectedSigned = Boolean.parseBoolean(args[i + 1]);
            var signatures = request.getElementsByTagNameNS(DS, "Signature");
            if (!expectedSigned) {
                if (signatures.getLength() != 0) throw new IllegalArgumentException("Unsigned fixture has Signature");
                continue;
            }
            if (signatures.getLength() != 1) throw new IllegalArgumentException("Signed fixture needs one Signature");
            if (!request.hasAttribute("ID")) throw new IllegalArgumentException("Signed request lacks ID");
            request.setIdAttribute("ID", true);
            var signatureElement = (Element) signatures.item(0);
            var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
            context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
            if (!signature.validate(context)) throw new IllegalArgumentException("Invalid request signature: " + args[i]);
            var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
            if (embedded.getLength() != 1) throw new IllegalArgumentException("Signed request certificate missing");
            var wireCert = embedded.item(0).getTextContent().replaceAll("\\s+", "");
            if (!encoded.equals(wireCert)) throw new IllegalArgumentException("Wire certificate differs from metadata");
        }
        System.out.printf("{\"metadataCertificateSha256\":\"%s\"}%n", certSha);
    }

    private static org.w3c.dom.Document parse(byte[] raw) throws Exception {
        var factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(raw));
    }

    private static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
}
