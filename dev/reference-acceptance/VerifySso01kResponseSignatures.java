import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Independently verifies the signed SSO01.k Response originals against target metadata. */
public final class VerifySso01kResponseSignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && "--requests".equals(args[0])) {
            verifyRequests(java.util.Arrays.copyOfRange(args, 1, args.length));
            return;
        }
        if (args.length > 0 && "--responses".equals(args[0])) {
            args = java.util.Arrays.copyOfRange(args, 1, args.length);
        }
        if (args.length < 2) {
            throw new IllegalArgumentException("target metadata followed by Response originals required");
        }
        var metadata = parse(Files.readAllBytes(Path.of(args[0]))).getDocumentElement();
        if (!MD.equals(metadata.getNamespaceURI()) || !"EntityDescriptor".equals(metadata.getLocalName())) {
            throw new IllegalArgumentException("Target metadata is not an EntityDescriptor");
        }
        var entityId = metadata.getAttribute("entityID");
        if (entityId.isBlank()) throw new IllegalArgumentException("Target entityID is missing");

        var encodedCertificates = new HashSet<String>();
        var idpDescriptors = metadata.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (idpDescriptors.getLength() != 1) {
            throw new IllegalArgumentException("Target metadata must contain exactly one IDPSSODescriptor");
        }
        var descriptor = (Element) idpDescriptors.item(0);
        var keyDescriptors = descriptor.getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int keyIndex = 0; keyIndex < keyDescriptors.getLength(); keyIndex++) {
            var keyDescriptor = (Element) keyDescriptors.item(keyIndex);
            var use = keyDescriptor.getAttribute("use");
            if (!use.isBlank() && !"signing".equals(use)) continue;
            var certificates = keyDescriptor.getElementsByTagNameNS(DS, "X509Certificate");
            for (int certIndex = 0; certIndex < certificates.getLength(); certIndex++) {
                encodedCertificates.add(certificates.item(certIndex).getTextContent().replaceAll("\\s+", ""));
            }
        }
        if (encodedCertificates.size() != 1) {
            throw new IllegalArgumentException("Target metadata must contain one distinct signing certificate");
        }
        var encoded = encodedCertificates.iterator().next();
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        var responseIds = new ArrayList<String>();

        for (int index = 1; index < args.length; index++) {
            var document = parse(Files.readAllBytes(Path.of(args[index])));
            var response = document.getDocumentElement();
            if (!P.equals(response.getNamespaceURI()) || !"Response".equals(response.getLocalName())) {
                throw new IllegalArgumentException("Not a SAML Response: " + args[index]);
            }
            var id = response.getAttribute("ID");
            if (id.isBlank() || responseIds.contains(id)) {
                throw new IllegalArgumentException("Missing or duplicate Response ID");
            }
            response.setIdAttribute("ID", true);
            var signatures = response.getElementsByTagNameNS(DS, "Signature");
            if (signatures.getLength() != 1) {
                throw new IllegalArgumentException("Response needs exactly one Signature: " + id);
            }
            var signatureElement = (Element) signatures.item(0);
            if (signatureElement.getParentNode() != response) {
                throw new IllegalArgumentException("Response Signature is not a direct child: " + id);
            }
            var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
            if (embedded.getLength() != 1
                    || !encoded.equals(embedded.item(0).getTextContent().replaceAll("\\s+", ""))) {
                throw new IllegalArgumentException("Wire certificate differs from target metadata: " + id);
            }
            var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
            context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
            if (signature.getSignedInfo().getReferences().size() != 1
                    || !("#" + id).equals(signature.getSignedInfo().getReferences().getFirst().getURI())
                    || !RSA_SHA256.equals(signature.getSignedInfo().getSignatureMethod().getAlgorithm())
                    || !signature.validate(context)) {
                throw new IllegalArgumentException("Invalid or incorrectly scoped Response signature: " + id);
            }
            responseIds.add(id);
        }

        System.out.printf(
                "{\"entityId\":\"%s\",\"certificateSha256\":\"%s\",\"responses\":%d}%n",
                entityId, sha(certificate.getEncoded()), responseIds.size());
    }

    private static void verifyRequests(String[] args) throws Exception {
        if (args.length < 3 || args.length % 2 == 0) {
            throw new IllegalArgumentException(
                    "Suite metadata followed by expected-valid/request pairs required");
        }
        var metadata = parse(Files.readAllBytes(Path.of(args[0]))).getDocumentElement();
        var encodedCertificates = new HashSet<String>();
        var spDescriptors = metadata.getElementsByTagNameNS(MD, "SPSSODescriptor");
        if (spDescriptors.getLength() != 1) {
            throw new IllegalArgumentException("Suite metadata must contain one SPSSODescriptor");
        }
        var descriptor = (Element) spDescriptors.item(0);
        var keyDescriptors = descriptor.getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int keyIndex = 0; keyIndex < keyDescriptors.getLength(); keyIndex++) {
            var keyDescriptor = (Element) keyDescriptors.item(keyIndex);
            if (!"signing".equals(keyDescriptor.getAttribute("use"))) continue;
            var certificates = keyDescriptor.getElementsByTagNameNS(DS, "X509Certificate");
            for (int certIndex = 0; certIndex < certificates.getLength(); certIndex++) {
                encodedCertificates.add(certificates.item(certIndex).getTextContent().replaceAll("\\s+", ""));
            }
        }
        if (encodedCertificates.size() != 1) {
            throw new IllegalArgumentException("Suite metadata must contain one SP signing certificate");
        }
        var encoded = encodedCertificates.iterator().next();
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        int validCount = 0;
        int invalidCount = 0;
        for (int index = 1; index < args.length; index += 2) {
            boolean expectedValid = Boolean.parseBoolean(args[index]);
            var request = parse(Files.readAllBytes(Path.of(args[index + 1]))).getDocumentElement();
            if (!P.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName())
                    || !request.hasAttribute("ID")) {
                throw new IllegalArgumentException("Not an identified AuthnRequest");
            }
            request.setIdAttribute("ID", true);
            var signatures = request.getElementsByTagNameNS(DS, "Signature");
            if (signatures.getLength() != 1) {
                throw new IllegalArgumentException("AuthnRequest needs exactly one Signature");
            }
            var signatureElement = (Element) signatures.item(0);
            var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
            if (embedded.getLength() != 1
                    || !encoded.equals(embedded.item(0).getTextContent().replaceAll("\\s+", ""))) {
                throw new IllegalArgumentException("AuthnRequest certificate differs from Suite metadata");
            }
            boolean valid;
            try {
                var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
                valid = signature.getSignedInfo().getReferences().size() == 1
                        && ("#" + request.getAttribute("ID")).equals(
                                signature.getSignedInfo().getReferences().getFirst().getURI())
                        && RSA_SHA256.equals(signature.getSignedInfo().getSignatureMethod().getAlgorithm())
                        && signature.validate(context);
            } catch (Exception invalidSignature) {
                valid = false;
            }
            if (valid != expectedValid) {
                throw new IllegalArgumentException("Unexpected AuthnRequest signature state");
            }
            if (valid) validCount++; else invalidCount++;
        }
        System.out.printf("{\"valid\":%d,\"invalid\":%d}%n", validCount, invalidCount);
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
