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
import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Verifies direct Response signatures while permitting a separately signed Assertion. */
public final class VerifyMetadataValidityResponseSignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String RSA_SHA256 =
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            throw new IllegalArgumentException("target metadata and Response originals required");
        }
        var metadata = parse(Files.readAllBytes(Path.of(args[0]))).getDocumentElement();
        if (!MD.equals(metadata.getNamespaceURI())
                || !"EntityDescriptor".equals(metadata.getLocalName())) {
            throw new IllegalArgumentException("Target metadata is not an EntityDescriptor");
        }
        var entityId = metadata.getAttribute("entityID");
        if (entityId.isBlank()) throw new IllegalArgumentException("Target entityID is missing");
        var descriptors = metadata.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (descriptors.getLength() != 1) {
            throw new IllegalArgumentException("Exactly one IDPSSODescriptor required");
        }
        var encodedCertificates = new HashSet<String>();
        var keys = ((Element) descriptors.item(0)).getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int keyIndex = 0; keyIndex < keys.getLength(); keyIndex++) {
            var key = (Element) keys.item(keyIndex);
            var use = key.getAttribute("use");
            if (!use.isBlank() && !"signing".equals(use)) continue;
            var certificates = key.getElementsByTagNameNS(DS, "X509Certificate");
            for (int certIndex = 0; certIndex < certificates.getLength(); certIndex++) {
                encodedCertificates.add(
                        certificates.item(certIndex).getTextContent().replaceAll("\\s+", ""));
            }
        }
        if (encodedCertificates.size() != 1) {
            throw new IllegalArgumentException("Exactly one target signing certificate required");
        }
        var encoded = encodedCertificates.iterator().next();
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encoded)));
        var responseIds = new HashSet<String>();
        for (int index = 1; index < args.length; index++) {
            var response = parse(Files.readAllBytes(Path.of(args[index]))).getDocumentElement();
            if (!P.equals(response.getNamespaceURI()) || !"Response".equals(response.getLocalName())) {
                throw new IllegalArgumentException("Not a SAML Response");
            }
            var id = response.getAttribute("ID");
            if (id.isBlank() || !responseIds.add(id)) {
                throw new IllegalArgumentException("Missing or duplicate Response ID");
            }
            response.setIdAttribute("ID", true);
            var direct = new ArrayList<Element>();
            for (Node child = response.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof Element element && DS.equals(element.getNamespaceURI())
                        && "Signature".equals(element.getLocalName())) {
                    direct.add(element);
                }
            }
            if (direct.size() != 1) {
                throw new IllegalArgumentException("Exactly one direct Response Signature required");
            }
            var signatureElement = direct.getFirst();
            var embedded = signatureElement.getElementsByTagNameNS(DS, "X509Certificate");
            if (embedded.getLength() != 1
                    || !encoded.equals(embedded.item(0).getTextContent().replaceAll("\\s+", ""))) {
                throw new IllegalArgumentException("Wire certificate differs from target metadata");
            }
            var context = new DOMValidateContext(certificate.getPublicKey(), signatureElement);
            context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
            if (signature.getSignedInfo().getReferences().size() != 1
                    || !("#" + id).equals(signature.getSignedInfo().getReferences().getFirst().getURI())
                    || !RSA_SHA256.equals(signature.getSignedInfo().getSignatureMethod().getAlgorithm())
                    || !signature.validate(context)) {
                throw new IllegalArgumentException("Invalid or incorrectly scoped Response signature");
            }
        }
        System.out.printf("{\"entityId\":\"%s\",\"certificateSha256\":\"%s\","
                        + "\"responses\":%d}%n",
                entityId, sha(certificate.getEncoded()), responseIds.size());
    }

    private static org.w3c.dom.Document parse(byte[] raw) throws Exception {
        var upper = new String(raw, java.nio.charset.StandardCharsets.UTF_8).toUpperCase();
        if (upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")) {
            throw new IllegalArgumentException("DTD/entity is forbidden");
        }
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
