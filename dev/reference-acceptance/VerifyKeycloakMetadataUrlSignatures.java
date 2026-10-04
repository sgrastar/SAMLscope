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

/** Independent JDK verifier for Keycloak's MD01.a and MD02.a signed-request originals. */
public final class VerifyKeycloakMetadataUrlSignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static void main(String[] args) throws Exception {
        if (args.length == 2) {
            var keys = keys(Path.of(args[0]));
            if (keys.isEmpty() || !valid(request(Path.of(args[1])), keys)) {
                throw new IllegalArgumentException("MDQ request is not signed by acquired metadata key");
            }
            System.out.println("{\"mdq_valid\":true,\"keys\":" + keys.size() + "}");
            return;
        }
        if (args.length != 6) {
            throw new IllegalArgumentException(
                    "metadataA requestA metadataB requestB invalidB oldA required");
        }
        var a = keys(Path.of(args[0]));
        var b = keys(Path.of(args[2]));
        if (a.isEmpty() || b.isEmpty() || !disjoint(a, b)) {
            throw new IllegalArgumentException("Metadata signing keys are absent or overlap");
        }
        var requestA = request(Path.of(args[1]));
        var requestB = request(Path.of(args[3]));
        var invalidB = request(Path.of(args[4]));
        var oldA = request(Path.of(args[5]));
        if (!valid(requestA, a) || valid(requestA, b)
                || !valid(requestB, b) || valid(requestB, a)
                || valid(invalidB, a) || valid(invalidB, b)
                || !valid(oldA, a) || valid(oldA, b)) {
            throw new IllegalArgumentException("A/B/invalid/old-key signature control failed");
        }
        System.out.println("{\"a_valid\":true,\"b_valid\":true,"
                + "\"invalid_b_valid\":false,\"old_a_valid\":true,"
                + "\"old_a_valid_with_b\":false,\"a_keys\":" + a.size()
                + ",\"b_keys\":" + b.size() + "}");
    }

    private static List<X509Certificate> keys(Path path) throws Exception {
        var root = parse(Files.readAllBytes(path)).getDocumentElement();
        if (!MD.equals(root.getNamespaceURI()) || !"EntityDescriptor".equals(root.getLocalName())) {
            throw new IllegalArgumentException("Metadata root must be EntityDescriptor");
        }
        var roles = root.getElementsByTagNameNS(MD, "SPSSODescriptor");
        if (roles.getLength() != 1) throw new IllegalArgumentException("Exactly one SP role required");
        var descriptors = ((Element) roles.item(0)).getElementsByTagNameNS(MD, "KeyDescriptor");
        var result = new ArrayList<X509Certificate>();
        var factory = CertificateFactory.getInstance("X.509");
        for (int index = 0; index < descriptors.getLength(); index++) {
            var descriptor = (Element) descriptors.item(index);
            var use = descriptor.getAttribute("use");
            if (!use.isBlank() && !"signing".equals(use)) continue;
            var nodes = descriptor.getElementsByTagNameNS(DS, "X509Certificate");
            for (int item = 0; item < nodes.getLength(); item++) {
                var raw = Base64.getDecoder().decode(nodes.item(item).getTextContent().replaceAll("\\s+", ""));
                result.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(raw)));
            }
        }
        return List.copyOf(result);
    }

    private static Element request(Path path) throws Exception {
        var root = parse(Files.readAllBytes(path)).getDocumentElement();
        if (!P.equals(root.getNamespaceURI()) || !"AuthnRequest".equals(root.getLocalName())
                || root.getAttribute("ID").isBlank()) {
            throw new IllegalArgumentException("Signed original is not an AuthnRequest");
        }
        root.setIdAttribute("ID", true);
        return root;
    }

    private static boolean valid(Element request, List<X509Certificate> keys) {
        Element signatureElement = null;
        for (var child = request.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && DS.equals(element.getNamespaceURI())
                    && "Signature".equals(element.getLocalName())) {
                if (signatureElement != null) return false;
                signatureElement = element;
            }
        }
        if (signatureElement == null) return false;
        for (var key : keys) {
            try {
                var context = new DOMValidateContext(key.getPublicKey(), signatureElement);
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                var signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
                var references = signature.getSignedInfo().getReferences();
                if (references.size() == 1
                        && ("#" + request.getAttribute("ID")).equals(references.getFirst().getURI())
                        && signature.validate(context)) {
                    return true;
                }
            } catch (Exception ignored) { }
        }
        return false;
    }

    private static boolean disjoint(List<X509Certificate> a, List<X509Certificate> b) throws Exception {
        var values = new HashSet<String>();
        for (var key : a) values.add(hash(key.getPublicKey().getEncoded()));
        for (var key : b) if (values.contains(hash(key.getPublicKey().getEncoded()))) return false;
        return true;
    }

    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
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
}
