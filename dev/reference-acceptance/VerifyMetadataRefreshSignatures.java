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

/** Independent JDK verifier for the MD02.a changed-key control. */
public final class VerifyMetadataRefreshSignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static void main(String[] args) throws Exception {
        if (args.length != 5) {
            throw new IllegalArgumentException("metadataA requestA metadataB requestB invalidRequestB required");
        }
        var a = keys(Path.of(args[0]));
        var b = keys(Path.of(args[2]));
        if (a.isEmpty() || b.isEmpty() || !disjoint(a, b)) {
            throw new IllegalArgumentException("Metadata signing keys are absent or overlap");
        }
        var requestA = request(Path.of(args[1]));
        var requestB = request(Path.of(args[3]));
        var invalidRequestB = request(Path.of(args[4]));
        if (!valid(requestA, a) || !valid(requestB, b) || valid(requestB, a)
                || valid(invalidRequestB, b) || valid(invalidRequestB, a)) {
            throw new IllegalArgumentException("A/B request signature control failed");
        }
        System.out.println("{\"a_valid\":true,\"b_valid\":true,\"b_valid_with_a\":false,"
                + "\"invalid_b_valid_with_b\":false,\"invalid_b_valid_with_a\":false,"
                + "\"a_keys\":" + a.size() + ",\"b_keys\":" + b.size() + "}");
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
            for (int certificate = 0; certificate < nodes.getLength(); certificate++) {
                var raw = Base64.getDecoder().decode(nodes.item(certificate).getTextContent().replaceAll("\\s+", ""));
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
        var signatures = request.getElementsByTagNameNS(DS, "Signature");
        if (signatures.getLength() != 1) return false;
        for (var key : keys) {
            try {
                var context = new DOMValidateContext(key.getPublicKey(), signatures.item(0));
                context.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
                if (XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context).validate(context)) {
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
