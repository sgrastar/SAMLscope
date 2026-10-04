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

/** Independent JDK verifier for each MD04 validity fixture's request signature controls. */
public final class VerifyMetadataValiditySignatures {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args.length % 3 != 0) {
            throw new IllegalArgumentException("metadata validRequest invalidRequest triples required");
        }
        var fingerprints = new HashSet<String>();
        var results = new ArrayList<String>();
        for (int index = 0; index < args.length; index += 3) {
            var keys = keys(Path.of(args[index]));
            if (keys.size() != 1) throw new IllegalArgumentException("Exactly one signing key required");
            var fingerprint = hash(keys.getFirst().getPublicKey().getEncoded());
            if (!fingerprints.add(fingerprint)) {
                throw new IllegalArgumentException("Fixture signing keys must be pairwise disjoint");
            }
            var valid = request(Path.of(args[index + 1]));
            var invalid = request(Path.of(args[index + 2]));
            if (!valid(valid, keys) || valid(invalid, keys)) {
                throw new IllegalArgumentException("Valid/invalid request signature control failed");
            }
            results.add("{\"key\":\"" + fingerprint + "\",\"valid\":true,\"invalid\":false}");
        }
        System.out.println("{\"fixtures\":[" + String.join(",", results) + "]}");
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
                var raw = Base64.getDecoder().decode(
                        nodes.item(certificate).getTextContent().replaceAll("\\s+", ""));
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
                if (XMLSignatureFactory.getInstance("DOM")
                        .unmarshalXMLSignature(context).validate(context)) return true;
            } catch (Exception ignored) { }
        }
        return false;
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
