import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.keycloak.rotation.KeyLocator;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.keycloak.saml.processing.core.saml.v2.util.DocumentUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Runs the installed Keycloak SAML implementation's RSA-SHA1 metadata signer and verifier.
 *
 * <p>This helper does not assign a SAMLscope outcome. It emits exact positive and negative
 * observations. The caller runs {@code default} with the container's normal Java security policy,
 * then {@code capability} in a separate process whose only override removes the XML-DSig
 * RSA/SHA-1 deny-list. This distinguishes a policy-disabled algorithm from an absent native
 * implementation without changing the running Keycloak server.</p>
 */
public final class KeycloakRsaSha1MetadataCapability {
    private static final String SCHEMA = "samlscope-keycloak-rsa-sha1-verification-v1";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String RSA_SHA1 = DS + "rsa-sha1";
    private static final String DIGEST_SHA1 = DS + "sha1";
    private static final String C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private KeycloakRsaSha1MetadataCapability() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 5 || !(args[0].equals("default") || args[0].equals("capability"))) {
            throw new IllegalArgumentException(
                    "default|capability input.xml private-pkcs8.der certificate.der wrong-certificate.der");
        }
        var mode = args[0];
        var input = Files.readAllBytes(Path.of(args[1]));
        var certificate = certificate(args[3]);
        var wrongCertificate = certificate(args[4]);
        byte[] signed;
        if (mode.equals("default")) {
            signed = sign(input, privateKey(args[2]), certificate);
            Files.write(Path.of(args[1] + ".signed"), signed);
        } else {
            signed = input;
        }

        var document = parse(signed);
        var root = document.getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        var entityId = root.getAttribute("entityID");
        require(!entityId.isBlank());
        var methods = document.getElementsByTagNameNS(DS, "SignatureMethod");
        require(methods.getLength() == 1
                && RSA_SHA1.equals(((Element) methods.item(0)).getAttribute("Algorithm")));

        var tamperedDocument = parse(signed);
        tamperedDocument.getDocumentElement().setAttribute("entityID", entityId + "#tampered");
        var tampered = serialize(tamperedDocument);
        var unsignedDocument = parse(signed);
        var signatures = unsignedDocument.getDocumentElement().getElementsByTagNameNS(DS, "Signature");
        require(signatures.getLength() == 1);
        var signature = signatures.item(0);
        signature.getParentNode().removeChild(signature);
        var unsigned = serialize(unsignedDocument);

        var positive = validate(signed, certificate.getPublicKey());
        var changed = validate(tampered, certificate.getPublicKey());
        var wrong = validate(signed, wrongCertificate.getPublicKey());
        var absent = validate(unsigned, certificate.getPublicKey());
        var output = "{\n"
                + field("schema", SCHEMA) + ",\n"
                + field("policyMode", mode) + ",\n"
                + field("inputSha256", hash(signed)) + ",\n"
                + field("targetEntityId", entityId) + ",\n"
                + field("signatureAlgorithm", SignatureAlgorithm.RSA_SHA1.getXmlSignatureMethod()) + ",\n"
                + field("trustedCertificateSha256", hash(certificate.getEncoded())) + ",\n"
                + field("wrongCertificateSha256", hash(wrongCertificate.getEncoded())) + ",\n"
                + field("tamperedInputBase64", Base64.getEncoder().encodeToString(tampered)) + ",\n"
                + field("tamperedInputSha256", hash(tampered)) + ",\n"
                + field("unsignedInputBase64", Base64.getEncoder().encodeToString(unsigned)) + ",\n"
                + field("unsignedInputSha256", hash(unsigned)) + ",\n"
                + boolField("positiveAccepted", positive.accepted()) + ",\n"
                + field("positiveError", positive.error()) + ",\n"
                + boolField("tamperedAccepted", changed.accepted()) + ",\n"
                + boolField("wrongKeyAccepted", wrong.accepted()) + ",\n"
                + boolField("unsignedAccepted", absent.accepted()) + "\n}\n";
        System.out.print(output);

        var correct = mode.equals("default")
                ? !positive.accepted() && positive.error().contains("secure validation is enabled")
                : positive.accepted();
        if (!correct || changed.accepted() || wrong.accepted() || absent.accepted()) System.exit(2);
    }

    private static byte[] sign(byte[] unsigned, PrivateKey privateKey, X509Certificate certificate)
            throws Exception {
        var document = parse(unsigned);
        var root = document.getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        if (root.getAttribute("ID").isBlank()) root.setAttribute("ID", "_samlscope_keycloak_rsa_sha1");
        var signature = new SAML2Signature();
        signature.setSignatureMethod(RSA_SHA1);
        signature.setDigestMethod(DIGEST_SHA1);
        signature.setX509Certificate(certificate);
        signature.setNextSibling(root.getFirstChild());
        signature.signSAMLDocument(document, "samlscope-keycloak-md05ah",
                new KeyPair(certificate.getPublicKey(), privateKey), C14N);
        return serialize(document);
    }

    private static Validation validate(byte[] raw, PublicKey key) {
        try {
            return new Validation(new SAML2Signature().validate(parse(raw), new FixedLocator(key)), "");
        } catch (Exception error) {
            var message = error.toString();
            for (var cause = error.getCause(); cause != null; cause = cause.getCause()) {
                message += " | " + cause;
            }
            return new Validation(false, message);
        }
    }

    private static Document parse(byte[] raw) throws Exception {
        return DocumentUtil.getDocument(new String(raw, StandardCharsets.UTF_8));
    }

    private static byte[] serialize(Document document) throws Exception {
        var transformer = TransformerFactory.newInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        var output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    private static PrivateKey privateKey(String path) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Files.readAllBytes(Path.of(path))));
    }

    private static X509Certificate certificate(String path) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(Files.readAllBytes(Path.of(path))));
    }

    private static String field(String name, String value) {
        return "  \"" + name + "\": \"" + escape(value) + "\"";
    }

    private static String boolField(String name, boolean value) {
        return "  \"" + name + "\": " + value;
    }

    private static String escape(String value) {
        var result = new StringBuilder();
        for (int index = 0; index < value.length(); index++) {
            var character = value.charAt(index);
            switch (character) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (character < 0x20) result.append(String.format("\\u%04x", (int) character));
                    else result.append(character);
                }
            }
        }
        return result.toString();
    }

    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("Keycloak RSA-SHA1 probe invariant failed");
    }

    private record Validation(boolean accepted, String error) {}

    private static final class FixedLocator implements KeyLocator {
        private final PublicKey key;

        FixedLocator(PublicKey key) {
            this.key = key;
        }

        @Override
        public Key getKey(String name) {
            return key;
        }

        @Override
        public void refreshKeyCache() {}

        @Override
        public Iterator<Key> iterator() {
            return List.<Key>of(key).iterator();
        }
    }
}
