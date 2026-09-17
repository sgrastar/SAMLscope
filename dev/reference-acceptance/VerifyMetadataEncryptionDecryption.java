import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.*;
import java.util.*;
import org.w3c.dom.Element;

/** Run inside the Suite container: existing private keys never leave its data directory. */
public final class VerifyMetadataEncryptionDecryption {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata", DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SAML = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static String hash(byte[] b) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)); }
    private static JsonNode read(Path p) throws Exception { return JSON.readTree(Files.readAllBytes(p)); }
    private static void require(boolean value) { if (!value) throw new IllegalArgumentException("Evidence binding failed"); }
    private static Path keyFolder(Path data, String plan, String variant) throws Exception {
        require(plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
        return data.resolve("keys").resolve(plan).resolve("poll-" + hash(variant.getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 16));
    }
    private static PrivateKey key(Path folder) throws Exception {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(folder.resolve("signing-key.pk8"))));
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("Expected evidence folder, Suite data directory and output file");
        Path folder = Path.of(args[0]), data = Path.of(args[1]);
        var result = read(folder.resolve("result.json"));
        var plan = read(folder.resolve("plan.json")).at("/plan/plan/id").asText();
        var proof = read(folder.resolve("verified-algorithm-signatures.json"));
        require(result.at("/run/id").asText().equals(proof.path("run").asText()));
        var originals = new HashMap<String,JsonNode>();
        for (var entry : read(folder.resolve("decoded-manifest.json"))) require(originals.put(entry.path("id").asText(), entry) == null);
        var outcomes = new ArrayList<Map<String,Object>>();
        var decrypt = new SamlXmlDecrypter();
        for (var signed : proof.path("observations")) {
            require(signed.path("signed_response_verified").asBoolean());
            var variant = signed.path("variant").asText();
            require(variant.matches("[a-z0-9-]+"));
            var keyFolder = keyFolder(data, plan, variant);
            var own = key(keyFolder);
            var wrong = key(keyFolder(data, plan, variant.equals("control") ? "algorithm-encryption-aes128-cbc" : "control"));
            var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                    Files.newInputStream(keyFolder.resolve("signing-certificate.der")));
            byte[] fixture = Files.readAllBytes(folder.resolve(variant).resolve("fixture.xml"));
            require(hash(fixture).equals(read(folder.resolve(variant).resolve("import.json")).path("fixture_sha256").asText()));
            var root = SecureXml.parse(fixture).getDocumentElement();
            var role = (Element) root.getElementsByTagNameNS(MD, "SPSSODescriptor").item(0);
            require(role != null);
            boolean matching = false;
            var keys = role.getElementsByTagNameNS(MD, "KeyDescriptor");
            for (int i = 0; i < keys.getLength(); i++) {
                var descriptor = (Element) keys.item(i);
                if ("signing".equals(descriptor.getAttribute("use"))) continue;
                var certs = descriptor.getElementsByTagNameNS(DS, "X509Certificate");
                for (int j = 0; j < certs.getLength(); j++) {
                    var advertised = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                            Base64.getDecoder().decode(certs.item(j).getTextContent().replaceAll("\\s+", ""))));
                    matching |= Arrays.equals(advertised.getPublicKey().getEncoded(), certificate.getPublicKey().getEncoded());
                }
            }
            require(matching);
            var original = originals.get(signed.path("response").asText());
            var path = folder.resolve(original.path("file").asText()).normalize();
            require(path.startsWith(folder.normalize()));
            byte[] raw = Files.readAllBytes(path);
            require(hash(raw).equals(original.path("sha256").asText()));
            var response = SecureXml.parse(raw).getDocumentElement();
            var assertions = response.getElementsByTagNameNS(SAML, "EncryptedAssertion");
            require(assertions.getLength() > 0);
            for (int i = 0; i < assertions.getLength(); i++) {
                var wrapper = (Element) assertions.item(i);
                var plain = decrypt.decrypt(wrapper, own);
                require(SAML.equals(plain.getNamespaceURI()) && "Assertion".equals(plain.getLocalName()));
                boolean rejected = false;
                try { decrypt.decrypt(wrapper, wrong); }
                catch (com.samlscope.saml.normal.SamlException expected) { rejected = true; }
                require(rejected);
            }
            outcomes.add(Map.of("variant", variant, "response", signed.path("response").asText(),
                    "decrypted_assertions", assertions.getLength(), "wrong_key_rejected", true,
                    "advertised_key_matched", true, "private_key_exported", false, "plaintext_persisted", false));
        }
        JSON.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(),
                Map.of("run", proof.path("run").asText(), "observations", outcomes,
                        "signed_evidence_sha256", hash(Files.readAllBytes(folder.resolve("verified-algorithm-signatures.json"))),
                        "affects_verdict", false));
        System.out.println("Decrypted with matched keys; wrong-key controls rejected: " + outcomes.size());
    }
}
