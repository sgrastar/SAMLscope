import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.jar.JarFile;

/** Read-only inventory of the pinned Keycloak runtime's algorithm policy surfaces. */
public final class KeycloakAlgorithmPolicyScan {
    private static final List<String> TERMS = List.of(
            "saml.encryption.keyAlgorithm", "saml.encryption.algorithm", "rsa-1_5",
            "RSA_1_5", "RSA1_5", "blockedAlgorithms", "disabledAlgorithms",
            "deniedAlgorithms", "allowedAlgorithms", "algorithmBlacklist",
            "algorithmWhitelist", "AlgorithmPolicy", "SignatureAlgorithm",
            "EncryptionAlgorithm", "SamlClient", "SAMLClient", "XMLCipher");

    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
    private static boolean has(byte[] haystack, String needle) {
        byte[] token = needle.getBytes(StandardCharsets.UTF_8);
        outer: for (int i = 0; i <= haystack.length - token.length; i++) {
            for (int j = 0; j < token.length; j++) if (haystack[i + j] != token[j]) continue outer;
            return true;
        }
        return false;
    }
    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("usage: jar-root output");
        Path root = Path.of(args[0]).toRealPath();
        var jars = new ArrayList<Path>();
        try (var stream = Files.walk(root)) {
            stream.filter(p -> Files.isRegularFile(p) && p.toString().endsWith(".jar"))
                    .sorted(Comparator.comparing(Path::toString)).forEach(jars::add);
        }
        var rows = new ArrayList<String>();
        for (Path path : jars) {
            try (var jar = new JarFile(path.toFile(), false)) {
                for (var entry : jar.stream().filter(e -> !e.isDirectory()).toList()) {
                    if (!entry.getName().endsWith(".class") && !entry.getName().startsWith("META-INF/services/")) continue;
                    byte[] raw;
                    try (InputStream input = jar.getInputStream(entry)) { raw = input.readAllBytes(); }
                    var hits = TERMS.stream().filter(term -> has(raw, term)).toList();
                    if (!hits.isEmpty()) {
                        rows.add("{\"jar\":" + quote(path.toString()) + ",\"entry\":"
                                + quote(entry.getName()) + ",\"sha256\":" + quote(hash(raw))
                                + ",\"terms\":[" + String.join(",", hits.stream().map(KeycloakAlgorithmPolicyScan::quote).toList()) + "]}");
                    }
                }
            }
        }
        String json = "{\"schema\":\"samlscope-keycloak-algorithm-policy-scan-v1\",\"root\":"
                + quote(root.toString()) + ",\"jarCount\":" + jars.size() + ",\"terms\":["
                + String.join(",", TERMS.stream().map(KeycloakAlgorithmPolicyScan::quote).toList())
                + "],\"hits\":[" + String.join(",", rows) + "]}\n";
        Files.writeString(Path.of(args[1]), json, StandardCharsets.UTF_8);
    }
}
