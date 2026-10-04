import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Deterministic, dependency-free inventory of every Keycloak runtime JAR. */
public final class KeycloakAllJarNativeScan {
    private static final List<String> TERMS = List.of(
            "ClientDescriptionConverter",
            "ClientRegistrationProvider",
            "EntityDescriptorDescriptionConverter",
            "EntityDescriptorClientRegistrationProvider",
            "saml2-entity-descriptor",
            "Expected one entity descriptor",
            "EntitiesDescriptorType",
            "metadataDescriptorUrl",
            "saml.metadataDescriptorUrl",
            "saml.useMetadataDescriptorUrl",
            "trustAnchor",
            "validateCertificate",
            "SignatureValidation",
            "DynamicHTTPMetadataProvider",
            "MetadataProvider",
            "MDQ");

    private record JarRecord(String path, long size, String sha256) {}
    private record ServiceRecord(String sha256, String base64) {}

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String sha256(Path value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(value)) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static String json(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        return out.append('\"').toString();
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        outer: for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("usage: <jar-root> <output>");
        Path root = Path.of(args[0]).toRealPath();
        Path output = Path.of(args[1]);
        List<Path> jars;
        try (var paths = Files.walk(root)) {
            jars = paths.filter(path -> Files.isRegularFile(path) && path.toString().endsWith(".jar"))
                    .sorted(Comparator.comparing(Path::toString)).toList();
        }
        List<JarRecord> records = new ArrayList<>();
        Map<String, List<String>> termHits = new TreeMap<>();
        Map<String, ServiceRecord> services = new TreeMap<>();
        for (Path jar : jars) {
            records.add(new JarRecord(jar.toString(), Files.size(jar), sha256(jar)));
            try (JarFile archive = new JarFile(jar.toFile(), false)) {
                var entries = archive.stream().filter(entry -> !entry.isDirectory())
                        .sorted(Comparator.comparing(JarEntry::getName)).toList();
                for (JarEntry entry : entries) {
                    boolean service = entry.getName().startsWith("META-INF/services/");
                    boolean classFile = entry.getName().endsWith(".class");
                    if (!service && !classFile) continue;
                    byte[] raw;
                    try (InputStream input = archive.getInputStream(entry)) {
                        raw = input.readAllBytes();
                    }
                    String identity = jar + "!" + entry.getName();
                    if (service) {
                        services.put(identity, new ServiceRecord(sha256(raw),
                                Base64.getEncoder().encodeToString(raw)));
                    }
                    List<String> hits = new ArrayList<>();
                    for (String term : TERMS) {
                        if (contains(raw, term.getBytes(StandardCharsets.UTF_8))) hits.add(term);
                    }
                    if (!hits.isEmpty()) termHits.put(identity, hits);
                }
            } catch (IOException error) {
                throw new IOException("failed to scan " + jar, error);
            }
        }
        StringBuilder value = new StringBuilder();
        value.append("{\"schema\":\"samlscope-keycloak-all-jars-native-scan-v1\"");
        value.append(",\"root\":").append(json(root.toString()));
        value.append(",\"terms\":[");
        for (int i = 0; i < TERMS.size(); i++) {
            if (i > 0) value.append(',');
            value.append(json(TERMS.get(i)));
        }
        value.append("],\"jarCount\":").append(records.size()).append(",\"jars\":[");
        for (int i = 0; i < records.size(); i++) {
            if (i > 0) value.append(',');
            JarRecord record = records.get(i);
            value.append("{\"path\":").append(json(record.path()))
                    .append(",\"sha256\":").append(json(record.sha256()))
                    .append(",\"size\":").append(record.size()).append('}');
        }
        value.append("],\"termHits\":{");
        int index = 0;
        for (var item : termHits.entrySet()) {
            if (index++ > 0) value.append(',');
            value.append(json(item.getKey())).append(":[");
            for (int i = 0; i < item.getValue().size(); i++) {
                if (i > 0) value.append(',');
                value.append(json(item.getValue().get(i)));
            }
            value.append(']');
        }
        value.append("},\"serviceEntries\":{");
        index = 0;
        for (var item : services.entrySet()) {
            if (index++ > 0) value.append(',');
            value.append(json(item.getKey())).append(":{\"sha256\":")
                    .append(json(item.getValue().sha256())).append(",\"base64\":")
                    .append(json(item.getValue().base64())).append('}');
        }
        value.append("}}\n");
        Files.writeString(output, value.toString(), StandardCharsets.UTF_8);
    }
}
