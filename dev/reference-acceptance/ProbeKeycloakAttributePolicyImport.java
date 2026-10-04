import java.lang.reflect.*;
import java.nio.file.*;
import java.util.*;

/** Read-only invocation of Keycloak's installed metadata-to-client converter. */
public final class ProbeKeycloakAttributePolicyImport {
    private static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof String text) return "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        if (value instanceof Map<?,?> map) {
            var keys = map.keySet().stream().map(Object::toString).sorted().toList();
            var parts = new ArrayList<String>();
            for (var key : keys) parts.add(json(key) + ":" + json(map.get(key)));
            return "{" + String.join(",", parts) + "}";
        }
        if (value instanceof Collection<?> collection) {
            return "[" + String.join(",", collection.stream().map(ProbeKeycloakAttributePolicyImport::json).toList()) + "]";
        }
        throw new IllegalArgumentException("Unsupported JSON value");
    }

    @SuppressWarnings("unchecked")
    private static Map<String,Object> probe(Path path) throws Exception {
        var converterClass = Class.forName("org.keycloak.protocol.saml.EntityDescriptorDescriptionConverter");
        var converter = converterClass.getConstructor().newInstance();
        var client = converterClass.getMethod("convertToInternal", String.class)
                .invoke(converter, Files.readString(path));
        var type = client.getClass();
        var mappers = new ArrayList<Map<String,Object>>();
        var mapperValues = (Collection<Object>) type.getMethod("getProtocolMappers").invoke(client);
        if (mapperValues != null) for (var mapper : mapperValues) {
            var mapperType = mapper.getClass();
            mappers.add(Map.of("name", mapperType.getMethod("getName").invoke(mapper),
                    "protocol", mapperType.getMethod("getProtocol").invoke(mapper),
                    "protocolMapper", mapperType.getMethod("getProtocolMapper").invoke(mapper),
                    "config", new TreeMap<>((Map<String,String>) mapperType.getMethod("getConfig").invoke(mapper))));
        }
        mappers.sort(Comparator.comparing(item -> item.get("name").toString()));
        var attributes = (Map<String,String>) type.getMethod("getAttributes").invoke(client);
        return Map.of("fixture", path.getFileName().toString(),
                "clientId", type.getMethod("getClientId").invoke(client),
                "attributes", attributes == null ? Map.of() : new TreeMap<>(attributes),
                "protocolMappers", mappers,
                "converterCodeSource", converterClass.getProtectionDomain().getCodeSource().getLocation().toString());
    }

    public static void main(String[] args) throws Exception {
        // The distribution also ships the FIPS provider service entry while its
        // optional FIPS library is absent.  Use the same default provider as this
        // non-FIPS runtime rather than letting ServiceLoader instantiate every
        // advertised provider.
        var providerType = Class.forName("org.keycloak.common.crypto.CryptoProvider");
        var defaultProvider = Class.forName("org.keycloak.crypto.def.DefaultCryptoProvider")
                .getConstructor().newInstance();
        Class.forName("org.keycloak.common.crypto.CryptoIntegration")
                .getMethod("setProvider", providerType)
                .invoke(null, defaultProvider);
        var records = new ArrayList<Map<String,Object>>();
        for (var argument : args) records.add(probe(Path.of(argument)));
        System.out.println(json(records));
    }
}
