import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeMap;
import java.util.UUID;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.sessions.infinispan.AuthenticatedClientSessionAdapter;
import org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter;
import org.keycloak.models.sessions.infinispan.SessionEntityUpdater;
import org.keycloak.models.sessions.infinispan.UserSessionAdapter;
import org.keycloak.models.sessions.infinispan.entities.AuthenticatedClientSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.AuthenticationSessionEntity;
import org.keycloak.models.sessions.infinispan.entities.UserSessionEntity;
import org.keycloak.protocol.saml.SamlClient;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.saml.mappers.SAMLNameIdMapper;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;
import org.keycloak.util.JsonSerialization;

/** Isolated unchanged native identifier producer; no HTTP, native store, or verdict writes. */
public final class ProbeKeycloakPersistentIdentifier {
    static final String FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String PREFIX = "saml.persistent.name.id.for.";
    static void require(boolean yes, String reason) {
        if (!yes) throw new IllegalArgumentException(reason);
    }
    static String sha(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    static byte[] bounded(Path path) throws Exception {
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 2_097_152,
                "Missing, linked, or oversized original");
        for (var p = path; p != null; p = p.getParent()) require(!Files.isSymbolicLink(p), "Linked original parent");
        return Files.readAllBytes(path);
    }
    static JsonNode reply(Path path) throws Exception {
        var record = JsonSerialization.mapper.readTree(bounded(path));
        require(record.path("method").asText().equals("GET") && record.path("status").asInt() == 200,
                "Successful original native GET required");
        byte[] raw = Base64.getDecoder().decode(record.path("response_base64").asText());
        require(raw.length <= 1_048_576 && sha(raw).equals(record.path("response_sha256").asText()),
                "Original native response digest mismatch");
        return JsonSerialization.mapper.readTree(raw);
    }
    static String text(JsonNode node, String field) {
        require(node.path(field).isTextual() && !node.path(field).asText().isBlank(), "Missing native " + field);
        return node.path(field).asText();
    }
    static Map<String, List<String>> attributes(JsonNode user) {
        var result = new TreeMap<String, List<String>>();
        var attrs = user.path("attributes");
        // The main entry point first proves actual ADMIN_EDIT visibility. Under that policy an
        // absent attributes member is the native API representation of an empty attribute map.
        require(attrs.isMissingNode() || attrs.isObject(), "Invalid native attribute inventory");
        if (attrs.isMissingNode()) return result;
        attrs.fields().forEachRemaining(e -> {
            require(e.getValue().isArray() && e.getValue().size() <= 16, "Invalid native attribute values");
            var values = new ArrayList<String>();
            e.getValue().forEach(v -> { require(v.isTextual(), "Native attribute must be text"); values.add(v.asText()); });
            result.put(e.getKey(), List.copyOf(values));
        });
        return result;
    }
    interface Call { Object apply(Method method, Object[] args) throws Throwable; }
    @SuppressWarnings("unchecked")
    static <T> T boundary(Class<T> type, Call call) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (p, m, a) -> {
            if (m.getDeclaringClass() == Object.class) return switch (m.getName()) {
                case "toString" -> "isolated-captured-" + type.getSimpleName();
                case "hashCode" -> System.identityHashCode(p);
                case "equals" -> p == a[0];
                default -> throw new UnsupportedOperationException(m.getName());
            };
            return call.apply(m, a == null ? new Object[0] : a);
        });
    }
    static Object parse(byte[] raw) throws Exception {
        // These are archived local XML originals. No remote resource resolution is allowed.
        String xml = new String(raw, java.nio.charset.StandardCharsets.UTF_8);
        require(!xml.contains("<!DOCTYPE") && !xml.contains("<!ENTITY"), "DTD original refused");
        return SAMLParser.getInstance().parse(StaxParserUtil.getXMLEventReader(new ByteArrayInputStream(raw)));
    }
    static record Exchange(AuthnRequestType request, ResponseType response, NameIDType name,
                           String requestSha256, String responseSha256) {}
    static Exchange exchange(Path requestPath, Path responsePath, String clientId) throws Exception {
        byte[] requestRaw = bounded(requestPath), responseRaw = bounded(responsePath);
        require(parse(requestRaw) instanceof AuthnRequestType, "Native AuthnRequest required");
        var request = (AuthnRequestType) parse(requestRaw);
        require(parse(responseRaw) instanceof ResponseType, "Native Response required");
        var response = (ResponseType) parse(responseRaw);
        require(request.getIssuer() != null && clientId.equals(request.getIssuer().getValue()), "Foreign request client");
        require(request.getID().equals(response.getInResponseTo()), "Response request mismatch");
        require(response.getAssertions().size() == 1 && response.getAssertions().getFirst().getAssertion() != null,
                "One original clear Assertion required");
        var assertion = response.getAssertions().getFirst().getAssertion();
        require(assertion.getSubject() != null && assertion.getSubject().getSubType() != null
                && assertion.getSubject().getSubType().getBaseID() instanceof NameIDType, "Native NameID required");
        var name = (NameIDType) assertion.getSubject().getSubType().getBaseID();
        require(name.getFormat() != null && FORMAT.equals(name.getFormat().toString()), "Persistent original required");
        return new Exchange(request, response, name, sha(requestRaw), sha(responseRaw));
    }
    static Map<String, Object> produce(JsonNode clientRead, JsonNode userRead, Exchange exchange,
                                       String mode, String expected) throws Exception {
        String clientId = text(clientRead, "clientId"), userId = text(userRead, "id");
        var attrs = new TreeMap<>(attributes(userRead));
        var before = new TreeMap<>(attrs);
        var accesses = new ArrayList<Map<String, Object>>();
        var writes = new ArrayList<Map<String, Object>>();
        var user = boundary(UserModel.class, (m, a) -> {
            accesses.add(Map.of("method", m.getName(), "arguments", List.of(a)));
            return switch (m.getName()) {
                case "getId" -> userId;
                case "getUsername" -> text(userRead, "username");
                case "getEmail" -> userRead.path("email").asText(null);
                case "getFirstAttribute" -> {
                    var values = attrs.get((String) a[0]);
                    yield values == null || values.isEmpty() ? null : values.getFirst();
                }
                case "setSingleAttribute" -> {
                    // Storage boundary only: persist exactly the value supplied by unchanged product code.
                    var key = (String) a[0]; var value = (String) a[1];
                    writes.add(Map.of("attribute", key, "value", value));
                    attrs.put(key, List.of(value)); yield null;
                }
                default -> throw new UnsupportedOperationException("Uncaptured UserModel method " + m.getName());
            };
        });
        var client = boundary(ClientModel.class, (m, a) -> switch (m.getName()) {
            case "getId" -> text(clientRead, "id");
            case "getClientId" -> clientId;
            case "getAttribute" -> clientRead.path("attributes").path((String) a[0]).asText(null);
            default -> throw new UnsupportedOperationException("Uncaptured ClientModel method " + m.getName());
        });
        var userEntity = new UserSessionEntity("isolated-persistent-probe");
        userEntity.setUser(userId);
        UserSessionModel userSession = new UserSessionAdapter<>(null, user, null, null, null, null, userEntity, false);
        var clientEntity = new AuthenticatedClientSessionEntity();
        clientEntity.setClientId(text(clientRead, "id")); clientEntity.setUserId(userId);
        var clientSession = new AuthenticatedClientSessionAdapter(null, clientEntity, client, userSession, null, null, false);
        var authEntity = new AuthenticationSessionEntity();
        authEntity.setClientUUID(text(clientRead, "id")); authEntity.setClientNotes(new TreeMap<>());
        if (exchange.request().getNameIDPolicy() != null && exchange.request().getNameIDPolicy().getFormat() != null)
            authEntity.getClientNotes().put("NAMEID_FORMAT", exchange.request().getNameIDPolicy().getFormat().toString());
        var updater = new SessionEntityUpdater<AuthenticationSessionEntity>() {
            public AuthenticationSessionEntity getEntity() { return authEntity; }
            public void onEntityUpdated() { throw new UnsupportedOperationException("No session mutation expected"); }
            public void onEntityRemoved() { throw new UnsupportedOperationException("No session removal expected"); }
        };
        var authSession = new AuthenticationSessionAdapter(null, null, updater, "isolated-persistent-probe");
        var protocol = new SamlProtocol(); // No subclass, producer override, supplied UUID, or randomness replacement.
        var formatMethod = SamlProtocol.class.getDeclaredMethod("getNameIdFormat", SamlClient.class, AuthenticationSessionModel.class);
        var valueMethod = SamlProtocol.class.getDeclaredMethod("getNameId", String.class, CommonClientSessionModel.class, UserSessionModel.class);
        formatMethod.setAccessible(true); valueMethod.setAccessible(true);
        String format, value;
        try {
            format = (String) formatMethod.invoke(protocol, new SamlClient(client), authSession);
            require(FORMAT.equals(format), "Selected native producer format differs");
            value = (String) valueMethod.invoke(protocol, format, clientSession, userSession);
        } catch (InvocationTargetException error) {
            throw new IllegalArgumentException("Native producer invocation failed", error.getCause());
        }
        String key = PREFIX + clientId;
        if (mode.equals("empty-construction")) {
            require(before.isEmpty(), "Empty native attribute state required for construction");
            require(writes.size() == 1 && key.equals(writes.getFirst().get("attribute"))
                    && value.equals(writes.getFirst().get("value")) && attrs.equals(Map.of(key, List.of(value))),
                    "Native construction did not persist exactly its own value");
            require(value.startsWith("G-"), "Unexpected native UUID prefix");
            var uuid = UUID.fromString(value.substring(2));
            require(uuid.version() == 4 && uuid.variant() == 2, "Native UUID construction diagnostic mismatch");
        } else {
            require(writes.isEmpty() && before.equals(attrs) && value.equals(expected), "Original saved native value not reused exactly");
        }
        require(accesses.stream().noneMatch(a -> List.of("getUsername", "getEmail", "getId").contains(a.get("method"))),
                "Producer unexpectedly read principal identifiers");
        var trace = new LinkedHashMap<String, Object>();
        trace.put("mode", mode); trace.put("diagnosticOnly", mode.equals("principal-valued-control"));
        trace.put("requestSha256", exchange.requestSha256()); trace.put("responseSha256", exchange.responseSha256());
        trace.put("requestId", exchange.request().getID()); trace.put("clientId", clientId); trace.put("userId", userId);
        trace.put("selectedFormat", format); trace.put("nativeValue", value);
        trace.put("equalsDeclaredPrincipal", value.equals(text(userRead, "username")));
        trace.put("equalsDeclaredEmail", userRead.path("email").isTextual() && value.equals(userRead.path("email").asText()));
        trace.put("originalNameId", exchange.name().getValue()); trace.put("attributesBefore", before);
        trace.put("attributesAfter", attrs); trace.put("userMethodAccesses", accesses); trace.put("setSingleAttributeEffects", writes);
        trace.put("method", valueMethod.toGenericString()); trace.put("persistentMethod",
                SamlProtocol.class.getDeclaredMethod("getPersistentNameId", CommonClientSessionModel.class, UserSessionModel.class).toGenericString());
        trace.put("formatMethod", formatMethod.toGenericString());
        return trace;
    }
    static Map<String, Object> origin(Class<?> type) throws Exception {
        var source = type.getProtectionDomain().getCodeSource();
        byte[] bytes; try (var input = type.getResourceAsStream("/" + type.getName().replace('.', '/') + ".class")) {
            require(input != null, "Missing native class original"); bytes = input.readAllBytes();
        }
        var row = new LinkedHashMap<String, Object>(); row.put("class", type.getName()); row.put("classSha256", sha(bytes));
        if (source != null) {
            var jar = Path.of(source.getLocation().toURI());
            require(Files.isRegularFile(jar), "Native class did not load from immutable JAR");
            row.put("jarPath", jar.toString()); row.put("jarSha256", sha(Files.readAllBytes(jar)));
        } else { require(type == UUID.class, "Unexpected bootstrap class"); row.put("module", "java.base"); }
        return row;
    }
    static Map<String, Object> mapperClosure(Path originals, JsonNode client) throws Exception {
        var after = reply(originals.resolve("native-client-after.json"));
        require(client.equals(after), "Captured selected native client changed");
        var scopes = reply(originals.resolve("client-scopes-before.json"));
        require(scopes.isArray() && scopes.equals(reply(originals.resolve("client-scopes-after.json"))),
                "Complete native client scope inventory changed");
        var providers = new TreeMap<String, ProtocolMapper>();
        var factories = new ArrayList<Map<String, Object>>();
        for (var factory : ServiceLoader.load(ProtocolMapper.class)) {
            require(providers.put(factory.getId(), factory) == null, "Duplicate native ProtocolMapper provider");
            var row = new LinkedHashMap<>(origin(factory.getClass()));
            row.put("providerId", factory.getId()); row.put("protocol", factory.getProtocol());
            row.put("samlNameIdMapper", factory instanceof SAMLNameIdMapper); factories.add(row);
        }
        require(!providers.isEmpty() && providers.values().stream().anyMatch(p -> p instanceof SAMLNameIdMapper),
                "Actual native NameID mapper factory closure missing");
        var selected = new ArrayList<Map<String, Object>>();
        var containers = new ArrayList<JsonNode>(); containers.add(client);
        for (var scope : scopes) if (scope.path("protocol").asText().equals("saml")) containers.add(scope);
        for (var container : containers) {
            var mappers = container.path("protocolMappers");
            require(mappers.isMissingNode() || mappers.isArray(), "Invalid native mapper inventory");
            if (mappers.isMissingNode()) continue;
            for (var mapper : mappers) {
                require(mapper.path("protocol").asText().equals("saml"), "Foreign mapper in native SAML scope");
                String id = text(mapper, "protocolMapper"); var factory = providers.get(id);
                require(factory != null && "saml".equals(factory.getProtocol()), "Unknown native SAML mapper provider");
                require(!(factory instanceof SAMLNameIdMapper), "Native NameID mapper bypasses selected producer");
                selected.add(Map.of("containerId", text(container, "id"), "mapperId", text(mapper, "id"),
                        "providerId", id, "factoryClass", factory.getClass().getName(), "samlNameIdMapper", false));
            }
        }
        return Map.of("factories", factories, "configuredSamlMappers", selected,
                "allConfiguredSamlScopesIncluded", true, "selectedNameIdMapperPresent", false);
    }
    static List<Map<String, Object>> origins() throws Exception {
        var rows = new ArrayList<Map<String, Object>>();
        for (var type : List.of(SamlProtocol.class, SamlClient.class, UserModel.class, ClientModel.class,
                UserSessionAdapter.class, AuthenticatedClientSessionAdapter.class, AuthenticationSessionAdapter.class,
                UserSessionEntity.class, AuthenticatedClientSessionEntity.class, AuthenticationSessionEntity.class,
                ProtocolMapper.class, SAMLNameIdMapper.class, SAMLParser.class, StaxParserUtil.class,
                AuthnRequestType.class, ResponseType.class, NameIDType.class, UUID.class)) {
            rows.add(origin(type));
        }
        return rows;
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 6, "folder normalRequest normalResponse mutantRequest mutantResponse output required");
        var folder = Path.of(args[0]).toAbsolutePath().normalize(); var output = Path.of(args[5]);
        require(!Files.exists(output, LinkOption.NOFOLLOW_LINKS) && output.getParent() != null
                && Files.isDirectory(output.toAbsolutePath().getParent(), LinkOption.NOFOLLOW_LINKS), "Output must be fresh and owned");
        for (var p = output.toAbsolutePath().getParent(); p != null; p = p.getParent())
            require(!Files.isSymbolicLink(p), "Linked output parent");
        var originals = folder.resolve("originals");
        var visibility = reply(originals.resolve("user-profile-visible.json"));
        require("ADMIN_EDIT".equals(visibility.path("unmanagedAttributePolicy").asText()),
                "Actual native ADMIN_EDIT attribute visibility required");
        var client = reply(originals.resolve("native-client-before.json"));
        var before = reply(originals.resolve("native-user-before.json"));
        var after = reply(originals.resolve("native-user-after.json"));
        var mutant = reply(originals.resolve("native-user-mutant-before.json"));
        var mapperProof = mapperClosure(originals, client);
        String clientId = text(client, "clientId"), userId = text(before, "id"), principal = text(before, "username");
        require(userId.equals(text(after, "id")) && userId.equals(text(mutant, "id"))
                && principal.equals(text(after, "username")) && principal.equals(text(mutant, "username")), "Native principal changed");
        require("saml".equals(text(client, "protocol")) && "persistent".equals(client.path("attributes").path("saml_name_id_format").asText())
                && "true".equals(client.path("attributes").path("saml_force_name_id_format").asText()), "Native persistent client policy required");
        require(attributes(before).isEmpty(), "Construction baseline has native attributes");
        var normal = exchange(Path.of(args[1]), Path.of(args[2]), clientId);
        var negative = exchange(Path.of(args[3]), Path.of(args[4]), clientId);
        String key = PREFIX + clientId;
        require(attributes(after).equals(Map.of(key, List.of(normal.name().getValue()))), "Saved original attribute and signed NameID differ");
        require(attributes(mutant).equals(Map.of(key, List.of(principal))) && principal.equals(negative.name().getValue()),
                "Original native principal-valued control is not bound");
        var traces = List.of(produce(client, before, normal, "empty-construction", null),
                produce(client, after, normal, "saved-original-reuse", normal.name().getValue()),
                produce(client, mutant, negative, "principal-valued-control", principal));
        var report = new LinkedHashMap<String, Object>();
        report.put("schema", "samlscope-keycloak-persistent-native-instrumentation-v1");
        report.put("scope", "isolated-unchanged-native-persistent-construction-and-original-saved-state-reuse");
        report.put("traces", traces); report.put("classes", origins());
        report.put("mapperClosure", mapperProof);
        report.put("userProfileVisibilityProof", Map.of("file", "originals/user-profile-visible.json",
                "recordSha256", sha(bounded(originals.resolve("user-profile-visible.json"))),
                "unmanagedAttributePolicy", "ADMIN_EDIT"));
        report.put("helperSha256", sha(bounded(Path.of(System.getProperty("samlscope.probe.source",
                "dev/reference-acceptance/ProbeKeycloakPersistentIdentifier.java")))));
        report.put("nativeClassOverridden", false); report.put("randomnessSeededOrReplaced", false);
        report.put("signatureValidationPerformed", false); report.put("universalUserOpacityClaimed", false);
        report.put("protocolSubmissions", 0); report.put("credentialPosts", 0); report.put("productSettingWrites", 0);
        report.put("nativeStoreWrites", 0); report.put("verdictAdopted", false);
        Files.writeString(output, JsonSerialization.writeValueAsPrettyString(report), java.nio.file.StandardOpenOption.CREATE_NEW);
    }
}
