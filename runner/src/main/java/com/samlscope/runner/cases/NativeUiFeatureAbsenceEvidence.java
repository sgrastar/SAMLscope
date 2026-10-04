package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.w3c.dom.Element;

/**
 * Reads a local product-native proof that an approved optional UI feature is not used.
 *
 * <p>This is intentionally narrower than a DOM observation.  The Keycloak adapter must bind the
 * original Suite metadata and successful SAML exchange to the product's own metadata converter,
 * full admin read-back, pinned runtime classes, request-bound login decision, and exact deletion
 * read-back.  Missing UI text in a page or a receipt boolean is never conclusive.</p>
 */
final class NativeUiFeatureAbsenceEvidence {
    static final String LOGO = "IIP-MD05-f9-idp-01";
    static final String DISCOVERY = "IIP-MD05-fb-idp-01";
    static final String URL = "IIP-MD05-fh-idp-01";
    static final String DISPLAY = "IIP-MD05-fj-idp-01";
    static final Set<String> SUPPORTED = Set.of(DISCOVERY, DISPLAY);
    private static final String SCHEMA = "samlscope-native-ui-feature-absence-v1";
    private static final String ADAPTER = "keycloak-native-client-import";
    private static final String VARIANT = "ui-consumer-display-all";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DISPLAY_SENTINEL = "SAMLscope UI display candidate";
    private static final String SERVICE_SENTINEL = "SAMLscope service candidate";
    private static final String IMAGE =
            "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";
    private static final String CONVERTER =
            "f12ac7fc23ddaec03f2b0d61c47368dae8038b478a4972a66d0ff7f3415de4ec";
    private static final String PROTOCOL =
            "4ad89b08f6d37e00a02e3cb0a4563883935f7d66b3f3bb717f9da8c316104100";
    private static final String SERVICE =
            "9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45";
    private static final ReferenceIdentity KEYCLOAK = new ReferenceIdentity(
            IMAGE, "26.7.2", CONVERTER, PROTOCOL, SERVICE);

    record ReferenceIdentity(String imageId, String version, String converterSha256,
                             String protocolSha256, String serviceSha256) {}

    private final Path directory;
    private final TranscriptContentReader content;
    private final ReferenceIdentity reference;

    NativeUiFeatureAbsenceEvidence(Path directory, TranscriptContentReader content) {
        this(directory, content, KEYCLOAK);
    }

    NativeUiFeatureAbsenceEvidence(Path directory, TranscriptContentReader content,
            ReferenceIdentity reference) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content);
        this.reference = Objects.requireNonNull(reference);
    }

    boolean exists(String run) {
        return run != null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(run + ".json"), LinkOption.NOFOLLOW_LINKS);
    }

    Optional<CaseOutcome> read(CaseContext context, byte[] targetMetadata, String caseId) {
        if (!SUPPORTED.contains(caseId) || targetMetadata == null || targetMetadata.length == 0) {
            return Optional.empty();
        }
        try {
            require(context.transcriptComplete());
            require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var file = directory.resolve(context.runId() + ".json");
            if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
            require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(file) > 0 && Files.size(file) <= 1_048_576);
            var receiptBytes = Files.readAllBytes(file);
            var receipt = new JsonCodec().mapper().readTree(receiptBytes);
            requireFields(receipt, Set.of("schema", "runId", "targetEntityId",
                    "targetMetadataSha256", "evidenceAdapter", "provenCases", "fixture",
                    "exchange", "nativeImport", "runtime", "requestBoundDecision",
                    "restoration", "operationCounts"));
            require(SCHEMA.equals(text(receipt, "schema"))
                    && context.runId().equals(text(receipt, "runId"))
                    && ADAPTER.equals(text(receipt, "evidenceAdapter"))
                    && hash(targetMetadata).equals(text(receipt, "targetMetadataSha256")));
            var proven = stringSet(receipt.path("provenCases"));
            require(proven.equals(SUPPORTED) && proven.contains(caseId));

            var target = SecureXml.parse(targetMetadata).getDocumentElement();
            require(MD.equals(target.getNamespaceURI())
                    && "EntityDescriptor".equals(target.getLocalName())
                    && text(receipt, "targetEntityId").equals(target.getAttribute("entityID")));

            var entries = entries(context);
            var prepared = prepared(context, receipt.path("fixture"), entries);
            var exchangeRefs = exchange(context, receipt.path("exchange"), entries,
                    prepared.entityId(), target.getAttribute("entityID"));
            verifyRuntime(receipt.path("runtime"));
            verifyNativeImport(receipt.path("nativeImport"), prepared);
            verifyRequestBoundDecision(receipt.path("requestBoundDecision"), prepared.entityId(),
                    context.runId());
            verifyRestoration(receipt.path("restoration"), prepared.entityId());
            verifyCounts(receipt.path("operationCounts"));

            var refs = new ArrayList<EvidenceRef>();
            refs.add(new EvidenceRef("transcript", prepared.fetch().id()));
            refs.add(new EvidenceRef("transcript", prepared.entry().id()));
            refs.addAll(exchangeRefs);
            refs.add(new EvidenceRef("native-ui-policy", context.runId() + ".json#" + hash(receiptBytes)));
            var feature = caseId.equals(DISPLAY) ? "display-name" : "discovery-ui";
            return Optional.of(new CaseOutcome(Outcome.SATISFIED_WITH_NOTE, null,
                    "browser.ui-native-feature.not-used", "browser.ui-native-feature.not-used",
                    List.copyOf(refs), Map.of("feature", feature, "product", "keycloak",
                            "evidence_adapter", ADAPTER)));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    private Map<String, TranscriptEntry> entries(CaseContext context) {
        var entries = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        return entries;
    }

    private Prepared prepared(CaseContext context, JsonNode fixture,
            Map<String, TranscriptEntry> entries) throws Exception {
        requireFields(fixture, Set.of("variant", "fetchReference", "metadataReference",
                "metadataSha256"));
        require(VARIANT.equals(text(fixture, "variant")));
        var fetch = entries.get(text(fixture, "fetchReference"));
        var prepared = entries.get(text(fixture, "metadataReference"));
        require(fetch != null && prepared != null
                && fetch.direction() == Direction.INBOUND
                && prepared.direction() == Direction.OUTBOUND
                && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && "MetadataPrepared".equals(prepared.samlSummary().get("type"))
                && VARIANT.equals(fetch.samlSummary().get("variant"))
                && VARIANT.equals(prepared.samlSummary().get("variant"))
                && fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))
                && Objects.equals(fetch.status(), 200) && Objects.equals(prepared.status(), 200)
                && prepared.timestamp().isAfter(fetch.timestamp()));
        var raw = content.readDecodedSaml(prepared);
        require(hash(raw).equals(text(fixture, "metadataSha256"))
                && hash(raw).equals(String.valueOf(prepared.samlSummary().get("metadataSha256"))));
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName())
                && !root.getAttribute("entityID").isBlank());
        var roles = children(root, MD, "SPSSODescriptor");
        require(roles.size() == 1);
        var extensions = children(roles.getFirst(), MD, "Extensions");
        require(extensions.size() == 1);
        var infos = children(extensions.getFirst(), UI, "UIInfo");
        require(infos.size() == 1);
        var displays = children(infos.getFirst(), UI, "DisplayName");
        require(displays.size() == 1 && DISPLAY_SENTINEL.equals(displays.getFirst().getTextContent()));
        var services = children(roles.getFirst(), MD, "AttributeConsumingService");
        require(services.size() == 1);
        var names = children(services.getFirst(), MD, "ServiceName");
        require(names.size() == 1 && SERVICE_SENTINEL.equals(names.getFirst().getTextContent()));
        return new Prepared(fetch, prepared, root.getAttribute("entityID"), raw);
    }

    private List<EvidenceRef> exchange(CaseContext context, JsonNode exchange,
            Map<String, TranscriptEntry> entries, String fixtureEntity, String targetEntity) throws Exception {
        requireFields(exchange, Set.of("requestReference", "responseReference",
                "requestSha256", "responseSha256"));
        var request = entries.get(text(exchange, "requestReference"));
        var response = entries.get(text(exchange, "responseReference"));
        require(request != null && response != null
                && request.direction() == Direction.OUTBOUND
                && response.direction() == Direction.INBOUND
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && "Response".equals(response.samlSummary().get("type"))
                && VARIANT.equals(request.samlSummary().get("variant"))
                && Boolean.TRUE.equals(response.samlSummary().get("metadataProbeAccepted"))
                && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                        response.samlSummary().get("statusCode"))
                && response.timestamp().isAfter(request.timestamp()));
        var requestRaw = content.readDecodedSaml(request);
        var responseRaw = content.readDecodedSaml(response);
        require(hash(requestRaw).equals(text(exchange, "requestSha256"))
                && hash(responseRaw).equals(text(exchange, "responseSha256")));
        var authn = SecureXml.parse(requestRaw).getDocumentElement();
        var samlResponse = SecureXml.parse(responseRaw).getDocumentElement();
        require(P.equals(authn.getNamespaceURI()) && "AuthnRequest".equals(authn.getLocalName())
                && P.equals(samlResponse.getNamespaceURI()) && "Response".equals(samlResponse.getLocalName())
                && authn.getAttribute("ID").equals(samlResponse.getAttribute("InResponseTo"))
                && authn.getAttribute("ID").equals(response.correlationId())
                && fixtureEntity.equals(one(authn, S, "Issuer").getTextContent())
                && targetEntity.equals(one(samlResponse, S, "Issuer").getTextContent())
                && MetadataProbeCorrelation.matches(response.url(), context.runId(), VARIANT));
        return List.of(new EvidenceRef("transcript", request.id()),
                new EvidenceRef("transcript", response.id()));
    }

    private void verifyRuntime(JsonNode runtime) throws Exception {
        requireFields(runtime, Set.of("containerName", "containerId", "imageId", "startedAt",
                "runningAtCapture", "productVersion", "converterClass", "samlProtocolClass",
                "samlServiceClass"));
        require("samlscope-reference-keycloak".equals(text(runtime, "containerName"))
                && text(runtime, "containerId").matches("[0-9a-f]{64}")
                && reference.imageId().equals(text(runtime, "imageId"))
                && reference.version().equals(text(runtime, "productVersion"))
                && runtime.path("runningAtCapture").isBoolean()
                && runtime.path("runningAtCapture").asBoolean());
        Instant.parse(text(runtime, "startedAt"));
        require(reference.converterSha256().equals(hash(blob(runtime.path("converterClass"),
                65536, "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class"))));
        require(reference.protocolSha256().equals(hash(blob(runtime.path("samlProtocolClass"),
                131072, "org/keycloak/protocol/saml/SamlProtocol.class"))));
        require(reference.serviceSha256().equals(hash(blob(runtime.path("samlServiceClass"),
                131072, "org/keycloak/protocol/saml/SamlService.class"))));
    }

    private void verifyNativeImport(JsonNode nativeImport, Prepared prepared) throws Exception {
        requireFields(nativeImport, Set.of("uiImportRecord", "converterOutput",
                "configuredReadBack"));
        var importRecord = new JsonCodec().mapper().readTree(blob(nativeImport.path("uiImportRecord"),
                131072, null));
        require("success".equals(text(importRecord, "status"))
                && prepared.entityId().equals(importRecord.path("fixture").path("entity_id").asText())
                && hash(prepared.raw()).equals(importRecord.path("fixture").path("sha256").asText())
                && "client-settings-page".equals(importRecord.path("import").path("ui_status").asText())
                && importRecord.path("client").path("database_id").asText().matches("[0-9a-f-]{32,36}"));
        var configuredRaw = blob(nativeImport.path("configuredReadBack"), 524288, null);
        var configured = new JsonCodec().mapper().readTree(configuredRaw);
        require(prepared.entityId().equals(text(configured, "clientId"))
                && "saml".equals(text(configured, "protocol"))
                && importRecord.path("client").path("database_id").asText().equals(text(configured, "id")));
        require(configured.path("redirectUris").isArray()
                && iterable(configured.path("redirectUris")).stream().map(JsonNode::asText)
                        .anyMatch(value -> value.contains("mdv=" + VARIANT)));

        var converter = new JsonCodec().mapper().readTree(blob(nativeImport.path("converterOutput"),
                524288, null));
        require(converter.isArray() && converter.size() == 1);
        var row = converter.get(0);
        require(prepared.entityId().equals(text(row, "clientId"))
                && row.path("converterCodeSource").asText().endsWith(
                        "/org.keycloak.keycloak-services-26.7.2.jar"));
        // The product must demonstrably have parsed the same non-UI metadata.  This prevents an
        // empty/failed converter output from being mistaken for nonuse.
        require(row.path("attributes").path("saml_assertion_consumer_url_post").asText()
                .contains("mdv=" + VARIANT));
        var forbidden = List.of(DISPLAY_SENTINEL, SERVICE_SENTINEL, "UIInfo", "DisplayName",
                "OrganizationDisplayName", "DiscoHints", "DomainHint", "GeolocationHint", "IPHint");
        var configuredText = new String(configuredRaw, StandardCharsets.UTF_8);
        var converterText = converter.toString();
        for (var token : forbidden) {
            require(!configuredText.contains(token) && !converterText.contains(token));
        }
        require(!configured.hasNonNull("name") || configured.path("name").asText().isBlank());
        require(!row.hasNonNull("name") || row.path("name").asText().isBlank());
    }

    private void verifyRequestBoundDecision(JsonNode decision, String fixtureEntity, String runId)
            throws Exception {
        requireFields(decision, Set.of("entityId", "requestUrl", "loginPageUrl",
                "loginPageSha256", "loginFormActionPath", "loginFormActionSha256",
                "identityProviderAliases",
                "identityProviderLinks", "identityProviderReadBack",
                "authenticatedFlowCompleted"));
        var providers = new JsonCodec().mapper().readTree(
                blob(decision.path("identityProviderReadBack"), 262144, null));
        require(fixtureEntity.equals(text(decision, "entityId"))
                && runBound(text(decision, "requestUrl"), runId)
                && keycloakLoginUrl(text(decision, "loginPageUrl"))
                && text(decision, "loginPageSha256").matches("[0-9a-f]{64}")
                && "/realms/samlscope/login-actions/authenticate".equals(
                        text(decision, "loginFormActionPath"))
                && text(decision, "loginFormActionSha256").matches("[0-9a-f]{64}")
                && decision.path("authenticatedFlowCompleted").isBoolean()
                && decision.path("authenticatedFlowCompleted").asBoolean()
                && providers.isArray() && providers.isEmpty()
                && stringSet(decision.path("identityProviderAliases")).isEmpty()
                && stringSet(decision.path("identityProviderLinks")).isEmpty());
    }

    private static boolean runBound(String value, String runId) {
        try {
            var query = java.net.URI.create(value).getRawQuery();
            if (query == null) return false;
            String observed = null;
            for (var part : query.split("&", -1)) {
                var pair = part.split("=", 2);
                var key = java.net.URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                if (!"run".equals(key)) continue;
                if (pair.length != 2 || observed != null) return false;
                observed = java.net.URLDecoder.decode(pair[1], StandardCharsets.UTF_8);
            }
            return runId.equals(observed);
        } catch (IllegalArgumentException invalidUriOrEncoding) {
            return false;
        }
    }

    private static boolean keycloakLoginUrl(String value) {
        try {
            var uri = java.net.URI.create(value);
            return "http".equals(uri.getScheme()) && "localhost".equals(uri.getHost())
                    && uri.getPort() == 18180
                    && "/realms/samlscope/login-actions/authenticate".equals(uri.getPath())
                    && uri.getRawFragment() == null;
        } catch (IllegalArgumentException invalidUri) {
            return false;
        }
    }

    private void verifyRestoration(JsonNode restoration, String fixtureEntity) throws Exception {
        requireFields(restoration, Set.of("beforeReadBack", "afterReadBack", "deletedClientId",
                "restored"));
        var before = blob(restoration.path("beforeReadBack"), 65536, null);
        var after = blob(restoration.path("afterReadBack"), 65536, null);
        require(Arrays.equals(before, after));
        var beforeJson = new JsonCodec().mapper().readTree(before);
        require(beforeJson.isArray() && beforeJson.isEmpty()
                && fixtureEntity.equals(text(restoration, "deletedClientId"))
                && restoration.path("restored").isBoolean()
                && restoration.path("restored").asBoolean());
    }

    private void verifyCounts(JsonNode counts) {
        requireFields(counts, Set.of("productConfigurationWrites", "productRestarts",
                "metadataImports", "protocolRoundTrips", "humanOperations"));
        require(counts.path("productConfigurationWrites").asInt(-1) == 4
                && counts.path("metadataImports").asInt(-1) == 2
                && counts.path("productRestarts").asInt(-1) == 0
                && counts.path("protocolRoundTrips").asInt(-1) == 2
                && counts.path("humanOperations").asInt(-1) == 0);
    }

    private byte[] blob(JsonNode node, int limit, String expectedPath) throws Exception {
        requireFields(node, Set.of("path", "sha256", "base64"));
        if (expectedPath != null) require(expectedPath.equals(text(node, "path")));
        var raw = Base64.getDecoder().decode(text(node, "base64"));
        require(raw.length > 0 && raw.length <= limit && hash(raw).equals(text(node, "sha256")));
        return raw;
    }

    private static Set<String> stringSet(JsonNode node) {
        require(node.isArray());
        var result = new HashSet<String>();
        for (var value : node) require(value.isTextual() && !value.asText().isBlank() && result.add(value.asText()));
        return Set.copyOf(result);
    }

    private static List<JsonNode> iterable(JsonNode node) {
        var values = new ArrayList<JsonNode>();
        node.forEach(values::add);
        return values;
    }

    private static Element one(Element parent, String namespace, String name) {
        var values = children(parent, namespace, name);
        require(values.size() == 1);
        return values.getFirst();
    }

    private static String text(JsonNode node, String name) {
        return node.path(name).asText("");
    }

    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private static void requireFields(JsonNode node, Set<String> expected) {
        require(node.isObject());
        var actual = new HashSet<String>();
        node.fieldNames().forEachRemaining(actual::add);
        require(actual.equals(expected));
    }

    private static void require(boolean value) {
        if (!value) throw new IllegalArgumentException("Unbound native UI feature evidence");
    }

    private record Prepared(TranscriptEntry fetch, TranscriptEntry entry, String entityId, byte[] raw) {}
}
