package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeUiFeatureAbsenceEvidenceTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String VARIANT = "ui-consumer-display-all";
    private static final String TARGET = "https://idp.example";
    private static final String ENTITY = "https://suite.example/sp";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final byte[] CONVERTER_CLASS = "converter-class".getBytes(StandardCharsets.UTF_8);
    private static final byte[] PROTOCOL_CLASS = "protocol-class".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SERVICE_CLASS = "service-class".getBytes(StandardCharsets.UTF_8);
    private static final String IMAGE = "sha256:" + "1".repeat(64);
    private final JsonCodec json = new JsonCodec();
    private final List<TranscriptEntry> entries = new ArrayList<>();
    private final Map<String, byte[]> bodies = new HashMap<>();

    @TempDir Path temp;

    @Test
    void exactNativeImportRuntimeDecisionAndRestorationProveOnlyApprovedNonuseCases()
            throws Exception {
        fixture();
        write(validReceipt());
        var evidence = evidence();
        var discovery = evidence.read(context(), targetMetadata(), NativeUiFeatureAbsenceEvidence.DISCOVERY);
        var display = evidence.read(context(), targetMetadata(), NativeUiFeatureAbsenceEvidence.DISPLAY);
        assertTrue(discovery.isPresent());
        assertTrue(display.isPresent());
        assertEquals(Outcome.SATISFIED_WITH_NOTE, discovery.orElseThrow().outcome());
        assertEquals("discovery-ui", discovery.orElseThrow().details().get("feature"));
        assertEquals("display-name", display.orElseThrow().details().get("feature"));
        assertTrue(evidence.read(context(), targetMetadata(), NativeUiFeatureAbsenceEvidence.LOGO).isEmpty());
        assertTrue(evidence.read(context(), targetMetadata(), NativeUiFeatureAbsenceEvidence.URL).isEmpty());
    }

    @Test
    void receiptAndOriginalTamperingFailClosed() throws Exception {
        fixture();
        var mutations = List.<Consumer<ObjectNode>>of(
                value -> value.put("runId", "run_00000000000000000000000000"),
                value -> value.put("targetMetadataSha256", "0".repeat(64)),
                value -> value.withObject("/fixture").put("metadataSha256", "0".repeat(64)),
                value -> value.withObject("/exchange").put("responseSha256", "0".repeat(64)),
                value -> value.withObject("/runtime").put("imageId", "sha256:" + "0".repeat(64)),
                value -> replaceBlob(value.withObject("/runtime").withObject("/converterClass"),
                        "forged".getBytes(StandardCharsets.UTF_8)),
                value -> replaceConfigured(value, configured -> configured.put("name",
                        "SAMLscope UI display candidate")),
                value -> replaceConverter(value, converter -> converter.get(0).withObject("/attributes")
                        .put("display", "SAMLscope UI display candidate")),
                value -> value.withObject("/requestBoundDecision")
                        .withArray("identityProviderAliases").add("unproven-broker"),
                value -> value.withObject("/requestBoundDecision").put("requestUrl",
                        "https://suite.example/start?run=" + RUN + "&run=" + RUN),
                value -> replaceBlob(value.withObject("/requestBoundDecision")
                        .withObject("/identityProviderReadBack"),
                        "[{}]".getBytes(StandardCharsets.UTF_8)),
                value -> value.withObject("/requestBoundDecision")
                        .put("authenticatedFlowCompleted", false),
                value -> replaceBlob(value.withObject("/restoration").withObject("/afterReadBack"),
                        "[{}]".getBytes(StandardCharsets.UTF_8)),
                value -> value.withObject("/restoration").put("restored", false),
                value -> value.withObject("/operationCounts").put("humanOperations", 1),
                value -> value.putArray("provenCases").add(NativeUiFeatureAbsenceEvidence.DISPLAY));
        for (var index = 0; index < mutations.size(); index++) {
            var receipt = validReceipt();
            mutations.get(index).accept(receipt);
            write(receipt);
            assertTrue(evidence().read(context(), targetMetadata(),
                    NativeUiFeatureAbsenceEvidence.DISPLAY).isEmpty(), "mutation " + index);
        }
    }

    @Test
    void transcriptCorrelationAndProductDecisionCannotBeReplacedByReceiptClaims()
            throws Exception {
        fixture();
        write(validReceipt());
        assertTrue(evidence().read(context(), targetMetadata(),
                NativeUiFeatureAbsenceEvidence.DISPLAY).isPresent());

        var response = entries.get(3);
        entries.set(3, entry(response.id(), response.direction(), response.timestamp(),
                "_different-request", response.url(), bodies.get(response.id()),
                response.samlSummary()));
        assertTrue(evidence().read(context(), targetMetadata(),
                NativeUiFeatureAbsenceEvidence.DISPLAY).isEmpty());

        fixture();
        write(validReceipt());
        response = entries.get(3);
        var summary = new HashMap<>(response.samlSummary());
        summary.put("metadataProbeAccepted", false);
        entries.set(3, entry(response.id(), response.direction(), response.timestamp(),
                response.correlationId(), response.url(), bodies.get(response.id()), summary));
        assertTrue(evidence().read(context(), targetMetadata(),
                NativeUiFeatureAbsenceEvidence.DISPLAY).isEmpty());
    }

    private NativeUiFeatureAbsenceEvidence evidence() {
        var identity = new NativeUiFeatureAbsenceEvidence.ReferenceIdentity(IMAGE, "26.7.2",
                hash(CONVERTER_CLASS), hash(PROTOCOL_CLASS), hash(SERVICE_CLASS));
        return new NativeUiFeatureAbsenceEvidence(temp.resolve("evidence"),
                entry -> bodies.get(entry.decodedSamlRef()), identity);
    }

    private void fixture() {
        entries.clear();
        bodies.clear();
        var metadata = fixtureMetadata();
        var request = ("<p:AuthnRequest xmlns:p='" + P + "' xmlns:s='" + S
                + "' ID='_request'><s:Issuer>" + ENTITY + "</s:Issuer></p:AuthnRequest>")
                .getBytes(StandardCharsets.UTF_8);
        var response = ("<p:Response xmlns:p='" + P + "' xmlns:s='" + S
                + "' ID='_response' InResponseTo='_request'><s:Issuer>" + TARGET
                + "</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                + "</p:Status></p:Response>").getBytes(StandardCharsets.UTF_8);
        add("fetch", Direction.INBOUND, Instant.EPOCH, null, "https://suite.example/metadata",
                null, Map.of("type", "MetadataFetch", "variant", VARIANT));
        add("prepared", Direction.OUTBOUND, Instant.EPOCH.plusSeconds(1), "fetch",
                "https://suite.example/metadata", metadata,
                Map.of("type", "MetadataPrepared", "variant", VARIANT,
                        "fetchTranscriptId", "fetch", "metadataSha256", hash(metadata)));
        add("request", Direction.OUTBOUND, Instant.EPOCH.plusSeconds(2), null,
                "https://idp.example/sso", request,
                Map.of("type", "AuthnRequest", "variant", VARIANT));
        add("response", Direction.INBOUND, Instant.EPOCH.plusSeconds(3), "_request",
                "https://suite.example/acs?mdv=" + VARIANT + "&run=" + RUN, response,
                Map.of("type", "Response", "metadataProbeAccepted", true,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success"));
    }

    private ObjectNode validReceipt() {
        var metadata = fixtureMetadata();
        var importRecord = json.mapper().createObjectNode();
        importRecord.put("status", "success");
        importRecord.withObject("/fixture").put("entity_id", ENTITY).put("sha256", hash(metadata));
        importRecord.withObject("/import").put("ui_status", "client-settings-page");
        importRecord.withObject("/client").put("database_id",
                "01234567-89ab-cdef-0123-456789abcdef");
        var configured = json.mapper().createObjectNode();
        configured.put("id", "01234567-89ab-cdef-0123-456789abcdef");
        configured.put("clientId", ENTITY);
        configured.put("protocol", "saml");
        configured.put("name", "");
        configured.putArray("redirectUris").add(
                "https://suite.example/acs?mdv=" + VARIANT + "&run=" + RUN);
        var converter = json.mapper().createArrayNode();
        var row = converter.addObject();
        row.put("clientId", ENTITY);
        row.put("name", "");
        row.put("converterCodeSource",
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar");
        row.withObject("/attributes").put("saml_assertion_consumer_url_post",
                "https://suite.example/acs?mdv=" + VARIANT + "&run=" + RUN);

        var receipt = json.mapper().createObjectNode();
        receipt.put("schema", "samlscope-native-ui-feature-absence-v1");
        receipt.put("runId", RUN);
        receipt.put("targetEntityId", TARGET);
        receipt.put("targetMetadataSha256", hash(targetMetadata()));
        receipt.put("evidenceAdapter", "keycloak-native-client-import");
        receipt.putArray("provenCases").add(NativeUiFeatureAbsenceEvidence.DISCOVERY)
                .add(NativeUiFeatureAbsenceEvidence.DISPLAY);
        receipt.withObject("/fixture").put("variant", VARIANT)
                .put("fetchReference", "fetch").put("metadataReference", "prepared")
                .put("metadataSha256", hash(metadata));
        receipt.withObject("/exchange").put("requestReference", "request")
                .put("responseReference", "response")
                .put("requestSha256", hash(bodies.get("request")))
                .put("responseSha256", hash(bodies.get("response")));
        var nativeImport = receipt.withObject("/nativeImport");
        nativeImport.set("uiImportRecord", blob(bytes(importRecord), null));
        nativeImport.set("configuredReadBack", blob(bytes(configured), null));
        nativeImport.set("converterOutput", blob(bytes(converter), null));
        var runtime = receipt.withObject("/runtime");
        runtime.put("containerName", "samlscope-reference-keycloak");
        runtime.put("containerId", "a".repeat(64));
        runtime.put("imageId", IMAGE);
        runtime.put("startedAt", "2026-09-28T00:50:56.819831383Z");
        runtime.put("runningAtCapture", true);
        runtime.put("productVersion", "26.7.2");
        runtime.set("converterClass", blob(CONVERTER_CLASS,
                "org/keycloak/protocol/saml/EntityDescriptorDescriptionConverter.class"));
        runtime.set("samlProtocolClass", blob(PROTOCOL_CLASS,
                "org/keycloak/protocol/saml/SamlProtocol.class"));
        runtime.set("samlServiceClass", blob(SERVICE_CLASS,
                "org/keycloak/protocol/saml/SamlService.class"));
        var decision = receipt.withObject("/requestBoundDecision");
        decision.put("entityId", ENTITY);
        decision.put("requestUrl", "https://idp.example/sso?mdv=" + VARIANT + "&run=" + RUN);
        decision.put("loginPageUrl",
                "http://localhost:18180/realms/samlscope/login-actions/authenticate");
        decision.put("loginPageSha256", "2".repeat(64));
        decision.put("loginFormActionPath", "/realms/samlscope/login-actions/authenticate");
        decision.put("loginFormActionSha256", "3".repeat(64));
        decision.putArray("identityProviderAliases");
        decision.putArray("identityProviderLinks");
        decision.set("identityProviderReadBack",
                blob("[]".getBytes(StandardCharsets.UTF_8), null));
        decision.put("authenticatedFlowCompleted", true);
        var restoration = receipt.withObject("/restoration");
        restoration.set("beforeReadBack", blob("[]".getBytes(StandardCharsets.UTF_8), null));
        restoration.set("afterReadBack", blob("[]".getBytes(StandardCharsets.UTF_8), null));
        restoration.put("deletedClientId", ENTITY);
        restoration.put("restored", true);
        var counts = receipt.withObject("/operationCounts");
        counts.put("productConfigurationWrites", 4);
        counts.put("productRestarts", 0);
        counts.put("metadataImports", 2);
        counts.put("protocolRoundTrips", 2);
        counts.put("humanOperations", 0);
        return receipt;
    }

    private ObjectNode blob(byte[] raw, String path) {
        var value = json.mapper().createObjectNode();
        value.put("path", path == null ? "evidence.bin" : path);
        value.put("sha256", hash(raw));
        value.put("base64", Base64.getEncoder().encodeToString(raw));
        return value;
    }

    private void replaceConfigured(ObjectNode receipt, Consumer<ObjectNode> mutation) {
        var node = receipt.withObject("/nativeImport").withObject("/configuredReadBack");
        try {
            var configured = (ObjectNode) json.mapper().readTree(Base64.getDecoder().decode(node.path("base64").asText()));
            mutation.accept(configured);
            replaceBlob(node, bytes(configured));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private void replaceConverter(ObjectNode receipt, Consumer<com.fasterxml.jackson.databind.node.ArrayNode> mutation) {
        var node = receipt.withObject("/nativeImport").withObject("/converterOutput");
        try {
            var converter = (com.fasterxml.jackson.databind.node.ArrayNode) json.mapper().readTree(
                    Base64.getDecoder().decode(node.path("base64").asText()));
            mutation.accept(converter);
            replaceBlob(node, bytes(converter));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private void replaceBlob(ObjectNode node, byte[] raw) {
        node.put("sha256", hash(raw));
        node.put("base64", Base64.getEncoder().encodeToString(raw));
    }

    private void write(ObjectNode receipt) throws Exception {
        Files.createDirectories(temp.resolve("evidence"));
        Files.write(temp.resolve("evidence").resolve(RUN + ".json"), bytes(receipt));
    }

    private byte[] fixtureMetadata() {
        return ("<md:EntityDescriptor xmlns:md='" + MD
                + "' xmlns:mdui='urn:oasis:names:tc:SAML:metadata:ui' entityID='" + ENTITY + "'>"
                + "<md:SPSSODescriptor protocolSupportEnumeration='" + P + "'><md:Extensions><mdui:UIInfo>"
                + "<mdui:DisplayName xml:lang='en'>SAMLscope UI display candidate</mdui:DisplayName>"
                + "</mdui:UIInfo></md:Extensions><md:AssertionConsumerService index='0' "
                + "Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='https://suite.example/acs?mdv="
                + VARIANT + "&amp;run=" + RUN + "'/><md:AttributeConsumingService index='0'>"
                + "<md:ServiceName xml:lang='en'>SAMLscope service candidate</md:ServiceName>"
                + "<md:RequestedAttribute Name='urn:samlscope:anchor'/></md:AttributeConsumingService>"
                + "</md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] targetMetadata() {
        return ("<md:EntityDescriptor xmlns:md='" + MD + "' entityID='" + TARGET
                + "'><md:IDPSSODescriptor protocolSupportEnumeration='" + P
                + "'/></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }

    private void add(String id, Direction direction, Instant time, String correlation, String url,
            byte[] body, Map<String, Object> summary) {
        if (body != null) bodies.put(id, body);
        entries.add(entry(id, direction, time, correlation, url, body, summary));
    }

    private TranscriptEntry entry(String id, Direction direction, Instant time, String correlation,
            String url, byte[] body, Map<String, Object> summary) {
        return new TranscriptEntry(id, RUN, direction, time, correlation, "POST", url, 200,
                Map.of(), null, 0, body == null ? null : id, body == null ? 0 : body.length,
                null, null, summary);
    }

    private DefaultCaseContext context() {
        var recorder = new TranscriptRecorder() {
            @Override public TranscriptEntry record(TranscriptInput input) {
                throw new UnsupportedOperationException();
            }
            @Override public TranscriptEntry updateSamlAnalysis(String id, String correlationId,
                    Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
            @Override public List<TranscriptEntry> list(String runId) { return List.copyOf(entries); }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, recorder, true);
    }

    private byte[] bytes(com.fasterxml.jackson.databind.JsonNode node) {
        try {
            return json.mapper().writeValueAsBytes(node);
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static String hash(byte[] raw) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }
}
