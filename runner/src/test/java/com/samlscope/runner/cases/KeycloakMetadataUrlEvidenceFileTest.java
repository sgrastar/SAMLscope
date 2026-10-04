package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeycloakMetadataUrlEvidenceFileTest {
    private static final String MDQ_RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String REFRESH_RUN = "run_1123456789ABCDEFGHJKMNPQRS";
    private static final String MDQ_PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String REFRESH_PLAN = "plan_1123456789ABCDEFGHJKMNPQRS";
    private static final String TARGET = "http://localhost:18180/realms/samlscope/protocol/saml";
    private static final String IMAGE =
            "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";
    private static final String RELAY_SOURCE_SHA =
            "7067092aafdaaffcddabbf9fcf60b53e6e1d20f6061f52f3c652197f626e865b";
    private static final String SERVICES =
            "213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9";
    private static final String STORAGE =
            "63ba0e2133e3a5a65f5a4b7944018d3ae7b524aecbcaeacadcdfc7a004fb76d6";
    private static final int WAIT = 12;
    private static final Instant NOW = Instant.parse("2026-09-30T06:00:00Z");

    @TempDir Path temp;
    private final JsonCodec json = new JsonCodec();
    private final List<TranscriptEntry> entries = new ArrayList<>();
    private final Map<String, byte[]> bodies = new HashMap<>();
    private Path mdqFolder;
    private Path refreshFolder;
    private ObjectNode mdqManifest;
    private ObjectNode refreshManifest;
    private byte[] metadataA;
    private byte[] metadataB;

    @BeforeEach
    void setUp() throws Exception {
        var keys = new FilePlanKeyStore(temp.resolve("keys"), Clock.fixed(NOW, ZoneOffset.UTC));
        mdqFolder = temp.resolve("evidence").resolve(MDQ_RUN + ".mdq");
        refreshFolder = temp.resolve("evidence").resolve(REFRESH_RUN + ".refresh");
        Files.createDirectories(mdqFolder);
        Files.createDirectories(refreshFolder);
        buildMdq(keys.getOrCreate(MDQ_PLAN, "native-mdq"));
        buildRefresh(keys.getOrCreate(REFRESH_PLAN, "refresh-a"),
                keys.getOrCreate(REFRESH_PLAN, "refresh-b"));
    }

    @Test
    void acceptsMdqOnlyWithNativeUrlFetchPinnedRuntimeAndExactRestoration() {
        var result = configure(mdqCase(), MDQ_RUN);
        assertEquals(Outcome.SATISFIED, result.outcome(), result.details().toString());
        assertEquals(KeycloakMetadataUrlEvidenceFile.MDQ_ADAPTER,
                result.details().get("native_adapter"));
    }

    @Test
    void acceptsRefreshOnlyWithAAndBInvalidSignatureAndOldKeyControls() {
        var result = configure(refreshCase(), REFRESH_RUN);
        assertEquals(Outcome.SATISFIED, result.outcome(), result.details().toString());
        assertEquals(true, result.details().get("invalid_signature_rejected"));
        assertEquals(true, result.details().get("old_key_rejected"));
    }

    @Test
    void rejectsMdqWhenSignedUseIsNotBoundToTheActiveAction() {
        var original = entries.stream().filter(value -> "mdq-request".equals(value.id())).findFirst().orElseThrow();
        var summary = new HashMap<>(original.samlSummary());
        summary.put("action_id", "action-other");
        entries.set(entries.indexOf(original), withSummary(original, summary));
        assertEquals(Outcome.NOT_VERIFIED, configure(mdqCase(), MDQ_RUN).outcome());
    }

    @Test
    void rejectsMdqWhenBootstrapDoesNotPrecedeSignedUse() {
        var original = entries.stream().filter(value -> "mdq-bootstrap-response".equals(value.id()))
                .findFirst().orElseThrow();
        entries.set(entries.indexOf(original), withTime(original, NOW.plusSeconds(4)));
        assertEquals(Outcome.NOT_VERIFIED, configure(mdqCase(), MDQ_RUN).outcome());
    }

    @Test
    void rejectsMdqWhenSignedUseDoesNotVerifyWithFetchedMetadataKey() {
        var keys = new FilePlanKeyStore(temp.resolve("wrong-keys"), Clock.fixed(NOW, ZoneOffset.UTC));
        bodies.put("mdq-request", request(keys.getOrCreate(MDQ_PLAN, "wrong"), "_mdq-request",
                "http://localhost:18080/p/" + MDQ_PLAN, NOW.plusSeconds(2),
                "https://suite.example/sp/acs/0"));
        assertEquals(Outcome.NOT_VERIFIED, configure(mdqCase(), MDQ_RUN).outcome());
    }

    @Test
    void rejectsRuntimeInventoryAndRestorationTamperingEvenWhenReceiptHashesChange() throws Exception {
        var runtime = (ObjectNode) json.mapper().readTree(Files.readAllBytes(
                refreshFolder.resolve("target-runtime-end.json")));
        runtime.put("containerId", "b".repeat(64));
        write(refreshFolder, "target-runtime-end.json", json.mapper().writeValueAsBytes(runtime));
        hashField(refreshFolder, refreshManifest, "targetRuntimeEndSha256", "target-runtime-end.json");
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());

        runtime.put("containerId", "a".repeat(64));
        write(refreshFolder, "target-runtime-end.json", json.mapper().writeValueAsBytes(runtime));
        hashField(refreshFolder, refreshManifest, "targetRuntimeEndSha256", "target-runtime-end.json");
        write(refreshFolder, "admin-final.json", "[{}]".getBytes(StandardCharsets.UTF_8));
        hashField(refreshFolder, refreshManifest, "adminFinalSha256", "admin-final.json");
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());
    }

    @Test
    void rejectsSyntheticHttpStatusAndMissingOldKeyRefetch() throws Exception {
        var old = (ObjectNode) json.mapper().readTree(Files.readAllBytes(
                refreshFolder.resolve("old-key-control.json")));
        old.put("responseStatus", 600);
        write(refreshFolder, "old-key-control.json", json.mapper().writeValueAsBytes(old));
        hashField(refreshFolder, refreshManifest, "oldKeyControlSha256", "old-key-control.json");
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());

        old.put("responseStatus", 400);
        write(refreshFolder, "old-key-control.json", json.mapper().writeValueAsBytes(old));
        hashField(refreshFolder, refreshManifest, "oldKeyControlSha256", "old-key-control.json");
        refreshManifest.withObject("/oldKeyControl").put("relaySequence", 2);
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());
    }

    @Test
    void rejectsCrossRunOrEarlyRefreshAndLeavesCapabilityAbsenceSemanticsIntact() throws Exception {
        refreshManifest.put("runId", MDQ_RUN);
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());

        refreshManifest.put("runId", REFRESH_RUN);
        var original = entries.stream().filter(value -> "control-b".equals(value.id())).findFirst().orElseThrow();
        entries.set(entries.indexOf(original), withTime(original, NOW.plusSeconds(15)));
        save(refreshFolder, refreshManifest);
        assertEquals(Outcome.NOT_VERIFIED, configure(refreshCase(), REFRESH_RUN).outcome());

        Files.delete(refreshFolder.resolve("manifest.json"));
        var test = refreshCase();
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context(REFRESH_RUN)));
        var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context(REFRESH_RUN), waiting.next(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,
                        "No native recurring source")));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    private void buildMdq(PlanCredentials key) throws Exception {
        var entity = "http://localhost:18080/p/" + MDQ_PLAN;
        var relay = relayUrl(entity);
        var source = "http://samlscope-reference-suite:8080/mdq/"
                + URLEncoder.encode(entity, StandardCharsets.UTF_8);
        var metadata = metadata(entity, key);
        write(mdqFolder, "metadata-mdq.xml", metadata);
        var bootstrapId = "_mdq-bootstrap";
        var bootstrapRequest = request(key, bootstrapId, entity, NOW, "https://suite.example/sp/acs/0");
        var bootstrapResponse = response(bootstrapId, "https://suite.example/sp/acs/0");
        bodies.put("mdq-bootstrap", bootstrapRequest);
        bodies.put("mdq-bootstrap-response", bootstrapResponse);
        entries.add(entry("mdq-bootstrap", MDQ_RUN, Direction.OUTBOUND, NOW, bootstrapId,
                "GET", TARGET, null, "mdq-bootstrap", bootstrapRequest.length,
                Map.of("type", "AuthnRequest", "id", bootstrapId)));
        entries.add(entry("mdq-bootstrap-response", MDQ_RUN, Direction.INBOUND, NOW.plusSeconds(1),
                bootstrapId, "POST", "https://suite.example/sp/acs/0", 200,
                "mdq-bootstrap-response", bootstrapResponse.length,
                Map.of("type", "Response", "normalFlowAccepted", true,
                        "statusCode", success(), "inResponseTo", bootstrapId)));
        var requestId = "_mdq-request";
        var request = request(key, requestId, entity, NOW.plusSeconds(2), "https://suite.example/sp/acs/0");
        var response = response(requestId, "https://suite.example/sp/acs/0");
        bodies.put("mdq-request", request);
        bodies.put("mdq-response", response);
        entries.add(entry("mdq-request", MDQ_RUN, Direction.OUTBOUND, NOW.plusSeconds(2), "action-mdq", "POST", TARGET,
                null, "mdq-request", request.length,
                Map.of("type", "AuthnRequest", "active_probe", true, "fixture_id", "valid",
                        "scenario_case_id", "IIP-ALG01-a-idp-01", "action_id", "action-mdq")));
        entries.add(entry("mdq-response", MDQ_RUN, Direction.INBOUND, NOW.plusSeconds(3), requestId,
                "POST", "https://suite.example/sp/acs/0", 200, "mdq-response", response.length,
                Map.of("type", "Response", "activeProbeAccepted", true,
                        "statusCode", success(), "inResponseTo", requestId)));
        mdqManifest = json.mapper().createObjectNode();
        mdqManifest.put("schema", "samlscope-keycloak-native-mdq-v1");
        mdqManifest.put("adapter", KeycloakMetadataUrlEvidenceFile.MDQ_ADAPTER);
        mdqManifest.put("runId", MDQ_RUN);
        mdqManifest.put("entityId", entity);
        mdqManifest.put("relayUrl", relay);
        mdqManifest.put("sourceUrl", source);
        mdqManifest.put("metadataSha256", sha(metadata));
        var bootstrap = mdqManifest.putObject("bootstrap");
        bootstrap.put("requestReference", "mdq-bootstrap");
        bootstrap.put("responseReference", "mdq-bootstrap-response");
        bootstrap.put("relaySequence", 1);
        var exchange = mdqManifest.putObject("exchange");
        exchange.put("requestReference", "mdq-request");
        exchange.put("responseReference", "mdq-response");
        var bootstrapRecord = relayRecord(1, entity, source, metadata, "fetch",
                NOW.plusMillis(100), NOW.plusMillis(300));
        common(mdqFolder, mdqManifest, entity, relay, List.of(bootstrapRecord), 2, 2, 1);
        save(mdqFolder, mdqManifest);
    }

    private void buildRefresh(PlanCredentials keyA, PlanCredentials keyB) throws Exception {
        var entity = "http://localhost:18080/p/" + REFRESH_PLAN;
        var relay = relayUrl(entity);
        var source = "http://samlscope-reference-suite:8080/p/" + REFRESH_PLAN
                + "/metadata/live?run=" + REFRESH_RUN;
        metadataA = metadata(entity, keyA);
        metadataB = metadata(entity, keyB);
        write(refreshFolder, "metadata-a.xml", metadataA);
        write(refreshFolder, "metadata-b.xml", metadataB);

        var aStart = NOW.plusSeconds(10);
        var bStart = aStart.plusSeconds(WAIT + 2);
        var oldStart = bStart.plusSeconds(WAIT + 3);
        addRefreshRequest("request-a", REFRESH_RUN, "_request-a", "entity-root", keyA,
                aStart, aStart.plusSeconds(1), true);
        addInvalid("control-b", "_control-b", "no-valid-until", keyB, bStart);
        addRefreshRequest("request-b", REFRESH_RUN, "_request-b", "no-valid-until", keyB,
                bStart.plusMillis(700), bStart.plusMillis(1500), true);
        addRefreshRequest("old-request", REFRESH_RUN, "_old-request", "keyvalue-only", keyA,
                oldStart, null, false);

        var invalidBody = "invalid signature".getBytes(StandardCharsets.UTF_8);
        terminal(refreshFolder, "signature-control", "_control-b", "control-b", invalidBody,
                bStart.plusMillis(500), 400);
        var oldBody = "old key rejected".getBytes(StandardCharsets.UTF_8);
        terminal(refreshFolder, "old-key-control", "_old-request", "old-request", oldBody,
                oldStart.plusMillis(500), 400);

        refreshManifest = json.mapper().createObjectNode();
        refreshManifest.put("schema", "samlscope-keycloak-native-metadata-refresh-v1");
        refreshManifest.put("adapter", KeycloakMetadataUrlEvidenceFile.REFRESH_ADAPTER);
        refreshManifest.put("runId", REFRESH_RUN);
        refreshManifest.put("entityId", entity);
        refreshManifest.put("relayUrl", relay);
        refreshManifest.put("sourceUrl", source);
        refreshManifest.put("refreshWaitSeconds", WAIT);
        refreshManifest.put("minimumRefreshSeconds", 10);
        refreshManifest.put("variantA", "entity-root");
        refreshManifest.put("variantB", "no-valid-until");
        refreshManifest.put("oldKeyVariant", "keyvalue-only");
        refreshManifest.put("metadataASha256", sha(metadataA));
        refreshManifest.put("metadataBSha256", sha(metadataB));
        refreshManifest.set("phaseA", phase("entity-root", "a", 1, false));
        refreshManifest.set("phaseB", phase("no-valid-until", "b", 2, true));
        var old = refreshManifest.putObject("oldKeyControl");
        old.put("variant", "keyvalue-only");
        old.put("requestReference", "old-request");
        old.put("relaySequence", 3);
        hashField(refreshFolder, refreshManifest, "signatureControlSha256", "signature-control.json");
        hashField(refreshFolder, refreshManifest, "signatureControlResponseSha256",
                "signature-control-response.html");
        hashField(refreshFolder, refreshManifest, "oldKeyControlSha256", "old-key-control.json");
        hashField(refreshFolder, refreshManifest, "oldKeyControlResponseSha256",
                "old-key-control-response.html");
        var records = List.of(
                relayRecord(1, entity, source, metadataA, "fetch",
                        aStart.plusMillis(100), aStart.plusMillis(300)),
                relayRecord(2, entity, source, metadataB, "fetch",
                        bStart.plusMillis(100), bStart.plusMillis(300)),
                relayRecord(3, entity, source, metadataB, "frozen",
                        oldStart.plusMillis(100), oldStart.plusMillis(300)));
        common(refreshFolder, refreshManifest, entity, relay, records, 2, 4, 3);
        save(refreshFolder, refreshManifest);
    }

    private void common(Path folder, ObjectNode manifest, String entity, String relay,
            List<ObjectNode> relayRecords, int writes, int roundTrips, int fetches) throws Exception {
        var before = "[]\n".getBytes(StandardCharsets.UTF_8);
        write(folder, "admin-before.json", before);
        write(folder, "admin-final.json", before);
        var attributes = Map.of(
                "saml.client.signature", "true",
                "saml.useMetadataDescriptorUrl", "true",
                "saml.metadataDescriptorUrl", relay,
                "saml.force.post.binding", "true");
        var configured = Map.ofEntries(
                Map.entry("schema", "samlscope-keycloak-client-readback-projection-v1"),
                Map.entry("client", Map.of("id", "01234567-89ab-cdef-0123-456789abcdef",
                        "clientId", entity, "protocol", "saml", "enabled", true,
                        "redirectUris", List.of(entity + "/sp/acs/0"), "attributes", attributes)),
                Map.entry("observedTopLevelFields", List.of("attributes", "clientId", "secret")),
                Map.entry("observedAttributeFields", List.of("saml.client.signature",
                        "saml.force.post.binding", "saml.metadataDescriptorUrl",
                        "saml.signing.certificate", "saml.signing.private.key",
                        "saml.useMetadataDescriptorUrl")),
                Map.entry("redactedCredentialFields", List.of("attributes.saml.signing.certificate",
                        "attributes.saml.signing.private.key", "secret")));
        write(folder, "admin-configured.json", json.mapper().writeValueAsBytes(configured));
        write(folder, "operation-counts.json", json.mapper().writeValueAsBytes(Map.of(
                "restored", true, "productConfigurationWrites", writes, "restorationWrites", 1,
                "protocolRoundTrips", roundTrips, "metadataFetches", fetches,
                "productRestarts", 0, "humanOperations", 0, "temporaryRelayStopped", true)));
        var sourcePath = Path.of("dev/keycloak/KeycloakMetadataUrlRelay.java");
        if (!Files.isRegularFile(sourcePath)) sourcePath = Path.of("../dev/keycloak/KeycloakMetadataUrlRelay.java");
        var source = Files.readAllBytes(sourcePath);
        assertEquals(RELAY_SOURCE_SHA, sha(source));
        write(folder, "KeycloakMetadataUrlRelay.java", source);
        var lines = new StringBuilder();
        for (var record : relayRecords) {
            lines.append(json.mapper().writeValueAsString(record)).append('\n');
            var sequence = record.path("sequence").asLong();
            var body = folder == mdqFolder ? Files.readAllBytes(folder.resolve("metadata-mdq.xml"))
                    : record.path("mode").asText().equals("fetch") && sequence == 1 ? metadataA : metadataB;
            write(folder, "relay-body-" + sequence + ".xml", body);
        }
        write(folder, "relay-requests.jsonl", lines.toString().getBytes(StandardCharsets.UTF_8));
        runtime(folder, "start");
        runtime(folder, "end");
        for (var value : Map.ofEntries(
                Map.entry("adminBeforeSha256", "admin-before.json"),
                Map.entry("adminConfiguredSha256", "admin-configured.json"),
                Map.entry("adminFinalSha256", "admin-final.json"),
                Map.entry("operationCountsSha256", "operation-counts.json"),
                Map.entry("relaySourceSha256", "KeycloakMetadataUrlRelay.java"),
                Map.entry("relayRequestsSha256", "relay-requests.jsonl"),
                Map.entry("targetRuntimeStartSha256", "target-runtime-start.json"),
                Map.entry("targetRuntimeEndSha256", "target-runtime-end.json")).entrySet()) {
            hashField(folder, manifest, value.getKey(), value.getValue());
        }
    }

    private void runtime(Path folder, String phase) throws Exception {
        var jar = getClass().getResourceAsStream(
                "/com/samlscope/runner/cases/keycloak-metadata-url/jar-manifest.json").readAllBytes();
        var providers = json.mapper().writeValueAsBytes(Map.ofEntries(
                Map.entry("schema", "samlscope-keycloak-metadata-provider-inventory-v1"),
                Map.entry("productVersion", "26.7.2"),
                Map.entry("publicKeyStorageProvider", "infinispan"),
                Map.entry("httpClientProvider", "default"),
                Map.entry("minTimeBetweenRequestsSeconds", 10),
                Map.entry("maxCacheTimeSeconds", 86400),
                Map.entry("configurationBasis", "factory-defaults-no-runtime-override"),
                Map.entry("servicesJarSha256", SERVICES),
                Map.entry("storageJarSha256", STORAGE)));
        var config = "# Keycloak test config\n".getBytes(StandardCharsets.UTF_8);
        write(folder, "keycloak-jars-" + phase + ".json", jar);
        write(folder, "provider-inventory-" + phase + ".json", providers);
        write(folder, "keycloak-config-" + phase + ".txt", config);
        var runtime = json.mapper().createObjectNode();
        runtime.put("schema", "samlscope-keycloak-metadata-url-runtime-v1");
        runtime.put("phase", phase);
        runtime.put("product", "keycloak");
        runtime.put("productVersion", "26.7.2");
        runtime.put("containerId", "a".repeat(64));
        runtime.put("imageId", IMAGE);
        runtime.put("configuredImage", "quay.io/keycloak/keycloak@" + IMAGE);
        runtime.put("startedAt", "2026-09-30T05:00:00Z");
        runtime.put("runningAtCapture", true);
        runtime.putArray("environmentKeys").add("KC_HTTP_ENABLED").add("KC_HOSTNAME");
        runtime.put("jarManifestSha256", sha(jar));
        runtime.put("providerInventorySha256", sha(providers));
        runtime.put("keycloakConfigSha256", sha(config));
        write(folder, "target-runtime-" + phase + ".json", json.mapper().writeValueAsBytes(runtime));
    }

    private ObjectNode relayRecord(long sequence, String entity, String source, byte[] body,
            String mode, Instant start, Instant end) {
        var value = json.mapper().createObjectNode();
        value.put("sequence", sequence);
        value.put("startedAt", start.toString());
        value.put("completedAt", end.toString());
        value.put("method", "GET");
        value.put("requestPath", "/entities/" + URLEncoder.encode(entity, StandardCharsets.UTF_8));
        value.put("entityId", entity);
        value.put("mode", mode);
        value.put("sourceUrl", source);
        value.put("httpStatus", 200);
        value.put("upstreamSha256", sha(body));
        value.put("servedSha256", sha(body));
        value.put("servedFile", "relay-body-" + sequence + ".xml");
        value.put("failure", "");
        return value;
    }

    private void addRefreshRequest(String ref, String run, String id, String variant,
            PlanCredentials key, Instant requestAt, Instant responseAt, boolean accepted) {
        var destination = "https://suite.example/sp/acs/0?mdv=" + variant + "&run=" + run;
        var request = request(key, id, "http://localhost:18080/p/" + REFRESH_PLAN,
                requestAt, destination);
        bodies.put(ref, request);
        entries.add(entry(ref, run, Direction.OUTBOUND, requestAt, id, "POST", TARGET, null,
                ref, request.length, Map.of("type", "AuthnRequest", "id", id,
                        "campaign", "metadata-polling", "variant", variant,
                        "metadataSignatureControl", "valid")));
        if (!accepted) return;
        var response = response(id, destination);
        bodies.put(ref + "-response", response);
        entries.add(entry(ref + "-response", run, Direction.INBOUND, responseAt, id, "POST",
                destination, 200, ref + "-response", response.length,
                Map.of("type", "Response", "metadataProbeAccepted", true,
                        "statusCode", success(), "inResponseTo", id)));
        var suffix = ref.endsWith("a") ? "a" : "b";
        var metadata = suffix.equals("a") ? metadataA : metadataB;
        var base = requestAt;
        var fetchAt = ref.endsWith("b") ? requestAt.minusMillis(600) : base.plusMillis(120);
        var preparedAt = ref.endsWith("b") ? requestAt.minusMillis(500) : base.plusMillis(180);
        bodies.put("prepared-" + suffix, metadata);
        entries.add(entry("fetch-" + suffix, run, Direction.INBOUND, fetchAt, "fetch-" + suffix,
                "GET", "https://suite.example/metadata/live", 200, null, 0,
                Map.of("type", "MetadataFetch", "variant", variant, "feed", "live")));
        entries.add(entry("prepared-" + suffix, run, Direction.OUTBOUND, preparedAt, "fetch-" + suffix,
                "GET", "https://suite.example/metadata/live", 200, "prepared-" + suffix, metadata.length,
                Map.of("type", "MetadataPrepared", "sourceType", "MetadataFetch",
                        "fetchTranscriptId", "fetch-" + suffix, "variant", variant,
                        "feed", "live", "metadataSha256", sha(metadata))));
    }

    private void addInvalid(String ref, String id, String variant, PlanCredentials key, Instant at) {
        var destination = "https://suite.example/sp/acs/0?mdv=" + variant + "&run=" + REFRESH_RUN;
        var request = new SamlSignedRequestFactory().build(
                SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE, id, URI.create(TARGET),
                "http://localhost:18080/p/" + REFRESH_PLAN, URI.create(destination), at, key);
        bodies.put(ref, request);
        entries.add(entry(ref, REFRESH_RUN, Direction.OUTBOUND, at, id, "POST", TARGET, null,
                ref, request.length, Map.of("type", "AuthnRequest", "id", id,
                        "campaign", "metadata-polling", "variant", variant,
                        "metadataSignatureControl", "invalid")));
    }

    private ObjectNode phase(String variant, String suffix, long sequence, boolean control) {
        var phase = json.mapper().createObjectNode();
        phase.put("variant", variant);
        phase.put("fetchReference", "fetch-" + suffix);
        phase.put("preparedReference", "prepared-" + suffix);
        phase.put("requestReference", "request-" + suffix);
        phase.put("responseReference", "request-" + suffix + "-response");
        phase.put("relaySequence", sequence);
        if (control) phase.put("controlRequestReference", "control-b");
        return phase;
    }

    private void terminal(Path folder, String name, String id, String ref, byte[] body,
            Instant observed, int status) throws Exception {
        write(folder, name + "-response.html", body);
        var value = Map.ofEntries(
                Map.entry("requestId", id), Map.entry("requestSha256", sha(bodies.get(ref))),
                Map.entry("requestUrl", TARGET), Map.entry("responseUrl", TARGET + "?error=1"),
                Map.entry("responseStatus", status), Map.entry("responseBodySha256", sha(body)),
                Map.entry("observedAt", observed.toString()),
                Map.entry("samlResponseFormPresent", false), Map.entry("deliveryState", "HTTP_RESPONSE"),
                Map.entry("productVerdictAssigned", false));
        write(folder, name + ".json", json.mapper().writeValueAsBytes(value));
    }

    private TestCase mdqCase() {
        return new MdqAcquisitionConfigurationTestCase(fallback(MdqAcquisitionConfigurationTestCase.ID),
                entry -> bodies.get(entry.decodedSamlRef()), temp.resolve("evidence"));
    }

    private TestCase refreshCase() {
        return new MetadataRefreshConfigurationTestCase(fallback(MetadataRefreshConfigurationTestCase.ID),
                entry -> bodies.get(entry.decodedSamlRef()), temp.resolve("evidence"));
    }

    private TestCase fallback(String id) {
        var evidence = new AttestedOutcomeTestCase(id, TargetRole.IDP, "metadata URL", "Review evidence",
                Duration.ofDays(1), List.of(AttestationOption.notVerified("unknown", "unknown", "unknown")));
        return new ConfigurationGateTestCase(evidence, "metadata-url", "Configure metadata URL",
                Duration.ofDays(1), ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
    }

    private com.samlscope.core.evaluation.CaseOutcome configure(TestCase test, String run) {
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context(run)));
        return assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(run), waiting.next(), new CaseEvent.ConfigConfirmed())).outcome();
    }

    private CaseContext context(String run) {
        return new CaseContext() {
            @Override public String runId() { return run; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW.plusSeconds(90), ZoneOffset.UTC); }
            @Override public TestPlan.Parameters parameters() {
                return new TestPlan.Parameters(180, WAIT, "", TestPlan.RequestSigningMode.REQUIRED);
            }
            @Override public TestPlan.Interaction interaction() { return TestPlan.Interaction.defaults(); }
            @Override public Reachability reachability() { return Reachability.CONFIRMED; }
            @Override public TranscriptRecorder transcript() {
                return new TranscriptRecorder() {
                    @Override public TranscriptEntry record(TranscriptInput input) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public TranscriptEntry updateSamlAnalysis(
                            String id, String correlation, Map<String, Object> summary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String ignored) {
                        return entries.stream().filter(value -> run.equals(value.runId())).toList();
                    }
                };
            }
            @Override public boolean transcriptComplete() { return true; }
        };
    }

    private byte[] metadata(String entity, PlanCredentials key) {
        var certificate = Base64.getEncoder().encodeToString(encoded(key));
        return ("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='" + entity + "'>"
                + "<md:SPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' "
                + "Location='https://suite.example/sp/acs/0' index='0'/></md:SPSSODescriptor>"
                + "</md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] request(PlanCredentials key, String id, String issuer, Instant at, String acs) {
        return new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.VALID,
                id, URI.create(TARGET), issuer, URI.create(acs), at, key);
    }

    private byte[] response(String requestId, String destination) {
        return ("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "ID='_response' Version='2.0' InResponseTo='" + requestId
                + "' Destination='" + destination.replace("&", "&amp;")
                + "'><samlp:Status><samlp:StatusCode Value='" + success()
                + "'/></samlp:Status></samlp:Response>").getBytes(StandardCharsets.UTF_8);
    }

    private TranscriptEntry entry(String id, String run, Direction direction, Instant time,
            String correlation, String method, String url, Integer status, String decoded, int size,
            Map<String, Object> summary) {
        return new TranscriptEntry(id, run, direction, time, correlation, method, url, status, Map.of(),
                null, 0, decoded, size, "application/xml", null, summary);
    }

    private TranscriptEntry withTime(TranscriptEntry value, Instant time) {
        return new TranscriptEntry(value.id(), value.runId(), value.direction(), time, value.correlationId(),
                value.method(), value.url(), value.status(), value.headers(), value.bodyRef(), value.bodyBytes(),
                value.decodedSamlRef(), value.decodedSamlBytes(), value.contentType(), value.rawQuery(),
                value.samlSummary());
    }

    private TranscriptEntry withSummary(TranscriptEntry value, Map<String, Object> summary) {
        return new TranscriptEntry(value.id(), value.runId(), value.direction(), value.timestamp(),
                value.correlationId(), value.method(), value.url(), value.status(), value.headers(),
                value.bodyRef(), value.bodyBytes(), value.decodedSamlRef(), value.decodedSamlBytes(),
                value.contentType(), value.rawQuery(), Map.copyOf(summary));
    }

    private String relayUrl(String entity) {
        return "http://samlscope-keycloak-metadata-relay:8081/entities/"
                + URLEncoder.encode(entity, StandardCharsets.UTF_8);
    }

    private byte[] encoded(PlanCredentials key) {
        try { return key.certificate().getEncoded(); }
        catch (Exception error) { throw new IllegalStateException(error); }
    }

    private String success() { return "urn:oasis:names:tc:SAML:2.0:status:Success"; }
    private void write(Path folder, String name, byte[] raw) throws Exception {
        Files.write(folder.resolve(name), raw);
    }
    private void hashField(Path folder, ObjectNode manifest, String field, String name) throws Exception {
        manifest.put(field, sha(Files.readAllBytes(folder.resolve(name))));
    }
    private void save(Path folder, ObjectNode manifest) throws Exception {
        Files.write(folder.resolve("manifest.json"), json.mapper().writeValueAsBytes(manifest));
    }
    private String sha(byte[] raw) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
        catch (Exception error) { throw new IllegalStateException(error); }
    }
}
