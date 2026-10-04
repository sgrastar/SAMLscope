package com.samlscope.runner.cases;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Fail-closed reader for the reference Keycloak native metadata-URL campaigns. */
final class KeycloakMetadataUrlEvidenceFile {
    static final String MDQ_ADAPTER = "keycloak-native-mdq-v1";
    static final String REFRESH_ADAPTER = "keycloak-native-metadata-url-refresh-v1";
    private static final String RUN_PATTERN = "run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String KEYCLOAK_IMAGE =
            "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";
    private static final String JAR_MANIFEST_SHA =
            "89a154de4e237a5c0280a262a38ed2f71d9648f09a88a47bead9c695fae0207e";
    private static final String RELAY_SOURCE_SHA =
            "7067092aafdaaffcddabbf9fcf60b53e6e1d20f6061f52f3c652197f626e865b";
    private static final String SERVICES_JAR_SHA =
            "213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9";
    private static final String STORAGE_JAR_SHA =
            "63ba0e2133e3a5a65f5a4b7944018d3ae7b524aecbcaeacadcdfc7a004fb76d6";
    private static final String SAML_PUBLIC_JAR_SHA =
            "e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2";
    private static final String SERVER_SPI_PRIVATE_JAR_SHA =
            "a9541ffb99d572a487afdbd0ce112f3038f8d58119857219306e14d3af400afa";
    private final TranscriptContentReader content;
    private final Path directory;
    private final JsonCodec json = new JsonCodec();

    KeycloakMetadataUrlEvidenceFile(TranscriptContentReader content, Path directory) {
        this.content = Objects.requireNonNull(content);
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
    }

    boolean mdqExists(String runId) {
        return exists(runId, ".mdq");
    }

    boolean refreshExists(String runId) {
        return exists(runId, ".refresh");
    }

    CaseOutcome evaluateMdq(CaseContext context) {
        String stage = "receipt-unavailable";
        try {
            var folder = folder(context, ".mdq");
            var manifestRaw = original(folder, "manifest.json", 262_144);
            var manifest = json.mapper().readTree(manifestRaw);
            require("samlscope-keycloak-native-mdq-v1".equals(text(manifest, "schema"))
                    && MDQ_ADAPTER.equals(text(manifest, "adapter"))
                    && context.runId().equals(text(manifest, "runId")));
            var entity = entity(manifest);
            var relayUrl = relayUrl(manifest, entity);
            var sourceUrl = text(manifest, "sourceUrl");
            require(sourceUrl.equals("http://samlscope-reference-suite:8080/mdq/"
                    + URLEncoder.encode(entity, StandardCharsets.UTF_8)));

            stage = "configuration-unproven";
            var common = common(folder, manifest, entity, relayUrl, 2, 2, 1);
            stage = "metadata-original-unproven";
            var metadata = checked(folder, manifest, "metadata-mdq.xml", "metadataSha256", 4_194_304);
            var keys = signingKeys(metadata(metadata, entity));
            require(!keys.isEmpty());
            stage = "transcript-correlation-unproven";
            var entries = entries(context);
            var bootstrapRequest = entry(entries, manifest.path("bootstrap"), "requestReference");
            var bootstrapResponse = entry(entries, manifest.path("bootstrap"), "responseReference");
            var bootstrapId = normalRequest(bootstrapRequest);
            success(bootstrapResponse, bootstrapId, false, null);
            uniqueCorrelation(entries, bootstrapId);
            var request = entry(entries, manifest.path("exchange"), "requestReference");
            var response = entry(entries, manifest.path("exchange"), "responseReference");
            var requestId = signedProbeRequest(request, keys);
            success(response, requestId, false, true, null);
            require(bootstrapResponse.timestamp().isBefore(request.timestamp())
                    && request.timestamp().isBefore(response.timestamp()));
            uniqueProbeCorrelation(entries, requestId, request.correlationId());
            stage = "native-fetch-unproven";
            var bootstrapRelay = relay(common.relayRecords(), folder,
                    manifest.path("bootstrap").path("relaySequence").asLong(-1), entity,
                    "fetch", sourceUrl, metadata, bootstrapRequest.timestamp(), bootstrapResponse.timestamp());
            require(hash(metadata).equals(bootstrapRelay.upstreamSha256())
                    && hash(metadata).equals(bootstrapRelay.servedSha256()));
            var refs = List.of(
                    new EvidenceRef("transcript", "transcript:" + bootstrapRequest.id()),
                    new EvidenceRef("transcript", "transcript:" + bootstrapResponse.id()),
                    new EvidenceRef("transcript", "transcript:" + request.id()),
                    new EvidenceRef("transcript", "transcript:" + response.id()),
                    new EvidenceRef("native-mdq-receipt", context.runId() + ".mdq/manifest.json"));
            return new CaseOutcome(Outcome.SATISFIED, null, "mdq.native-acquisition-observed",
                    "mdq.native-acquisition-observed", refs, Map.of(
                            "native_adapter", MDQ_ADAPTER, "restored", true,
                            "runtime_pinned", true, "receipt_sha256", hash(manifestRaw)));
        } catch (Exception unproven) {
            return notVerified("native_mdq_acquisition_unproven",
                    "mdq.native-evidence-incomplete", stage);
        }
    }

    CaseOutcome evaluateRefresh(CaseContext context) {
        String stage = "receipt-unavailable";
        try {
            var folder = folder(context, ".refresh");
            var manifestRaw = original(folder, "manifest.json", 262_144);
            var manifest = json.mapper().readTree(manifestRaw);
            require("samlscope-keycloak-native-metadata-refresh-v1".equals(text(manifest, "schema"))
                    && REFRESH_ADAPTER.equals(text(manifest, "adapter"))
                    && context.runId().equals(text(manifest, "runId")));
            var wait = context.parameters().metadataRefreshWaitSeconds();
            require(wait >= 10 && manifest.path("refreshWaitSeconds").asInt(-1) == wait
                    && manifest.path("minimumRefreshSeconds").asInt(-1) == 10
                    && "entity-root".equals(text(manifest, "variantA"))
                    && "no-valid-until".equals(text(manifest, "variantB"))
                    && "keyvalue-only".equals(text(manifest, "oldKeyVariant")));
            var entity = entity(manifest);
            var relayUrl = relayUrl(manifest, entity);
            var sourceUrl = text(manifest, "sourceUrl");
            require(sourceUrl.matches("http://samlscope-reference-suite:8080/p/plan_[0-9A-HJKMNP-TV-Z]{26}"
                    + "/metadata/live\\?run=" + context.runId()));

            stage = "configuration-unproven";
            var common = common(folder, manifest, entity, relayUrl, 2, 4, 3);
            stage = "metadata-originals-unproven";
            var metadataA = checked(folder, manifest, "metadata-a.xml", "metadataASha256", 4_194_304);
            var metadataB = checked(folder, manifest, "metadata-b.xml", "metadataBSha256", 4_194_304);
            require(!Arrays.equals(metadataA, metadataB));
            var keysA = signingKeys(metadata(metadataA, entity));
            var keysB = signingKeys(metadata(metadataB, entity));
            require(!keysA.isEmpty() && !keysB.isEmpty() && disjoint(keysA, keysB));
            var entries = entries(context);

            stage = "phase-a-unproven";
            var phaseA = phase(context, folder, entries, common.relayRecords(), manifest.path("phaseA"),
                    entity, text(manifest, "variantA"), sourceUrl, metadataA,
                    keysA, List.of(), null, null);
            stage = "phase-b-unproven";
            var invalidEvidence = json.mapper().readTree(checked(folder, manifest,
                    "signature-control.json", "signatureControlSha256", 262_144));
            var invalidBody = checked(folder, manifest, "signature-control-response.html",
                    "signatureControlResponseSha256", 4_194_304);
            var phaseB = phase(context, folder, entries, common.relayRecords(), manifest.path("phaseB"),
                    entity, text(manifest, "variantB"), sourceUrl, metadataB, keysB, keysA,
                    invalidEvidence, invalidBody);
            require(phaseB.control() != null
                    && !phaseB.control().timestamp().isBefore(phaseA.response().timestamp().plusSeconds(wait)));

            stage = "old-key-control-unproven";
            var old = manifest.path("oldKeyControl");
            require(old.isObject() && text(manifest, "oldKeyVariant").equals(text(old, "variant")));
            var oldRequest = entry(entries, old, "requestReference");
            require("valid".equals(oldRequest.samlSummary().get("metadataSignatureControl")));
            var oldId = signedRequest(oldRequest, keysA, keysB, text(manifest, "oldKeyVariant"));
            require(!oldRequest.timestamp().isBefore(phaseB.response().timestamp().plusSeconds(wait)));
            var oldEvidence = json.mapper().readTree(checked(folder, manifest,
                    "old-key-control.json", "oldKeyControlSha256", 262_144));
            var oldBody = checked(folder, manifest, "old-key-control-response.html",
                    "oldKeyControlResponseSha256", 4_194_304);
            var oldObserved = terminal(entries, oldRequest, oldId, oldEvidence, oldBody);
            var oldRelay = relay(common.relayRecords(), folder, old.path("relaySequence").asLong(-1),
                    entity, "frozen", sourceUrl, metadataB, oldRequest.timestamp(), oldObserved);
            require(hash(metadataB).equals(oldRelay.servedSha256()));

            var refs = new LinkedHashSet<EvidenceRef>();
            for (var item : List.of(phaseA.fetch(), phaseA.prepared(), phaseA.request(), phaseA.response(),
                    phaseB.control(), phaseB.fetch(), phaseB.prepared(), phaseB.request(), phaseB.response(),
                    oldRequest)) {
                if (item != null) refs.add(new EvidenceRef("transcript", "transcript:" + item.id()));
            }
            refs.add(new EvidenceRef("native-metadata-refresh-receipt",
                    context.runId() + ".refresh/manifest.json"));
            return new CaseOutcome(Outcome.SATISFIED, null, "metadata.native-refresh-observed",
                    "metadata.native-refresh-observed", List.copyOf(refs), Map.ofEntries(
                            Map.entry("adapter", REFRESH_ADAPTER),
                            Map.entry("refresh_wait_seconds", wait),
                            Map.entry("minimum_refresh_seconds", 10),
                            Map.entry("metadata_a_sha256", hash(metadataA)),
                            Map.entry("metadata_b_sha256", hash(metadataB)),
                            Map.entry("changed_signing_key_used", true),
                            Map.entry("invalid_signature_rejected", true),
                            Map.entry("old_key_rejected", true),
                            Map.entry("restored", true),
                            Map.entry("runtime_pinned", true),
                            Map.entry("receipt_sha256", hash(manifestRaw))));
        } catch (Exception unproven) {
            return notVerified("metadata_refresh_unproven",
                    "metadata.native-refresh-evidence-incomplete", stage);
        }
    }

    private record Common(List<JsonNode> relayRecords) {}
    private record Phase(TranscriptEntry control, TranscriptEntry fetch, TranscriptEntry prepared,
            TranscriptEntry request, TranscriptEntry response) {}
    private record RelayRecord(String upstreamSha256, String servedSha256) {}

    private Common common(Path folder, JsonNode manifest, String entity, String relayUrl,
            int configurationWrites, int protocolRoundTrips, int metadataFetches) throws Exception {
        var before = checked(folder, manifest, "admin-before.json", "adminBeforeSha256", 1_048_576);
        var configured = checked(folder, manifest, "admin-configured.json", "adminConfiguredSha256", 1_048_576);
        var after = checked(folder, manifest, "admin-final.json", "adminFinalSha256", 1_048_576);
        require(Arrays.equals(before, after));
        var beforeJson = json.mapper().readTree(before);
        require(beforeJson.isArray() && beforeJson.isEmpty());
        configuredClient(json.mapper().readTree(configured), entity, relayUrl);
        var counts = json.mapper().readTree(checked(folder, manifest, "operation-counts.json",
                "operationCountsSha256", 262_144));
        require(counts.path("restored").asBoolean(false)
                && counts.path("productConfigurationWrites").asInt(-1) == configurationWrites
                && counts.path("restorationWrites").asInt(-1) == 1
                && counts.path("protocolRoundTrips").asInt(-1) == protocolRoundTrips
                && counts.path("metadataFetches").asInt(-1) == metadataFetches
                && counts.path("productRestarts").asInt(-1) == 0
                && counts.path("humanOperations").asInt(-1) == 0
                && counts.path("temporaryRelayStopped").asBoolean(false));
        var source = checked(folder, manifest, "KeycloakMetadataUrlRelay.java",
                "relaySourceSha256", 262_144);
        require(RELAY_SOURCE_SHA.equals(hash(source)));
        var relayRaw = checked(folder, manifest, "relay-requests.jsonl", "relayRequestsSha256", 2_097_152);
        var records = new ArrayList<JsonNode>();
        var sequences = new HashSet<Long>();
        for (var line : new String(relayRaw, StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank()) continue;
            var record = json.mapper().readTree(line);
            require(record.isObject() && sequences.add(record.path("sequence").asLong(-1))
                    && "GET".equals(text(record, "method"))
                    && record.path("httpStatus").asInt(-1) == 200
                    && text(record, "failure").isEmpty());
            records.add(record);
        }
        require(records.size() == metadataFetches);
        var start = runtime(folder, manifest, "start", "targetRuntimeStartSha256");
        var end = runtime(folder, manifest, "end", "targetRuntimeEndSha256");
        require(text(start, "containerId").equals(text(end, "containerId"))
                && text(start, "imageId").equals(text(end, "imageId"))
                && text(start, "startedAt").equals(text(end, "startedAt"))
                && Arrays.equals(original(folder, "keycloak-jars-start.json", 131_072),
                        original(folder, "keycloak-jars-end.json", 131_072))
                && Arrays.equals(original(folder, "provider-inventory-start.json", 262_144),
                        original(folder, "provider-inventory-end.json", 262_144))
                && Arrays.equals(original(folder, "keycloak-config-start.txt", 262_144),
                        original(folder, "keycloak-config-end.txt", 262_144)));
        return new Common(List.copyOf(records));
    }

    private JsonNode runtime(Path folder, JsonNode manifest, String phase, String hashField) throws Exception {
        var runtime = json.mapper().readTree(checked(folder, manifest,
                "target-runtime-" + phase + ".json", hashField, 262_144));
        require("samlscope-keycloak-metadata-url-runtime-v1".equals(text(runtime, "schema"))
                && phase.equals(text(runtime, "phase"))
                && "keycloak".equals(text(runtime, "product"))
                && "26.7.2".equals(text(runtime, "productVersion"))
                && KEYCLOAK_IMAGE.equals(text(runtime, "imageId"))
                && text(runtime, "containerId").matches("[0-9a-f]{64}")
                && text(runtime, "configuredImage").contains(KEYCLOAK_IMAGE.substring("sha256:".length()))
                && !text(runtime, "startedAt").isBlank()
                && runtime.path("runningAtCapture").asBoolean(false));
        var keys = runtime.path("environmentKeys");
        require(keys.isArray() && keys.size() > 0);
        for (var key : keys) {
            require(key.isTextual() && !key.asText().contains("=")
                    && !key.asText().startsWith("KC_SPI_PUBLIC_KEY_STORAGE_INFINISPAN_"));
        }
        var jars = original(folder, "keycloak-jars-" + phase + ".json", 131_072);
        var providers = original(folder, "provider-inventory-" + phase + ".json", 262_144);
        var config = original(folder, "keycloak-config-" + phase + ".txt", 262_144);
        require(hash(jars).equals(text(runtime, "jarManifestSha256"))
                && hash(providers).equals(text(runtime, "providerInventorySha256"))
                && hash(config).equals(text(runtime, "keycloakConfigSha256"))
                && JAR_MANIFEST_SHA.equals(hash(jars)));
        verifyJarManifest(json.mapper().readTree(jars));
        verifyProviders(json.mapper().readTree(providers));
        var configText = new String(config, StandardCharsets.UTF_8).toLowerCase();
        require(!configText.contains("public-key-storage") && !configText.contains("public_key_storage"));
        return runtime;
    }

    private void verifyJarManifest(JsonNode jars) {
        require(jars.isArray() && jars.size() == 348);
        var expected = Map.of(
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar", SERVICES_JAR_SHA,
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-model-infinispan-26.7.2.jar", STORAGE_JAR_SHA,
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar", SAML_PUBLIC_JAR_SHA,
                "/opt/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-private-26.7.2.jar",
                SERVER_SPI_PRIVATE_JAR_SHA);
        var found = new HashMap<String, String>();
        String previous = null;
        for (var item : jars) {
            var path = text(item, "path");
            require(path.startsWith("/opt/keycloak/lib/lib/main/")
                    && path.endsWith(".jar") && item.path("size").asLong(-1) > 0
                    && text(item, "sha256").matches("[0-9a-f]{64}")
                    && (previous == null || previous.compareTo(path) < 0)
                    && found.put(path, text(item, "sha256")) == null);
            previous = path;
        }
        expected.forEach((path, hash) -> require(hash.equals(found.get(path))));
    }

    private void verifyProviders(JsonNode inventory) {
        require("samlscope-keycloak-metadata-provider-inventory-v1".equals(text(inventory, "schema"))
                && "26.7.2".equals(text(inventory, "productVersion"))
                && "infinispan".equals(text(inventory, "publicKeyStorageProvider"))
                && "default".equals(text(inventory, "httpClientProvider"))
                && inventory.path("minTimeBetweenRequestsSeconds").asInt(-1) == 10
                && inventory.path("maxCacheTimeSeconds").asInt(-1) == 86400
                && "factory-defaults-no-runtime-override".equals(text(inventory, "configurationBasis"))
                && SERVICES_JAR_SHA.equals(text(inventory, "servicesJarSha256"))
                && STORAGE_JAR_SHA.equals(text(inventory, "storageJarSha256")));
    }

    private void configuredClient(JsonNode client, String entity, String relayUrl) {
        require(client.isObject()
                && "samlscope-keycloak-client-readback-projection-v1".equals(text(client, "schema")));
        var observedTop = client.path("observedTopLevelFields");
        var observedAttributes = client.path("observedAttributeFields");
        var redacted = client.path("redactedCredentialFields");
        require(observedTop.isArray() && observedAttributes.isArray() && redacted.isArray()
                && contains(observedTop, "clientId") && contains(observedTop, "attributes")
                && contains(observedTop, "secret")
                && contains(observedAttributes, "saml.useMetadataDescriptorUrl")
                && contains(observedAttributes, "saml.metadataDescriptorUrl")
                && contains(observedAttributes, "saml.signing.certificate")
                && contains(observedAttributes, "saml.signing.private.key")
                && redacted.size() == 3
                && contains(redacted, "secret")
                && contains(redacted, "attributes.saml.signing.certificate")
                && contains(redacted, "attributes.saml.signing.private.key"));
        client = client.path("client");
        require(client.isObject() && entity.equals(text(client, "clientId"))
                && "saml".equals(text(client, "protocol")) && client.path("enabled").asBoolean(false)
                && text(client, "id").matches("[0-9a-f-]{36}"));
        var redirects = client.path("redirectUris");
        require(redirects.isArray() && redirects.size() >= 1);
        var allowed = false;
        for (var value : redirects) {
            if (value.isTextual() && value.asText().startsWith(entity + "/sp/acs/")) allowed = true;
        }
        require(allowed);
        var attributes = client.path("attributes");
        require(attributes.isObject()
                && "true".equals(text(attributes, "saml.client.signature"))
                && "true".equals(text(attributes, "saml.useMetadataDescriptorUrl"))
                && relayUrl.equals(text(attributes, "saml.metadataDescriptorUrl"))
                && "true".equals(text(attributes, "saml.force.post.binding")));
    }

    private boolean contains(JsonNode values, String expected) {
        for (var value : values) if (value.isTextual() && expected.equals(value.asText())) return true;
        return false;
    }

    private Phase phase(CaseContext context, Path folder, Map<String, TranscriptEntry> entries,
            List<JsonNode> relayRecords, JsonNode receipt, String entity, String variant, String sourceUrl,
            byte[] metadata, List<X509Certificate> trusted, List<X509Certificate> forbidden,
            JsonNode terminalEvidence, byte[] terminalBody) throws Exception {
        require(receipt.isObject() && variant.equals(text(receipt, "variant")));
        var fetch = entry(entries, receipt, "fetchReference");
        var prepared = entry(entries, receipt, "preparedReference");
        var request = entry(entries, receipt, "requestReference");
        var response = entry(entries, receipt, "responseReference");
        TranscriptEntry control = null;
        Instant lower = request.timestamp();
        if (terminalEvidence != null) {
            control = entry(entries, receipt, "controlRequestReference");
            require("invalid".equals(control.samlSummary().get("metadataSignatureControl")));
            var controlId = signedRequest(control, List.of(), concat(trusted, forbidden), variant);
            lower = control.timestamp();
            var observed = terminal(entries, control, controlId, terminalEvidence, terminalBody);
            require(observed.isBefore(request.timestamp()));
        }
        require(fetch.direction() == Direction.INBOUND && "GET".equals(fetch.method())
                && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant"))
                && "live".equals(fetch.samlSummary().get("feed")));
        require(prepared.direction() == Direction.OUTBOUND && "GET".equals(prepared.method())
                && "MetadataPrepared".equals(prepared.samlSummary().get("type"))
                && fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))
                && variant.equals(prepared.samlSummary().get("variant"))
                && hash(metadata).equals(prepared.samlSummary().get("metadataSha256"))
                && Arrays.equals(metadata, content.readDecodedSaml(prepared)));
        var relay = relay(relayRecords, folder, receipt.path("relaySequence").asLong(-1),
                entity, "fetch", sourceUrl, metadata, lower, response.timestamp());
        require(hash(metadata).equals(relay.upstreamSha256()) && hash(metadata).equals(relay.servedSha256()));
        require("valid".equals(request.samlSummary().get("metadataSignatureControl")));
        var requestId = signedRequest(request, trusted, forbidden, variant);
        success(response, requestId, true, variant);
        uniqueCorrelation(entries, requestId);
        require(!fetch.timestamp().isBefore(lower) && !prepared.timestamp().isBefore(fetch.timestamp())
                && response.timestamp().isAfter(request.timestamp()));
        if (control != null) require(!request.timestamp().isBefore(prepared.timestamp()));
        return new Phase(control, fetch, prepared, request, response);
    }

    private String signedRequest(TranscriptEntry request, List<X509Certificate> trusted,
            List<X509Certificate> forbidden, String variant) throws Exception {
        require(request.direction() == Direction.OUTBOUND && "POST".equals(request.method())
                && "AuthnRequest".equals(request.samlSummary().get("type")));
        if (variant != null) {
            require("metadata-polling".equals(request.samlSummary().get("campaign"))
                    && variant.equals(request.samlSummary().get("variant")));
        }
        var raw = content.readDecodedSaml(request);
        var xml = SecureXml.parse(raw).getDocumentElement();
        var id = xml.getAttribute("ID");
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && id.equals(request.correlationId()) && id.equals(request.samlSummary().get("id")));
        verifySignature(xml, trusted, forbidden);
        return id;
    }

    private String signedProbeRequest(TranscriptEntry request, List<X509Certificate> trusted) throws Exception {
        require(request.direction() == Direction.OUTBOUND && "POST".equals(request.method())
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && Boolean.TRUE.equals(request.samlSummary().get("active_probe"))
                && "valid".equals(request.samlSummary().get("fixture_id"))
                && "IIP-ALG01-a-idp-01".equals(request.samlSummary().get("scenario_case_id"))
                && Objects.equals(request.correlationId(), request.samlSummary().get("action_id")));
        var xml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
        var id = xml.getAttribute("ID");
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && !id.isBlank());
        verifySignature(xml, trusted, List.of());
        return id;
    }

    private String normalRequest(TranscriptEntry request) throws Exception {
        require(request.direction() == Direction.OUTBOUND && "GET".equals(request.method())
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && !Boolean.TRUE.equals(request.samlSummary().get("active_probe")));
        var xml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
        var id = xml.getAttribute("ID");
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && id.equals(request.correlationId()) && id.equals(request.samlSummary().get("id")));
        return id;
    }

    private void verifySignature(Element xml, List<X509Certificate> trusted,
            List<X509Certificate> forbidden) {
        if (trusted.isEmpty()) {
            require(forbidden.stream().noneMatch(key -> new XmlSignatureVerifier()
                    .hasValidEnvelopedSignature(xml, key)));
        } else {
            require(trusted.stream().anyMatch(key -> new XmlSignatureVerifier()
                    .hasValidEnvelopedSignature(xml, key))
                    && forbidden.stream().noneMatch(key -> new XmlSignatureVerifier()
                            .hasValidEnvelopedSignature(xml, key)));
        }
    }

    private void success(TranscriptEntry response, String requestId, boolean metadataProbe, String variant)
            throws Exception {
        success(response, requestId, metadataProbe, false, variant);
    }

    private void success(TranscriptEntry response, String requestId, boolean metadataProbe,
            boolean activeProbe, String variant)
            throws Exception {
        require(response.direction() == Direction.INBOUND
                && "Response".equals(response.samlSummary().get("type"))
                && SUCCESS.equals(response.samlSummary().get("statusCode"))
                && requestId.equals(response.samlSummary().get("inResponseTo"))
                && (metadataProbe
                        ? Boolean.TRUE.equals(response.samlSummary().get("metadataProbeAccepted"))
                        : activeProbe
                                ? Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted"))
                                : Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))));
        var xml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
        require(P.equals(xml.getNamespaceURI()) && "Response".equals(xml.getLocalName())
                && requestId.equals(xml.getAttribute("InResponseTo"))
                && response.url().equals(xml.getAttribute("Destination")));
        if (metadataProbe) require(MetadataProbeCorrelation.matches(response.url(), response.runId(), variant));
        var statuses = xml.getElementsByTagNameNS(P, "StatusCode");
        require(statuses.getLength() == 1
                && SUCCESS.equals(((Element) statuses.item(0)).getAttribute("Value")));
    }

    private void uniqueCorrelation(Map<String, TranscriptEntry> entries, String requestId) {
        require(entries.values().stream().filter(item -> item.direction() == Direction.OUTBOUND
                && requestId.equals(item.correlationId())).count() == 1);
        require(entries.values().stream().filter(item -> item.direction() == Direction.INBOUND
                && requestId.equals(item.samlSummary().get("inResponseTo"))).count() == 1);
    }

    private void uniqueProbeCorrelation(Map<String, TranscriptEntry> entries, String requestId,
            String actionId) {
        long requests = 0;
        for (var item : entries.values()) {
            if (item.direction() != Direction.OUTBOUND
                    || !"AuthnRequest".equals(item.samlSummary().get("type"))) continue;
            try {
                var xml = SecureXml.parse(content.readDecodedSaml(item)).getDocumentElement();
                if (requestId.equals(xml.getAttribute("ID"))) requests++;
            } catch (Exception ignored) { }
        }
        require(requests == 1
                && entries.values().stream().filter(item -> item.direction() == Direction.OUTBOUND
                        && actionId.equals(item.correlationId())).count() == 1
                && entries.values().stream().filter(item -> item.direction() == Direction.INBOUND
                        && requestId.equals(item.samlSummary().get("inResponseTo"))).count() == 1);
    }

    private Instant terminal(Map<String, TranscriptEntry> entries, TranscriptEntry request, String requestId,
            JsonNode evidence, byte[] body) throws Exception {
        require(requestId.equals(text(evidence, "requestId"))
                && hash(content.readDecodedSaml(request)).equals(text(evidence, "requestSha256"))
                && Objects.equals(request.url(), text(evidence, "requestUrl"))
                && sameOrigin(request.url(), text(evidence, "responseUrl"))
                && evidence.path("responseStatus").asInt(-1) >= 400
                && evidence.path("responseStatus").asInt(-1) <= 599
                && hash(body).equals(text(evidence, "responseBodySha256"))
                && !evidence.path("samlResponseFormPresent").asBoolean(true)
                && "HTTP_RESPONSE".equals(text(evidence, "deliveryState"))
                && !evidence.path("productVerdictAssigned").asBoolean(true));
        require(entries.values().stream().noneMatch(item -> item.direction() == Direction.INBOUND
                && requestId.equals(item.samlSummary().get("inResponseTo"))));
        var observed = Instant.parse(text(evidence, "observedAt"));
        require(!observed.isBefore(request.timestamp()));
        return observed;
    }

    private RelayRecord relay(List<JsonNode> records, Path folder, long sequence, String entity,
            String mode, String source, byte[] served, Instant lower, Instant upper) throws Exception {
        var values = records.stream().filter(item -> item.path("sequence").asLong(-1) == sequence).toList();
        require(values.size() == 1);
        var item = values.getFirst();
        var started = Instant.parse(text(item, "startedAt"));
        var completed = Instant.parse(text(item, "completedAt"));
        require(entity.equals(text(item, "entityId")) && mode.equals(text(item, "mode"))
                && source.equals(text(item, "sourceUrl"))
                && text(item, "requestPath").equals("/entities/" + URLEncoder.encode(entity, StandardCharsets.UTF_8))
                && !started.isBefore(lower) && !completed.isBefore(started) && !completed.isAfter(upper)
                && hash(served).equals(text(item, "servedSha256")));
        var file = text(item, "servedFile");
        require(file.equals("relay-body-" + sequence + ".xml")
                && Arrays.equals(served, original(folder, file, 4_194_304)));
        return new RelayRecord(text(item, "upstreamSha256"), text(item, "servedSha256"));
    }

    private Map<String, TranscriptEntry> entries(CaseContext context) {
        require(context.transcriptComplete() && context.runId().matches(RUN_PATTERN));
        var result = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && result.put(entry.id(), entry) == null);
        }
        return result;
    }

    private TranscriptEntry entry(Map<String, TranscriptEntry> entries, JsonNode receipt, String field) {
        var result = entries.get(text(receipt, field));
        require(result != null);
        return result;
    }

    private String entity(JsonNode manifest) {
        var value = text(manifest, "entityId");
        require(value.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}"));
        return value;
    }

    private String relayUrl(JsonNode manifest, String entity) {
        var value = text(manifest, "relayUrl");
        var uri = URI.create(value);
        require("http".equals(uri.getScheme()) && "samlscope-keycloak-metadata-relay".equals(uri.getHost())
                && uri.getPort() == 8081
                && uri.getRawPath().equals("/entities/" + URLEncoder.encode(entity, StandardCharsets.UTF_8))
                && uri.getRawQuery() == null && uri.getRawFragment() == null);
        return value;
    }

    private Element metadata(byte[] raw, String entity) {
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        if (entity != null) require(entity.equals(root.getAttribute("entityID")));
        return root;
    }

    private String text(Element element, String attribute) {
        var value = element.getAttribute(attribute);
        require(!value.isBlank());
        return value;
    }

    private List<X509Certificate> signingKeys(Element root) throws Exception {
        var factory = CertificateFactory.getInstance("X.509");
        var result = new ArrayList<X509Certificate>();
        var roles = root.getElementsByTagNameNS(MD, "SPSSODescriptor");
        require(roles.getLength() == 1);
        var descriptors = ((Element) roles.item(0)).getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int index = 0; index < descriptors.getLength(); index++) {
            var descriptor = (Element) descriptors.item(index);
            if (descriptor.hasAttribute("use") && !descriptor.getAttribute("use").isBlank()
                    && !"signing".equals(descriptor.getAttribute("use"))) continue;
            var values = descriptor.getElementsByTagNameNS(DS, "X509Certificate");
            for (int item = 0; item < values.getLength(); item++) {
                var encoded = values.item(item).getTextContent().replaceAll("\\s+", "");
                result.add((X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(encoded))));
            }
        }
        return List.copyOf(result);
    }

    private boolean disjoint(List<X509Certificate> first, List<X509Certificate> second) throws Exception {
        var keys = new HashSet<String>();
        for (var value : first) keys.add(hash(value.getPublicKey().getEncoded()));
        for (var value : second) if (keys.contains(hash(value.getPublicKey().getEncoded()))) return false;
        return true;
    }

    private List<X509Certificate> concat(List<X509Certificate> first, List<X509Certificate> second) {
        var result = new ArrayList<X509Certificate>(first);
        result.addAll(second);
        return List.copyOf(result);
    }

    private boolean sameOrigin(String first, String second) {
        try {
            var a = URI.create(first);
            var b = URI.create(second);
            return Objects.equals(a.getScheme(), b.getScheme()) && Objects.equals(a.getHost(), b.getHost())
                    && effectivePort(a) == effectivePort(b);
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private int effectivePort(URI value) {
        if (value.getPort() >= 0) return value.getPort();
        return "https".equalsIgnoreCase(value.getScheme()) ? 443
                : "http".equalsIgnoreCase(value.getScheme()) ? 80 : -1;
    }

    private Path folder(CaseContext context, String suffix) {
        require(context.transcriptComplete() && context.runId() != null && context.runId().matches(RUN_PATTERN));
        var result = directory.resolve(context.runId() + suffix).normalize();
        require(result.getParent().equals(directory) && Files.isDirectory(result, LinkOption.NOFOLLOW_LINKS));
        return result;
    }

    private boolean exists(String runId, String suffix) {
        return runId != null && runId.matches(RUN_PATTERN)
                && Files.isRegularFile(directory.resolve(runId + suffix).resolve("manifest.json"),
                        LinkOption.NOFOLLOW_LINKS);
    }

    private byte[] checked(Path folder, JsonNode manifest, String file, String field, long maximum)
            throws Exception {
        var raw = original(folder, file, maximum);
        require(hash(raw).equals(text(manifest, field)));
        return raw;
    }

    private byte[] original(Path folder, String name, long maximum) throws Exception {
        var path = folder.resolve(name).normalize();
        require(path.getParent().equals(folder) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && Files.size(path) <= maximum);
        return Files.readAllBytes(path);
    }

    private String text(JsonNode object, String field) {
        var value = object.path(field);
        require(value.isTextual());
        return value.asText();
    }

    private String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private CaseOutcome notVerified(String code, String reason, String stage) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, code, reason, reason, List.of(),
                Map.of("evidence_issue", stage));
    }

    private void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Keycloak metadata URL evidence is incomplete");
    }
}
