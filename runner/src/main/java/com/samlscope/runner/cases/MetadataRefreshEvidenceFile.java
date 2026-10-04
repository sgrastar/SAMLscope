package com.samlscope.runner.cases;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.net.URI;
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

/** Fail-closed reader for native MD02.a A-to-B refresh evidence. */
final class MetadataRefreshEvidenceFile {
    private static final String RUN_PATTERN = "run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String ADAPTER = "simplesamlphp-native-mdq-refresh-v1";
    private final TranscriptContentReader content;
    private final Path directory;

    MetadataRefreshEvidenceFile(TranscriptContentReader content, Path directory) {
        this.content = Objects.requireNonNull(content);
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
    }

    boolean exists(String runId) {
        return runId != null && runId.matches(RUN_PATTERN)
                && Files.isRegularFile(folder(runId).resolve("manifest.json"), LinkOption.NOFOLLOW_LINKS);
    }

    CaseOutcome evaluate(CaseContext context) {
        String stage = "receipt-unavailable";
        try {
            require(context.transcriptComplete() && context.runId().matches(RUN_PATTERN));
            var folder = folder(context.runId());
            require(folder.getParent().equals(directory) && Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
            var manifestRaw = original(folder, "manifest.json", 131_072);
            var manifest = new JsonCodec().mapper().readTree(manifestRaw);
            if ("shibboleth-native-http-refresh-v1".equals(manifest.path("adapter").asText())) {
                return new ShibbolethMetadataRefreshEvidenceFile(content, directory).evaluate(context);
            }
            if (KeycloakMetadataUrlEvidenceFile.REFRESH_ADAPTER.equals(
                    manifest.path("adapter").asText())) {
                return new KeycloakMetadataUrlEvidenceFile(content, directory).evaluateRefresh(context);
            }
            require("samlscope-native-metadata-refresh-v1".equals(text(manifest, "schema"))
                    && context.runId().equals(text(manifest, "runId"))
                    && ADAPTER.equals(text(manifest, "adapter")));
            var wait = context.parameters().metadataRefreshWaitSeconds();
            require(wait > 0 && manifest.path("refreshWaitSeconds").asInt(-1) == wait);

            stage = "configuration-unproven";
            var originalConfig = checked(folder, manifest, "original-config.php", "originalConfigSha256", 1_048_576);
            var configuredConfig = checked(folder, manifest, "configured-config.php", "configuredConfigSha256", 1_048_576);
            var finalConfig = checked(folder, manifest, "final-config.php", "finalConfigSha256", 1_048_576);
            require(Arrays.equals(originalConfig, finalConfig));
            var overlay = ("\n$config['metadata.sources'] = [['type'=>'flatfile'], "
                    + "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>" + wait + "]];\n")
                    .getBytes(StandardCharsets.UTF_8);
            require(Arrays.equals(configuredConfig, concat(originalConfig, overlay)));
            var effective = new JsonCodec().mapper().readTree(
                    checked(folder, manifest, "effective-source.json", "effectiveSourceSha256", 131_072));
            require(effective.isArray() && effective.size() == 2
                    && "flatfile".equals(text(effective.get(0), "type"))
                    && "mdq".equals(text(effective.get(1), "type"))
                    && "http://127.0.0.1:8081".equals(text(effective.get(1), "server"))
                    && effective.get(1).path("cachelength").asInt(-1) == wait);
            var operations = new JsonCodec().mapper().readTree(
                    checked(folder, manifest, "operation-counts.json", "operationCountsSha256", 131_072));
            require(operations.path("restored").asBoolean(false)
                    && operations.path("product_configuration_writes").asInt(-1) == 2
                    && operations.path("restoration_writes").asInt(-1) == 1
                    && operations.path("product_restarts").asInt(-1) == 0
                    && operations.path("human_operations").asInt(-1) == 0);

            stage = "runtime-identity-unproven";
            var runtimeStart = targetRuntime(folder, manifest, "start", "targetRuntimeStartSha256");
            var runtimeEnd = targetRuntime(folder, manifest, "end", "targetRuntimeEndSha256");
            require(runtimeStart.path("binding").equals(runtimeEnd.path("binding"))
                    && runtimeStart.path("runtime_version").path("value")
                            .equals(runtimeEnd.path("runtime_version").path("value"))
                    && runtimeStart.path("version_source").path("sha256")
                            .equals(runtimeEnd.path("version_source").path("sha256")));

            stage = "metadata-originals-unproven";
            var metadataA = checked(folder, manifest, "metadata-a.xml", "metadataASha256", 1_048_576);
            var metadataB = checked(folder, manifest, "metadata-b.xml", "metadataBSha256", 1_048_576);
            require(!Arrays.equals(metadataA, metadataB));
            var rootA = metadata(metadataA, text(manifest, "entityId"));
            var rootB = metadata(metadataB, text(manifest, "entityId"));
            var keysA = signingKeys(rootA);
            var keysB = signingKeys(rootB);
            require(!keysA.isEmpty() && !keysB.isEmpty() && disjoint(keysA, keysB));
            var signatureControl = new JsonCodec().mapper().readTree(
                    checked(folder, manifest, "signature-control.json", "signatureControlSha256", 131_072));
            var signatureControlResponse = checked(folder, manifest, "signature-control-response.html",
                    "signatureControlResponseSha256", 1_048_576);

            var entries = new HashMap<String, TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) {
                require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
            }
            stage = "phase-a-unproven";
            var phaseA = phase(context, entries, manifest.path("phaseA"), "control",
                    metadataA, keysA, List.of(), null, null);
            stage = "phase-b-unproven";
            var phaseB = phase(context, entries, manifest.path("phaseB"), text(manifest, "variantB"),
                    metadataB, keysB, keysA, signatureControl, signatureControlResponse);
            require(phaseB.control() != null
                    && !phaseB.control().timestamp().isBefore(phaseA.response().timestamp().plusSeconds(wait))
                    && phaseA.response().timestamp().isBefore(phaseB.control().timestamp()));

            stage = "native-fetch-log-unproven";
            var requests = checked(folder, manifest, "proxy-requests.jsonl", "proxyRequestsSha256", 1_048_576);
            require(fetchRecorded(requests, text(manifest, "entityId"), hash(metadataA),
                            phaseA.fetch().timestamp(), phaseA.response().timestamp())
                    && fetchRecorded(requests, text(manifest, "entityId"), hash(metadataB),
                            phaseB.fetch().timestamp(), phaseB.response().timestamp()));
            var refs = new LinkedHashSet<EvidenceRef>();
            for (var entry : List.of(phaseA.fetch(), phaseA.prepared(), phaseA.request(), phaseA.response(),
                    phaseB.control(), phaseB.fetch(), phaseB.prepared(), phaseB.request(), phaseB.response())) {
                refs.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
            }
            refs.add(new EvidenceRef("native-metadata-refresh-receipt",
                    context.runId() + ".refresh/manifest.json"));
            return new CaseOutcome(Outcome.SATISFIED, null, "metadata.native-refresh-observed",
                    "metadata.native-refresh-observed", List.copyOf(refs), Map.of(
                            "adapter", ADAPTER, "refresh_wait_seconds", wait,
                            "metadata_a_sha256", hash(metadataA), "metadata_b_sha256", hash(metadataB),
                            "changed_signing_key_used", true, "restored", true,
                            "receipt_sha256", hash(manifestRaw)));
        } catch (Exception unproven) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "metadata_refresh_unproven",
                    "metadata.native-refresh-evidence-incomplete",
                    "metadata.native-refresh-evidence-incomplete", List.of(),
                    Map.of("evidence_issue", stage));
        }
    }

    private record Phase(TranscriptEntry control, TranscriptEntry fetch, TranscriptEntry prepared,
            TranscriptEntry request, TranscriptEntry response) {}

    private Phase phase(CaseContext context, Map<String, TranscriptEntry> entries, JsonNode receipt,
            String variant, byte[] metadataBytes, List<X509Certificate> trusted,
            List<X509Certificate> forbidden, JsonNode controlEvidence,
            byte[] controlResponse) throws Exception {
        require(receipt.isObject() && variant.equals(text(receipt, "variant")));
        var fetch = entries.get(text(receipt, "fetchReference"));
        var prepared = entries.get(text(receipt, "preparedReference"));
        var request = entries.get(text(receipt, "requestReference"));
        var response = entries.get(text(receipt, "responseReference"));
        require(fetch != null && prepared != null && request != null && response != null);
        TranscriptEntry control = null;
        if (controlEvidence == null) {
            require(receipt.path("controlRequestReference").isMissingNode());
        } else {
            control = entries.get(text(receipt, "controlRequestReference"));
            require(control != null && controlResponse != null);
            verifySignatureControl(control, request, variant, trusted, forbidden,
                    controlEvidence, controlResponse);
        }
        require(fetch.direction() == Direction.INBOUND && "GET".equals(fetch.method())
                && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant"))
                && "live".equals(fetch.samlSummary().get("feed")));
        require(prepared.direction() == Direction.OUTBOUND && "GET".equals(prepared.method())
                && "MetadataPrepared".equals(prepared.samlSummary().get("type"))
                && "MetadataFetch".equals(prepared.samlSummary().get("sourceType"))
                && fetch.id().equals(prepared.samlSummary().get("fetchTranscriptId"))
                && variant.equals(prepared.samlSummary().get("variant"))
                && "live".equals(prepared.samlSummary().get("feed"))
                && hash(metadataBytes).equals(prepared.samlSummary().get("metadataSha256"))
                && prepared.decodedSamlRef() != null
                && prepared.decodedSamlBytes() == metadataBytes.length
                && Arrays.equals(metadataBytes, content.readDecodedSaml(prepared)));
        require(request.direction() == Direction.OUTBOUND && "POST".equals(request.method())
                && "AuthnRequest".equals(request.samlSummary().get("type"))
                && "metadata-polling".equals(request.samlSummary().get("campaign"))
                && variant.equals(request.samlSummary().get("variant"))
                && "valid".equals(request.samlSummary().get("metadataSignatureControl")));
        var requestXml = SecureXml.parse(content.readDecodedSaml(request)).getDocumentElement();
        var requestId = requestXml.getAttribute("ID");
        require(P.equals(requestXml.getNamespaceURI()) && "AuthnRequest".equals(requestXml.getLocalName())
                && requestId.equals(request.samlSummary().get("id"))
                && requestId.equals(request.correlationId())
                && trusted.stream().anyMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(requestXml, key))
                && forbidden.stream().noneMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(requestXml, key)));
        require(response.direction() == Direction.INBOUND
                && "Response".equals(response.samlSummary().get("type"))
                && Boolean.TRUE.equals(response.samlSummary().get("metadataProbeAccepted"))
                && SUCCESS.equals(response.samlSummary().get("statusCode"))
                && requestId.equals(response.samlSummary().get("inResponseTo")));
        var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
        require(P.equals(responseXml.getNamespaceURI()) && "Response".equals(responseXml.getLocalName())
                && requestId.equals(responseXml.getAttribute("InResponseTo"))
                && response.url().equals(responseXml.getAttribute("Destination"))
                && MetadataProbeCorrelation.matches(response.url(), context.runId(), variant)
                && status(responseXml));
        var fetchLower = control == null ? request.timestamp() : control.timestamp();
        require(!fetch.timestamp().isBefore(fetchLower)
                && !prepared.timestamp().isBefore(fetch.timestamp())
                && response.timestamp().isAfter(prepared.timestamp()));
        if (control != null) require(!request.timestamp().isBefore(prepared.timestamp()));
        require(entries.values().stream().filter(value -> value.direction() == Direction.OUTBOUND
                && requestId.equals(value.correlationId())).count() == 1);
        require(entries.values().stream().filter(value -> value.direction() == Direction.INBOUND
                && requestId.equals(value.samlSummary().get("inResponseTo"))).count() == 1);
        return new Phase(control, fetch, prepared, request, response);
    }

    private void verifySignatureControl(TranscriptEntry control, TranscriptEntry validRequest,
            String variant, List<X509Certificate> trusted, List<X509Certificate> forbidden,
            JsonNode evidence, byte[] responseBody) throws Exception {
        require(control.direction() == Direction.OUTBOUND && "POST".equals(control.method())
                && "AuthnRequest".equals(control.samlSummary().get("type"))
                && "metadata-polling".equals(control.samlSummary().get("campaign"))
                && variant.equals(control.samlSummary().get("variant"))
                && "invalid".equals(control.samlSummary().get("metadataSignatureControl")));
        var xmlBytes = content.readDecodedSaml(control);
        var xml = SecureXml.parse(xmlBytes).getDocumentElement();
        var requestId = xml.getAttribute("ID");
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && requestId.equals(control.correlationId())
                && requestId.equals(control.samlSummary().get("id"))
                && trusted.stream().noneMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(xml, key))
                && forbidden.stream().noneMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(xml, key)));
        require(requestId.equals(text(evidence, "request_id"))
                && hash(xmlBytes).equals(text(evidence, "request_sha256"))
                && Objects.equals(control.url(), text(evidence, "request_url"))
                && evidence.path("response_url_exact_match").asBoolean(false)
                && sameOrigin(control.url(), text(evidence, "response_url"))
                && evidence.path("response_status").asInt(-1) >= 400
                && evidence.path("response_status").asInt(-1) <= 599
                && "signature-value-invalid".equals(text(evidence, "native_signature_rejection"))
                && !evidence.path("saml_response_form_present").asBoolean(true)
                && hash(responseBody).equals(text(evidence, "response_body_sha256")));
        var responseText = new String(responseBody, StandardCharsets.UTF_8);
        require(responseText.contains("NOTVALIDCERTSIGNATURE") && responseText.contains("AuthnRequest"));
        var observed = Instant.parse(text(evidence, "observed_at"));
        require(!observed.isBefore(control.timestamp()) && !observed.isAfter(validRequest.timestamp()));
    }

    private boolean sameOrigin(String first, String second) {
        try {
            var a = URI.create(first);
            var b = URI.create(second);
            return Objects.equals(a.getScheme(), b.getScheme())
                    && Objects.equals(a.getHost(), b.getHost())
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

    private JsonNode targetRuntime(Path folder, JsonNode manifest, String phase, String manifestField)
            throws Exception {
        var summary = new JsonCodec().mapper().readTree(checked(folder, manifest,
                "target-runtime-" + phase + ".json", manifestField, 131_072));
        require("samlscope-terminal-http-target-runtime-v1".equals(text(summary, "schema"))
                && "simplesamlphp".equals(text(summary, "product"))
                && phase.equals(text(summary, "phase")));
        var inspectRaw = original(folder, "target-container-inspect-" + phase + ".json", 4_194_304);
        var imageRaw = original(folder, "target-image-inspect-" + phase + ".json", 4_194_304);
        require(hash(inspectRaw).equals(text(summary, "docker_inspect_sha256"))
                && hash(imageRaw).equals(text(summary, "image_inspect_sha256")));
        var inspect = new JsonCodec().mapper().readTree(inspectRaw);
        var image = new JsonCodec().mapper().readTree(imageRaw);
        require(inspect.isArray() && inspect.size() == 1 && image.isArray() && image.size() == 1);
        var item = inspect.get(0);
        var binding = summary.path("binding");
        require(binding.isObject()
                && text(binding, "container_id").equals(text(item, "Id"))
                && text(binding, "image_id").equals(text(item, "Image"))
                && text(binding, "configured_image").equals(text(item.path("Config"), "Image"))
                && text(binding, "container_started_at").equals(text(item.path("State"), "StartedAt"))
                && binding.path("running_at_capture").asBoolean(false)
                && item.path("State").path("Running").asBoolean(false)
                && binding.path("host_port_bound").asBoolean(false)
                && binding.path("host_port").asInt(-1) == 18380
                && "80/tcp".equals(text(binding, "container_port")));
        var runtime = summary.path("runtime_version");
        var runtimeRaw = original(folder, text(runtime, "file"), 16_384);
        require(hash(runtimeRaw).equals(text(runtime, "sha256"))
                && new String(runtimeRaw, StandardCharsets.UTF_8).strip().equals(text(runtime, "value")));
        var source = summary.path("version_source");
        var sourceRaw = original(folder, text(source, "file"), 1_048_576);
        require(hash(sourceRaw).equals(text(source, "sha256"))
                && source.path("value").isTextual() && !source.path("value").asText().isBlank());
        return summary;
    }

    private boolean status(Element response) {
        var statuses = response.getElementsByTagNameNS(P, "StatusCode");
        return statuses.getLength() == 1
                && SUCCESS.equals(((Element) statuses.item(0)).getAttribute("Value"));
    }

    private Element metadata(byte[] raw, String entityId) {
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName())
                && entityId.equals(root.getAttribute("entityID")));
        return root;
    }

    private List<X509Certificate> signingKeys(Element root) throws Exception {
        var result = new ArrayList<X509Certificate>();
        var factory = CertificateFactory.getInstance("X.509");
        var roles = root.getElementsByTagNameNS(MD, "SPSSODescriptor");
        require(roles.getLength() == 1);
        var descriptors = ((Element) roles.item(0)).getElementsByTagNameNS(MD, "KeyDescriptor");
        for (int index = 0; index < descriptors.getLength(); index++) {
            var descriptor = (Element) descriptors.item(index);
            if (descriptor.hasAttribute("use") && !descriptor.getAttribute("use").isBlank()
                    && !"signing".equals(descriptor.getAttribute("use"))) continue;
            var certificates = descriptor.getElementsByTagNameNS(DS, "X509Certificate");
            for (int certificate = 0; certificate < certificates.getLength(); certificate++) {
                var encoded = ((Element) certificates.item(certificate)).getTextContent().replaceAll("\\s+", "");
                result.add((X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(Base64.getDecoder().decode(encoded))));
            }
        }
        return List.copyOf(result);
    }

    private boolean disjoint(List<X509Certificate> first, List<X509Certificate> second) throws Exception {
        var values = new HashSet<String>();
        for (var certificate : first) values.add(hash(certificate.getPublicKey().getEncoded()));
        for (var certificate : second) if (values.contains(hash(certificate.getPublicKey().getEncoded()))) return false;
        return true;
    }

    private boolean fetchRecorded(byte[] raw, String entity, String responseHash,
            Instant lower, Instant upper) throws Exception {
        var found = false;
        for (var line : new String(raw, StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank()) continue;
            var item = new JsonCodec().mapper().readTree(line);
            if (!entity.equals(text(item, "entityId")) || !responseHash.equals(text(item, "responseSha256"))
                    || item.path("httpStatus").asInt(-1) != 200) continue;
            var observed = Instant.parse(text(item, "observedAt"));
            if (!observed.isBefore(lower) && !observed.isAfter(upper)) found = true;
        }
        return found;
    }

    private byte[] checked(Path folder, JsonNode manifest, String file, String field, long maximum)
            throws Exception {
        var raw = original(folder, file, maximum);
        require(hash(raw).equals(text(manifest, field)));
        return raw;
    }

    private Path folder(String runId) {
        return directory.resolve(runId + ".refresh").normalize();
    }

    private byte[] original(Path folder, String name, long maximum) throws Exception {
        var path = folder.resolve(name).normalize();
        require(path.getParent().equals(folder) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && Files.size(path) <= maximum);
        return Files.readAllBytes(path);
    }

    private String text(JsonNode object, String field) {
        var value = object.path(field);
        require(value.isTextual() && !value.asText().isBlank());
        return value.asText();
    }

    private byte[] concat(byte[] first, byte[] second) {
        var result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Metadata refresh evidence is incomplete");
    }
}
