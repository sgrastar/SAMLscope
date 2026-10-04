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

/** Native Shibboleth scheduled HTTP refresh, followed by cryptographically bound A/B SAML use. */
final class ShibbolethMetadataRefreshEvidenceFile {
    private static final String RUN_PATTERN = "run_[0-9A-HJKMNP-TV-Z]{26}";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String ADAPTER = "shibboleth-native-http-refresh-v1";
    private final TranscriptContentReader content;
    private final Path directory;

    ShibbolethMetadataRefreshEvidenceFile(TranscriptContentReader content, Path directory) {
        this.content = Objects.requireNonNull(content);
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
    }

    CaseOutcome evaluate(CaseContext context) {
        String stage = "receipt-unavailable";
        try {
            require(context.transcriptComplete() && context.runId().matches(RUN_PATTERN));
            var folder = folder(context.runId());
            require(folder.getParent().equals(directory) && Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
            var manifestRaw = original(folder, "manifest.json", 131_072);
            var manifest = new JsonCodec().mapper().readTree(manifestRaw);
            require("samlscope-native-metadata-refresh-v1".equals(text(manifest, "schema"))
                    && context.runId().equals(text(manifest, "runId"))
                    && ADAPTER.equals(text(manifest, "adapter")));
            var wait = context.parameters().metadataRefreshWaitSeconds();
            require(wait > 0 && manifest.path("refreshWaitSeconds").asInt(-1) == wait);

            stage = "configuration-unproven";
            var originalConfig = checked(folder, manifest, "original-providers.xml", "originalConfigSha256", 1_048_576);
            var configuredConfig = checked(folder, manifest, "configured-providers.xml", "configuredConfigSha256", 1_048_576);
            var finalConfig = checked(folder, manifest, "final-providers.xml", "finalConfigSha256", 1_048_576);
            require(Arrays.equals(originalConfig, finalConfig));
            var originalAudit = checked(folder, manifest, "original-audit.xml", "originalAuditSha256", 1_048_576);
            var configuredAudit = checked(folder, manifest, "configured-audit.xml", "configuredAuditSha256", 1_048_576);
            var finalAudit = checked(folder, manifest, "final-audit.xml", "finalAuditSha256", 1_048_576);
            require(Arrays.equals(originalAudit, finalAudit));
            verifyConfiguration(context, manifest, originalConfig, configuredConfig, originalAudit, configuredAudit);
            var operations = new JsonCodec().mapper().readTree(
                    checked(folder, manifest, "operation-counts.json", "operationCountsSha256", 131_072));
            require(operations.path("restored").asBoolean(false)
                    && operations.path("product_configuration_writes").asInt(-1) == 4
                    && operations.path("restoration_writes").asInt(-1) == 2
                    && operations.path("product_restarts").asInt(-1) == 2
                    && operations.path("product_reloads").asInt(-1) == 0
                    && operations.path("human_operations").asInt(-1) == 0);
            var restoration = new JsonCodec().mapper().readTree(checked(folder, manifest,
                    "restoration.json", "restorationSha256", 131_072));
            require(restoration.path("restored").asBoolean(false)
                    && restoration.path("backingFileRemoved").asBoolean(false)
                    && restoration.path("failures").isArray() && restoration.path("failures").isEmpty());

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
            var signatureControl = manifest.path("phaseB");
            var signatureControlResponse = checked(folder, manifest, "native-signature-audit.log",
                    "nativeAuditSha256", 1_048_576);

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
                    && !phaseB.fetch().timestamp().isBefore(phaseA.response().timestamp().plusSeconds(wait))
                    && phaseA.response().timestamp().isBefore(phaseB.control().timestamp()));
            require(entries.values().stream().noneMatch(value -> value.direction() == Direction.INBOUND
                    && phaseB.control().correlationId().equals(value.samlSummary().get("inResponseTo"))
                    && SUCCESS.equals(value.samlSummary().get("statusCode"))));
            verifySuccessAudit(signatureControlResponse, phaseA, text(manifest, "entityId"));
            verifySuccessAudit(signatureControlResponse, phaseB, text(manifest, "entityId"));

            stage = "native-fetch-log-unproven";
            var nativeLog = checked(folder, manifest, "native-refresh.log", "nativeRefreshSha256", 1_048_576);
            require(nativeLoadRecorded(nativeLog, context.runId(), text(manifest, "metadataUrl"),
                            phaseA.prepared().timestamp(), phaseA.request().timestamp())
                    && nativeLoadRecorded(nativeLog, context.runId(), text(manifest, "metadataUrl"),
                            phaseB.prepared().timestamp(), phaseB.control().timestamp()));
            verifyOperationWindow(operations, phaseA.fetch().timestamp(), phaseB.response().timestamp());
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
        var entity = text(receipt, "entityId");
        require(entity.equals(SecureXml.parse(metadataBytes).getDocumentElement().getAttribute("entityID"))
                && issuer(requestXml).equals(entity));
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
        require(!prepared.timestamp().isBefore(fetch.timestamp())
                && !request.timestamp().isBefore(prepared.timestamp())
                && response.timestamp().isAfter(request.timestamp()));
        if (control != null) require(!control.timestamp().isBefore(prepared.timestamp())
                && request.timestamp().isAfter(control.timestamp()));
        require(text(receipt, "metadataUrl").equals(fetch.url())
                && fetch.headers().getOrDefault("User-Agent", List.of()).stream()
                        .anyMatch(value -> value.contains("Shibboleth")));

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
        require(issuer(xml).equals(text(evidence, "entityId")));
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && requestId.equals(control.correlationId())
                && requestId.equals(control.samlSummary().get("id"))
                && trusted.stream().noneMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(xml, key))
                && forbidden.stream().noneMatch(key -> new XmlSignatureVerifier()
                        .hasValidEnvelopedSignature(xml, key)));
        var entity = text(evidence, "entityId");
        var found = 0;
        for (var line : new String(responseBody, StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank()) continue;
            var fields = line.split("\\|", -1);
            require(fields.length == 9 && "SAMLscope-signature-v1".equals(fields[0]));
            if (!requestId.equals(fields[1])) continue;
            var observed = Instant.parse(fields[8]);
            require(entity.equals(fields[2]) && "MessageAuthenticationError".equals(fields[3])
                    && fields[4].isEmpty() && "true".equals(fields[5]) && "POST".equals(fields[6])
                    && "http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(fields[7])
                    && !observed.isBefore(control.timestamp()) && !observed.isAfter(validRequest.timestamp()));
            found++;
        }
        require(found == 1);
    }

    private void verifySuccessAudit(byte[] raw, Phase phase, String entity) {
        var found = 0;
        for (var line : new String(raw, StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank()) continue;
            var fields = line.split("\\|", -1);
            require(fields.length == 9 && "SAMLscope-signature-v1".equals(fields[0]));
            if (!phase.request().correlationId().equals(fields[1])) continue;
            var at = Instant.parse(fields[8]);
            require(entity.equals(fields[2]) && fields[3].isEmpty() && "Success".equals(fields[4])
                    && "true".equals(fields[5]) && "POST".equals(fields[6])
                    && "http://shibboleth.net/ns/profiles/saml2/sso/browser".equals(fields[7])
                    && !at.isBefore(phase.request().timestamp()) && !at.isAfter(phase.response().timestamp()));
            found++;
        }
        require(found == 1);
    }

    private JsonNode targetRuntime(Path folder, JsonNode manifest, String phase, String manifestField)
            throws Exception {
        var summary = new JsonCodec().mapper().readTree(checked(folder, manifest,
                "target-runtime-" + phase + ".json", manifestField, 131_072));
        require("samlscope-terminal-http-target-runtime-v1".equals(text(summary, "schema"))
                && "shibboleth".equals(text(summary, "product"))
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
                && binding.path("host_port").asInt(-1) == 18280
                && "8080/tcp".equals(text(binding, "container_port")));
        require(text(item, "Image").equals(text(image.get(0), "Id")));
        var ports = item.path("NetworkSettings").path("Ports").path("8080/tcp");
        var bound = false;
        for (var port : ports) bound |= "127.0.0.1".equals(port.path("HostIp").asText())
                && "18280".equals(port.path("HostPort").asText());
        require(bound);
        var runtime = summary.path("runtime_version");
        var runtimeRaw = original(folder, text(runtime, "file"), 16_384);
        require(hash(runtimeRaw).equals(text(runtime, "sha256"))
                && new String(runtimeRaw, StandardCharsets.UTF_8).strip().equals(text(runtime, "value")));
        var source = summary.path("version_source");
        var sourceRaw = original(folder, text(source, "file"), 1_048_576);
        require(hash(sourceRaw).equals(text(source, "sha256"))
                && text(source, "value").equals(text(runtime, "value"))
                && new String(sourceRaw, StandardCharsets.UTF_8).lines().anyMatch(value ->
                        value.equals("idp.installed.version=" + text(runtime, "value"))));
        return summary;
    }

    private boolean status(Element response) {
        var statuses = response.getElementsByTagNameNS(P, "StatusCode");
        return statuses.getLength() == 1
                && SUCCESS.equals(((Element) statuses.item(0)).getAttribute("Value"));
    }

    private String issuer(Element request) {
        var issuers = request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
        require(issuers.getLength() == 1 && issuers.item(0).getParentNode() == request
                && !issuers.item(0).getTextContent().isBlank());
        return issuers.item(0).getTextContent().strip();
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

    private boolean nativeLoadRecorded(byte[] raw, String run, String url, Instant lower, Instant upper) {
        var prefix = "FileBackedHTTPMetadataResolver Refresh" + run + ": New metadata successfully loaded for '" + url + "'";
        for (var line : new String(raw, StandardCharsets.UTF_8).split("\\R")) {
            if (!line.contains(prefix)) continue;
            require(line.length() >= 23);
            var at = java.time.LocalDateTime.parse(line.substring(0, 23),
                    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss,SSS"))
                    .toInstant(java.time.ZoneOffset.UTC);
            // The native log truncates sub-millisecond precision.
            if (!at.plusMillis(1).isBefore(lower) && !at.isAfter(upper)) return true;
        }
        return false;
    }

    private void verifyOperationWindow(JsonNode counts, Instant first, Instant last) {
        var operations = counts.path("operations");
        require(operations.isArray() && operations.size() == 6);
        var writes = 0;
        var restarts = 0;
        for (var item : operations) {
            require(item.path("recordedAt").isNumber());
            var at = Instant.ofEpochMilli((long) (item.path("recordedAt").asDouble() * 1000));
            require(at.isBefore(first) || at.isAfter(last));
            var operation = text(item, "operation");
            if ("product-config-write".equals(operation)) {
                require(item.path("readBack").asBoolean(false));
                writes++;
            } else {
                require("product-restart".equals(operation) && item.path("completed").asBoolean(false));
                restarts++;
            }
        }
        require(writes == 4 && restarts == 2);
    }

    private void verifyConfiguration(CaseContext context, JsonNode manifest, byte[] before,
            byte[] configured, byte[] originalAudit, byte[] configuredAudit) {
        var ns = "urn:mace:shibboleth:2.0:metadata";
        var xsi = "http://www.w3.org/2001/XMLSchema-instance";
        var original = SecureXml.parse(before).getDocumentElement();
        var modified = SecureXml.parse(configured).getDocumentElement();
        require(ns.equals(original.getNamespaceURI()) && "MetadataProvider".equals(original.getLocalName())
                && "ChainingMetadataProvider".equals(original.getAttributeNS(xsi, "type"))
                && ns.equals(modified.getNamespaceURI()) && "MetadataProvider".equals(modified.getLocalName()));
        var children = elements(modified);
        var baseline = elements(original);
        require(children.size() == baseline.size() + 1);
        var provider = children.get(0);
        var wait = context.parameters().metadataRefreshWaitSeconds();
        var url = text(manifest, "metadataUrl");
        var uri = URI.create(url);
        require("http".equals(uri.getScheme()) && "samlscope-reference-suite".equals(uri.getHost())
                && uri.getPort() == 8080 && ("run=" + context.runId()).equals(uri.getRawQuery())
                && uri.getPath().matches("/p/plan_[0-9A-HJKMNP-TV-Z]{26}/metadata/live"));
        require(text(manifest, "entityId").equals("http://localhost:18080"
                + uri.getPath().substring(0, uri.getPath().length() - "/metadata/live".length())));
        require(ns.equals(provider.getNamespaceURI()) && "MetadataProvider".equals(provider.getLocalName())
                && ("Refresh" + context.runId()).equals(provider.getAttribute("id"))
                && "FileBackedHTTPMetadataProvider".equals(provider.getAttributeNS(xsi, "type"))
                && url.equals(provider.getAttribute("metadataURL"))
                && ("/opt/reference-idp/metadata/refresh-" + context.runId() + ".xml").equals(provider.getAttribute("backingFile"))
                && ("PT" + wait + "S").equals(provider.getAttribute("minRefreshDelay"))
                && ("PT" + wait * 2 + "S").equals(provider.getAttribute("maxRefreshDelay"))
                && "0.75".equals(provider.getAttribute("refreshDelayFactor")) && elements(provider).isEmpty());
        modified.removeChild(provider);
        require(semanticXml(original).equals(semanticXml(modified)));
        var auditBefore = SecureXml.parse(originalAudit).getDocumentElement();
        var auditAfter = SecureXml.parse(configuredAudit).getDocumentElement();
        var entries = auditAfter.getElementsByTagNameNS("http://www.springframework.org/schema/beans", "entry");
        var found = 0;
        for (var i = 0; i < entries.getLength(); i++) {
            var node = (Element) entries.item(i);
            if (!"Shibboleth-Audit".equals(node.getAttribute("key"))) continue;
            require("SAMLscope-signature-v1|%I|%SP|%e|%S|%XX|%b|%P|%T".equals(node.getAttribute("value")));
            var originalEntries = auditBefore.getElementsByTagNameNS("http://www.springframework.org/schema/beans", "entry");
            var originalValues = new ArrayList<String>();
            for (var j = 0; j < originalEntries.getLength(); j++) {
                var originalNode = (Element) originalEntries.item(j);
                if ("Shibboleth-Audit".equals(originalNode.getAttribute("key")))
                    originalValues.add(originalNode.getAttribute("value"));
            }
            require(originalValues.size() == 1);
            node.setAttribute("value", originalValues.get(0));
            found++;
        }
        require(found == 1 && semanticXml(auditBefore).equals(semanticXml(auditAfter)));
    }

    private String semanticXml(Element element) {
        var result = new StringBuilder("{").append(element.getNamespaceURI()).append("}")
                .append(element.getLocalName());
        var attributes = new java.util.TreeMap<String, String>();
        for (var i = 0; i < element.getAttributes().getLength(); i++) {
            var value = element.getAttributes().item(i);
            if ("http://www.w3.org/2000/xmlns/".equals(value.getNamespaceURI())) continue;
            attributes.put("{" + value.getNamespaceURI() + "}" + value.getLocalName(), value.getNodeValue());
        }
        result.append(attributes);
        for (var child = element.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element nested) result.append(semanticXml(nested));
            else if (child.getNodeType() == org.w3c.dom.Node.TEXT_NODE && !child.getTextContent().isBlank())
                result.append(child.getTextContent().strip());
        }
        return result.toString();
    }

    private List<Element> elements(Element root) {
        var result = new ArrayList<Element>();
        for (var child = root.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element) result.add(element);
        return result;
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

    private String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Metadata refresh evidence is incomplete");
    }
}
