package com.samlscope.runner.cases;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Proves a product's native MDQ fetch and subsequent use of the fetched SP metadata. */
public final class MdqAcquisitionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    public static final String ID = "IIP-MD01-a-idp-01";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String NS = "urn:mace:shibboleth:2.0:metadata";
    private static final String XSI = "http://www.w3.org/2001/XMLSchema-instance";
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Path directory;
    private final KeycloakMetadataUrlEvidenceFile keycloakEvidence;

    public MdqAcquisitionConfigurationTestCase(TestCase fallback, TranscriptContentReader content, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        this.content = Objects.requireNonNull(content);
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.keycloakEvidence = new KeycloakMetadataUrlEvidenceFile(content, directory);
        if (!ID.equals(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("MDQ acquisition requires the approved CONFIG fallback");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public String evidenceCampaignId() { return "native-mdq-acquisition"; }
    @Override public String evidenceCampaignTitle() { return "Native MDQ acquisition and correlated SSO"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && exists(context.runId())) {
            return new CaseStep.Finish(observe(context));
        }
        return fallback.resume(context, state, event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result = observe(context);
        var ready = result.outcome() == Outcome.SATISFIED;
        var required = List.of("native-mdq-fetch", "suite-mdq-response", "correlated-sso", "configuration-restored");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), result.details());
    }

    private boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.isRegularFile(directory.resolve(runId + ".mdq/manifest.json"), LinkOption.NOFOLLOW_LINKS);
    }

    private CaseOutcome observe(CaseContext context) {
        if (keycloakReceipt(context.runId())) return keycloakEvidence.evaluateMdq(context);
        try {
            var proof = verify(context);
            return new CaseOutcome(Outcome.SATISFIED, null, "mdq.native-acquisition-observed",
                    "mdq.native-acquisition-observed", proof.refs(),
                    Map.of("native_adapter", proof.adapter(), "restored", true));
        } catch (Exception unproven) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "native_mdq_acquisition_unproven",
                    "mdq.native-evidence-incomplete", "mdq.native-evidence-incomplete",
                    List.of(), Map.of("evidence_issue", unproven.getClass().getSimpleName()));
        }
    }

    private boolean keycloakReceipt(String runId) {
        if (!keycloakEvidence.mdqExists(runId)) return false;
        try {
            var manifest = new JsonCodec().mapper().readTree(original(
                    directory.resolve(runId + ".mdq"), "manifest.json", 262_144));
            return KeycloakMetadataUrlEvidenceFile.MDQ_ADAPTER.equals(value(manifest, "adapter"));
        } catch (Exception invalid) {
            return false;
        }
    }

    private record Proof(String adapter, List<EvidenceRef> refs) {}

    private Proof verify(CaseContext context) throws Exception {
        require(context.transcriptComplete() && exists(context.runId()));
        var folder = directory.resolve(context.runId() + ".mdq").normalize();
        require(folder.getParent().equals(directory) && Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS));
        var manifestRaw = original(folder, "manifest.json", 65536);
        var manifest = new JsonCodec().mapper().readTree(manifestRaw);
        require("samlscope-native-mdq-acquisition-v1".equals(value(manifest, "schema")));
        require(context.runId().equals(value(manifest, "runId")));
        if ("simplesamlphp-native-mdq-v1".equals(value(manifest, "adapter"))) {
            return verifySimpleSaml(context, folder, manifest);
        }
        require("shibboleth-dynamic-http-mdq-v1".equals(value(manifest, "adapter")));
        var entityId = value(manifest, "entityId");
        require(entityId.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}"));
        var initial = original(folder, "original-providers.xml", 1048576);
        var configured = original(folder, "configured-providers.xml", 1048576);
        var finalBytes = original(folder, "final-providers.xml", 1048576);
        var productLog = original(folder, "mdq-product-observation.log", 1048576);
        var mdqRaw = original(folder, "mdq-response.xml", 1048576);
        var mdqRequestRaw = original(folder, "mdq-request.json", 65536);
        require(hash(initial).equals(value(manifest, "originalSha256"))
                && hash(configured).equals(value(manifest, "configuredSha256"))
                && hash(finalBytes).equals(value(manifest, "finalSha256"))
                && hash(productLog).equals(value(manifest, "productLogSha256"))
                && hash(mdqRaw).equals(value(manifest, "mdqResponseSha256"))
                && hash(mdqRequestRaw).equals(value(manifest, "mdqRequestSha256"))
                && Arrays.equals(initial, finalBytes));
        var mdqRequest = new JsonCodec().mapper().readTree(mdqRequestRaw);
        require(entityId.equals(value(mdqRequest, "entity_id"))
                && hash(mdqRaw).equals(value(mdqRequest, "response_sha256"))
                && ("http://localhost:18080/mdq/" + java.net.URLEncoder.encode(entityId,
                        java.nio.charset.StandardCharsets.UTF_8)).equals(value(mdqRequest, "url")));
        var originalXml = SecureXml.parse(initial).getDocumentElement();
        var configuredXml = SecureXml.parse(configured).getDocumentElement();
        require(!new String(initial, java.nio.charset.StandardCharsets.UTF_8).contains(entityId));
        var providerId = "Dynamic" + context.runId();
        var provider = namedProvider(configuredXml, providerId);
        require(provider != null && namedProvider(originalXml, providerId) == null
                && "DynamicHTTPMetadataProvider".equals(provider.getAttributeNS(XSI, "type")));
        var templates = provider.getElementsByTagNameNS(NS, "Template");
        require(templates.getLength() == 1
                && "form".equals(((Element) templates.item(0)).getAttribute("encodingStyle"))
                && ("http://samlscope-reference-suite:8080/mdq/${entityID}?run=" + context.runId())
                        .equals(templates.item(0).getTextContent()));
        var log = new String(productLog, java.nio.charset.StandardCharsets.UTF_8);
        require(log.contains(providerId + ": Successfully loaded new EntityDescriptor with entityID '"
                + entityId + "' from origin source"));
        var mdqDocument = SecureXml.parse(mdqRaw).getDocumentElement();
        require(MD.equals(mdqDocument.getNamespaceURI())
                && "EntityDescriptor".equals(mdqDocument.getLocalName())
                && entityId.equals(mdqDocument.getAttribute("entityID")));
        var acs = mdqDocument.getElementsByTagNameNS(MD, "AssertionConsumerService");
        require(acs.getLength() > 0);

        var entries = new java.util.HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        var request = entry(entries, manifest, "requestTranscriptId");
        var response = entry(entries, manifest, "responseTranscriptId");
        require(request.direction() == Direction.OUTBOUND
                && "AuthnRequest".equals(request.samlSummary().get("type")));
        var requestId = String.valueOf(request.samlSummary().get("id"));
        require(requestId.startsWith("_saml_") && response.direction() == Direction.INBOUND
                && "Response".equals(response.samlSummary().get("type"))
                && Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))
                && SUCCESS.equals(response.samlSummary().get("statusCode"))
                && requestId.equals(response.samlSummary().get("inResponseTo")));
        var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
        require(P.equals(responseXml.getNamespaceURI()) && "Response".equals(responseXml.getLocalName())
                && requestId.equals(responseXml.getAttribute("InResponseTo")));
        var status = responseXml.getElementsByTagNameNS(P, "StatusCode");
        require(status.getLength() == 1 && SUCCESS.equals(((Element) status.item(0)).getAttribute("Value")));
        var responseDestination = responseXml.getAttribute("Destination");
        var advertisedDestination = false;
        for (int i = 0; i < acs.getLength(); i++) {
            if (responseDestination.equals(((Element) acs.item(i)).getAttribute("Location"))) {
                advertisedDestination = true;
            }
        }
        require(advertisedDestination && responseDestination.equals(response.url())
                && response.url().startsWith(entityId + "/sp/acs/")
                && request.timestamp().isBefore(response.timestamp()));
        var refs = new ArrayList<EvidenceRef>();
        for (var entry : List.of(request, response)) {
            refs.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
        }
        refs.add(new EvidenceRef("native-mdq-receipt", context.runId() + ".mdq/manifest.json"));
        require(Arrays.equals(manifestRaw, original(folder, "manifest.json", 65536)));
        return new Proof("shibboleth-dynamic-http-mdq-v1", List.copyOf(refs));
    }

    private Proof verifySimpleSaml(CaseContext context, Path folder, JsonNode manifest) throws Exception {
        var entityId = value(manifest, "entityId");
        require(entityId.matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}"));
        var initial = original(folder, "original-config.php", 1048576);
        var configured = original(folder, "configured-config.php", 1048576);
        var finalBytes = original(folder, "final-config.php", 1048576);
        var router = original(folder, "proxy-router.php", 65536);
        var requests = original(folder, "proxy-requests.jsonl", 1048576);
        var productLog = original(folder, "mdq-product-observation.log", 1048576);
        var mdqRaw = original(folder, "mdq-response.xml", 1048576);
        var mdqRequestRaw = original(folder, "mdq-request.json", 65536);
        require(hash(initial).equals(value(manifest, "originalSha256"))
                && hash(configured).equals(value(manifest, "configuredSha256"))
                && hash(finalBytes).equals(value(manifest, "finalSha256"))
                && hash(router).equals(value(manifest, "proxyRouterSha256"))
                && hash(requests).equals(value(manifest, "proxyRequestsSha256"))
                && hash(productLog).equals(value(manifest, "productLogSha256"))
                && hash(mdqRaw).equals(value(manifest, "mdqResponseSha256"))
                && hash(mdqRequestRaw).equals(value(manifest, "mdqRequestSha256"))
                && Arrays.equals(initial, finalBytes));
        var overlay = "\n$config['metadata.sources'] = [['type'=>'flatfile'], "
                + "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]];\n";
        require(Arrays.equals(configured, concat(initial, overlay.getBytes(java.nio.charset.StandardCharsets.UTF_8))));
        var sourceUrl = "http://samlscope-reference-suite:8080/mdq/"
                + java.net.URLEncoder.encode(entityId, java.nio.charset.StandardCharsets.UTF_8);
        var routerText = new String(router, java.nio.charset.StandardCharsets.UTF_8);
        require(routerText.contains("$expected=" + new JsonCodec().mapper().writeValueAsString(entityId))
                && routerText.contains("$source=" + new JsonCodec().mapper().writeValueAsString(sourceUrl))
                && routerText.contains("rawurldecode(substr($path,strlen($prefix)))!==$expected")
                && routerText.contains("file_get_contents($source)"));
        var mdqRequest = new JsonCodec().mapper().readTree(mdqRequestRaw);
        require(entityId.equals(value(mdqRequest, "entity_id"))
                && ("http://localhost:18080/mdq/" + java.net.URLEncoder.encode(entityId,
                        java.nio.charset.StandardCharsets.UTF_8)).equals(value(mdqRequest, "url"))
                && hash(mdqRaw).equals(value(mdqRequest, "response_sha256")));
        var metadata = SecureXml.parse(mdqRaw).getDocumentElement();
        require(MD.equals(metadata.getNamespaceURI()) && "EntityDescriptor".equals(metadata.getLocalName())
                && entityId.equals(metadata.getAttribute("entityID")));
        var acs = metadata.getElementsByTagNameNS(MD, "AssertionConsumerService");
        require(acs.getLength() > 0);
        var logText = new String(productLog, java.nio.charset.StandardCharsets.UTF_8);
        require(logText.contains("SimpleSAML\\Metadata\\Sources\\MDQ: loading metadata entity [" + entityId + "]")
                && logText.contains("from [saml20-sp-remote]"));
        var entries = new java.util.HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        var request = entry(entries, manifest, "requestTranscriptId");
        var response = entry(entries, manifest, "responseTranscriptId");
        require(request.direction() == Direction.OUTBOUND && "AuthnRequest".equals(request.samlSummary().get("type")));
        var requestId = String.valueOf(request.samlSummary().get("id"));
        require(requestId.startsWith("_saml_") && response.direction() == Direction.INBOUND
                && "Response".equals(response.samlSummary().get("type"))
                && Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))
                && SUCCESS.equals(response.samlSummary().get("statusCode"))
                && requestId.equals(response.samlSummary().get("inResponseTo")));
        var responseXml = SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
        require(P.equals(responseXml.getNamespaceURI()) && "Response".equals(responseXml.getLocalName())
                && requestId.equals(responseXml.getAttribute("InResponseTo")));
        var status = responseXml.getElementsByTagNameNS(P, "StatusCode");
        require(status.getLength() == 1 && SUCCESS.equals(((Element) status.item(0)).getAttribute("Value")));
        var destination = responseXml.getAttribute("Destination");
        var advertised = false;
        for (int i = 0; i < acs.getLength(); i++) {
            if (destination.equals(((Element) acs.item(i)).getAttribute("Location"))) advertised = true;
        }
        require(advertised && destination.equals(response.url()) && request.timestamp().isBefore(response.timestamp()));
        var observedFetch = false;
        for (var line : new String(requests, java.nio.charset.StandardCharsets.UTF_8).split("\\R")) {
            if (line.isBlank()) continue;
            var fetch = new JsonCodec().mapper().readTree(line);
            if (!entityId.equals(value(fetch, "entityId")) || !sourceUrl.equals(value(fetch, "sourceUrl"))
                    || !hash(mdqRaw).equals(value(fetch, "responseSha256"))
                    || fetch.path("httpStatus").asInt() != 200) continue;
            var at = java.time.Instant.parse(value(fetch, "observedAt"));
            if (request.timestamp().isBefore(at) && at.isBefore(response.timestamp())) observedFetch = true;
        }
        require(observedFetch);
        return new Proof("simplesamlphp-native-mdq-v1", List.of(
                new EvidenceRef("transcript", "transcript:" + request.id()),
                new EvidenceRef("transcript", "transcript:" + response.id()),
                new EvidenceRef("native-mdq-receipt", context.runId() + ".mdq/manifest.json")));
    }

    private static byte[] concat(byte[] first, byte[] second) {
        var result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static Element namedProvider(Element root, String id) {
        var matches = root.getElementsByTagNameNS(NS, "MetadataProvider");
        Element result = null;
        for (int i = 0; i < matches.getLength(); i++) {
            var candidate = (Element) matches.item(i);
            if (!id.equals(candidate.getAttribute("id"))) continue;
            if (result != null) throw new IllegalArgumentException("Duplicate native MDQ provider");
            result = candidate;
        }
        return result;
    }

    private static TranscriptEntry entry(Map<String, TranscriptEntry> entries, JsonNode manifest, String field) {
        var value = entries.get(value(manifest, field));
        if (value == null) throw new IllegalArgumentException("Missing Run transcript entry");
        return value;
    }

    private static byte[] original(Path folder, String name, long maxBytes) throws Exception {
        var file = folder.resolve(name);
        require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && Files.size(file) <= maxBytes);
        return Files.readAllBytes(file);
    }

    private static String value(JsonNode object, String name) {
        var node = object.path(name);
        if (!node.isTextual() || node.asText().isBlank()) throw new IllegalArgumentException("Missing MDQ field");
        return node.asText();
    }

    private static String hash(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Native MDQ evidence is incomplete");
    }
}
