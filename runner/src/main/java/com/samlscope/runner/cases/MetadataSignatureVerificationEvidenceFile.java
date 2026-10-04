package com.samlscope.runner.cases;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/**
 * Run-scoped proof that a target verifies metadata document signatures.
 *
 * <p>A consumer that never verifies the document signature accepts any signed fixture through its
 * ordinary parser, so acceptance alone can never establish MD03.b, MD03.c or the transform/KeyInfo
 * rules. This adapter input binds the Run's own recorded originals together, and the Runner checks
 * every referenced original's bytes, not the receipt's strings:
 *
 * <ul>
 *   <li>the Run, the campaign, the pinned target metadata (entityID and SHA-256) and the target
 *       metadata document;
 *   <li>the trusted out-of-band certificate, verified by fingerprinting the certificate bytes the
 *       product read back and requiring it to differ from the fixture's embedded KeyInfo certificate;
 *   <li>the configuration change and its restoration, verified by reading back the configuration
 *       before and after and requiring the restored bytes to equal the original ones;
 *   <li>the positive exchange (a Suite-recorded request and the correlated product response);
 *   <li>each negative control's product-side rejection, verified from the correlated error response.
 * </ul>
 *
 * <p>Every originals is referenced by a {@code tx_} transcript entry, so the Runner reads the actual
 * bytes and their SHA-256 must match the declaration; semantic fields are then checked against the
 * Run. A missing response, an HTTP timeout, an arbitrary Success response, a raw {@code restored}
 * flag or a bare hash string never qualify. It has no HTTP submission route and carries no verdict.
 *
 * <p>The reference SimpleSAMLphp native MDQ adapter records configuration, effective-source, trust
 * anchor, validator-source and native validation originals for the v4 branch. Other adapters must
 * provide their corresponding verified originals; absence of those originals remains NOT_VERIFIED.
 */
final class MetadataSignatureVerificationEvidenceFile {
    private static final Set<String> ADAPTERS = Set.of(
            "shibboleth-signature-validation", "simplesamlphp-runtime",
            "keycloak-trust-anchor", "suite-native");
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final Set<String> REJECTION_STATUSES = Set.of(
            "urn:oasis:names:tc:SAML:2.0:status:Requester",
            "urn:oasis:names:tc:SAML:2.0:status:Responder");
    private static final Set<String> REQUIRED_CONTROLS = Set.of("invalid-signature", "embedded-anchor");
    private static final String SCHEMA_V3 = "samlscope-metadata-signature-verification-receipt-v3";
    private static final String SCHEMA_V4 = "samlscope-metadata-signature-verification-receipt-v4";
    private static final String NATIVE_SCHEMA =
            "samlscope-simplesamlphp-metadata-signature-validation-v1";
    private static final String NATIVE_ARTIFACT = "metadata-signature-native-validation";
    private static final String CONFIGURATION_ARTIFACT = "metadata-signature-trust-configuration";
    private static final String RESTORED_ARTIFACT = "metadata-signature-configuration-restored";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";

    private final Path directory;

    MetadataSignatureVerificationEvidenceFile(Path directory) {
        this.directory = directory.toAbsolutePath().normalize();
    }

    /** Shares the Run's rejection-evidence directory but never the rejection receipt file. */
    private static Path receiptPath(Path directory, String runId) {
        return directory.resolve(runId + ".signature-verification.json");
    }

    boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(receiptPath(directory, runId), LinkOption.NOFOLLOW_LINKS);
    }

    record Proof(String adapter, String anchorCertificateSha256, String embeddedKeyInfoSha256) {}

    private record Artifact(TranscriptEntry entry, JsonNode json) {}

    private record ConfigurationProof(
            TranscriptEntry entry, Set<String> anchors, String contentSha256,
            String certificateLocation, TranscriptEntry effectiveEntry, Instant latestTimestamp) {}

    /**
     * Verifies the Run-scoped signature-verification receipt. Every failure is reported as an
     * unproven precondition, never as a target violation.
     */
    Proof verify(CaseContext context, byte[] target, TranscriptContentReader content, String campaignId)
            throws Exception {
        require(context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        var path = receiptPath(directory, context.runId());
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 1_048_576);
        require(context.transcriptComplete());
        require(campaignId != null && !campaignId.isBlank());
        var receipt = new JsonCodec().mapper().readTree(Files.readAllBytes(path));
        var schema = text(receipt, "schema");
        require((SCHEMA_V3.equals(schema) || SCHEMA_V4.equals(schema))
                && context.runId().equals(text(receipt, "runId")));
        require(campaignId.equals(text(receipt, "campaignId")));
        require(hash(target).equals(text(receipt, "targetMetadataSha256")));
        var targetEntityId = text(receipt, "targetEntityId");
        require(!targetEntityId.isBlank() && entityIds(target).contains(targetEntityId));
        var adapter = text(receipt, "evidenceAdapter");
        require(ADAPTERS.contains(adapter));

        var entries = new HashMap<String, TranscriptEntry>();
        var preparedByVariant = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
            if (entry.direction() == Direction.OUTBOUND
                    && "MetadataPrepared".equals(entry.samlSummary().get("type"))
                    && entry.samlSummary().get("variant") instanceof String variant) {
                preparedByVariant.put(variant, entry);
            }
        }

        var configuration = SCHEMA_V4.equals(schema)
                ? configurationOriginal(entries, receipt.path("configurationReadBack"), content)
                : configurationProof(configurationArtifact(entries, receipt.path("configurationReadBack"),
                        context.runId(), targetEntityId, content), content);
        var anchors = configuration.anchors();
        var anchor = requiredHex(receipt.path("configurationReadBack"), "trustAnchorCertificateSha256");
        require(anchors.contains(anchor));

        var nativeSources = SCHEMA_V4.equals(schema)
                ? verifyNativeSources(receipt.path("nativeSources"), entries, content) : null;
        var positive = verifyPositive(receipt.path("positive"), entries, preparedByVariant, content,
                configuration, context.runId(), campaignId, targetEntityId, nativeSources);
        require(!anchors.contains(positive.embedded()));

        var restoredOriginal = SCHEMA_V4.equals(schema)
                ? original(entries, receipt.path("restorationReadBack"), "originalReference",
                        "originalSha256", content)
                : restorationArtifact(entries, receipt.path("restorationReadBack"),
                        "originalReference", "originalSha256", context.runId(), targetEntityId, content).entry();
        var restoredFinal = SCHEMA_V4.equals(schema)
                ? original(entries, receipt.path("restorationReadBack"), "finalReference",
                        "finalSha256", content)
                : restorationArtifact(entries, receipt.path("restorationReadBack"),
                        "finalReference", "finalSha256", context.runId(), targetEntityId, content).entry();
        require(java.util.Arrays.equals(content.readDecodedSaml(restoredOriginal),
                content.readDecodedSaml(restoredFinal)));
        require(!java.util.Arrays.equals(content.readDecodedSaml(restoredOriginal),
                content.readDecodedSaml(configuration.entry())));
        require(!restoredOriginal.timestamp().isAfter(configuration.entry().timestamp()));

        var lastNegative = verifyNegativeControls(receipt.path("negativeControls"), entries, preparedByVariant, content,
                context.runId(), campaignId, targetEntityId, configuration, anchor, positive, nativeSources);

        var lastTested = latest(positive.response().timestamp(), lastNegative);
        require(!restoredFinal.timestamp().isBefore(lastTested));
        return new Proof(adapter, anchor, positive.embedded());
    }

    /**
     * Reuses the complete v4 trust proof for additional native signature refusals. Each refusal
     * still carries its own effective configuration and validator original; a successful gate alone
     * does not prove that another fixture was rejected.
     */
    Map<String, String> rejectedNativeVariants(CaseContext context, byte[] target,
            TranscriptContentReader content, JsonNode rejections) throws Exception {
        var campaign = "metadata-fixture-refresh";
        verify(context, target, content, campaign);
        var receipt = new JsonCodec().mapper().readTree(Files.readAllBytes(
                receiptPath(directory, context.runId())));
        require(SCHEMA_V4.equals(text(receipt, "schema"))
                && "simplesamlphp-runtime".equals(text(receipt, "evidenceAdapter")));
        var entries = new HashMap<String, TranscriptEntry>();
        var prepared = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
            if (entry.direction() == Direction.OUTBOUND
                    && "MetadataPrepared".equals(entry.samlSummary().get("type"))
                    && entry.samlSummary().get("variant") instanceof String variant) {
                prepared.put(variant, entry);
            }
        }
        var sources = verifyNativeSources(receipt.path("nativeSources"), entries, content);
        var restored = original(entries, receipt.path("restorationReadBack"),
                "finalReference", "finalSha256", content);
        require(rejections.isArray() && !rejections.isEmpty());
        var result = new java.util.LinkedHashMap<String, String>();
        for (var rejection : rejections) {
            var variant = text(rejection, "variant");
            require(Set.of("unsigned", "bad-signature", "signed-other-key", "xpath-identity",
                    "xpath-exclude-role-descriptors", "xpath-exclude-endpoints",
                    "xpath-exclude-key-descriptors").contains(variant));
            var fixture = requireOriginalFixture(prepared, variant, content);
            var nativeRecord = rejection.path("nativeRejection");
            require("simplesamlphp-native-mdq-signature".equals(text(nativeRecord, "source")));
            var configuration = configurationOriginal(entries,
                    nativeRecord.path("configurationReadBack"), content);
            var raw = content.readDecodedSaml(fixture);
            require(hash(raw).equals(requiredHex(rejection, "fixtureSha256")));
            if ("unsigned".equals(variant)) {
                require(SecureXml.parse(raw).getElementsByTagNameNS(DS, "Signature").getLength() == 0);
            } else if ("bad-signature".equals(variant)) {
                require(configuration.anchors().contains(embeddedKeyInfoCertificateSha256(raw)));
            } else if ("signed-other-key".equals(variant)) {
                require(!configuration.anchors().contains(embeddedKeyInfoCertificateSha256(raw)));
            }
            var validation = verifyNativeValidation(nativeRecord,
                    "reference", "detailSha256", entries, fixture, content, configuration, sources,
                    context.runId(), campaign, text(receipt, "targetEntityId"), variant, false);
            require(!restored.timestamp().isBefore(validation.timestamp()));
            // The refusal cannot coexist with a successful use of this same campaign variant.
            var requestIds = entries.values().stream().filter(entry -> entry.direction() == Direction.OUTBOUND
                    && "AuthnRequest".equals(entry.samlSummary().get("type"))
                    && variant.equals(String.valueOf(entry.samlSummary().get("variant"))))
                    .map(entry -> String.valueOf(entry.samlSummary().get("id")))
                    .collect(java.util.stream.Collectors.toSet());
            require(entries.values().stream().noneMatch(entry -> entry.direction() == Direction.INBOUND
                    && "Response".equals(entry.samlSummary().get("type"))
                    && SUCCESS.equals(entry.samlSummary().get("statusCode"))
                    && requestIds.contains(String.valueOf(entry.samlSummary().get("inResponseTo")))));
            require(result.put(variant, "simplesamlphp-native-mdq-signature") == null);
        }
        return Map.copyOf(result);
    }

    private record Positive(
            TranscriptEntry prepared, TranscriptEntry request, TranscriptEntry response, String embedded) {}

    private record NativeSources(
            TranscriptEntry parser, TranscriptEntry mdq, TranscriptEntry metaloader,
            TranscriptEntry configuration, TranscriptEntry adapter, String productVersion) {}

    /** Only the fixture's embedded KeyInfo certificate is trusted here; the out-of-band anchor is absent. */
    private static ConfigurationProof verifyEmbeddedAnchorConfiguration(Map<String, TranscriptEntry> entries, JsonNode ref,
            String runId, String targetEntityId, TranscriptContentReader content, Set<String> outOfBand,
            String embedded, TranscriptEntry controlRequest) throws Exception {
        var configuration = configurationProof(
                configurationArtifact(entries, ref, runId, targetEntityId, content), content);
        var anchors = configuration.anchors();
        require(anchors.contains(embedded) && java.util.Collections.disjoint(anchors, outOfBand));
        require(!configuration.entry().timestamp().isAfter(controlRequest.timestamp()));
        return configuration;
    }

    private static Instant verifyNegativeControls(JsonNode controls, Map<String, TranscriptEntry> entries,
            Map<String, TranscriptEntry> preparedByVariant, TranscriptContentReader content, String runId,
            String campaignId, String targetEntityId, ConfigurationProof configuration, String anchor,
            Positive positive, NativeSources nativeSources) throws Exception {
        require(controls.isArray() && controls.size() == REQUIRED_CONTROLS.size());
        var kinds = new HashSet<String>();
        Instant lastEvidence = Instant.MIN;
        for (var control : controls) {
            require(control.isObject());
            var kind = text(control, "kind");
            require(REQUIRED_CONTROLS.contains(kind) && kinds.add(kind));
            var variant = text(control, "variant");
            require(!variant.isBlank());
            var prepared = requireOriginalFixture(preparedByVariant, variant, content);
            if (nativeSources != null && control.has("nativeRejectionReference")) {
                ConfigurationProof controlConfiguration;
                if (control.has("configurationReadBack")) {
                    controlConfiguration = configurationOriginal(
                            entries, control.path("configurationReadBack"), content);
                } else {
                    controlConfiguration = configuration;
                }
                var controlAnchors = controlConfiguration.anchors();
                if ("invalid-signature".equals(kind)) {
                    require("bad-signature".equals(variant));
                    require(controlAnchors.contains(embeddedKeyInfoCertificateSha256(
                            content.readDecodedSaml(prepared))));
                } else {
                    require(variant.equals(String.valueOf(
                            positive.prepared().samlSummary().get("variant"))));
                    require(controlAnchors.contains(positive.embedded())
                            && java.util.Collections.disjoint(controlAnchors,
                                    configuration.anchors()));
                }
                var validation = verifyNativeValidation(control, "nativeRejectionReference", "nativeRejectionSha256",
                        entries, prepared, content, controlConfiguration, nativeSources, runId, campaignId,
                        targetEntityId, variant, false);
                lastEvidence = latest(lastEvidence, controlConfiguration.latestTimestamp(), validation.timestamp());
                continue;
            }
            var requestId = text(control, "requestId");
            require(!requestId.isBlank());
            var request = entries.get(reference(control, "requestReference"));
            require(request != null && request.direction() == Direction.OUTBOUND
                    && requestId.equals(request.samlSummary().get("id"))
                    && variant.equals(request.samlSummary().get("variant"))
                    && "AuthnRequest".equals(request.samlSummary().get("type")));
            require(!configuration.entry().timestamp().isAfter(request.timestamp()));
            if ("invalid-signature".equals(kind)) {
                require("invalid".equals(request.samlSummary().get("metadataSignatureControl")));
            } else {
                require(!"invalid".equals(request.samlSummary().get("metadataSignatureControl")));
                var controlConfiguration = verifyEmbeddedAnchorConfiguration(entries,
                        control.path("configurationReadBack"), runId, targetEntityId, content,
                        configuration.anchors(), positive.embedded(), request);
                lastEvidence = latest(lastEvidence, controlConfiguration.latestTimestamp());
            }
            // Refusal is the product's own correlated error response, never silence, an HTTP error or
            // an arbitrary Success. The response bytes must carry the top-level error status.
            var rejection = entries.get(reference(control, "rejectionReference"));
            require(rejection != null && rejection.direction() == Direction.INBOUND
                    && requestId.equals(rejection.samlSummary().get("inResponseTo"))
                    && rejection.timestamp() != null && !rejection.timestamp().isBefore(request.timestamp())
                    && "Response".equals(rejection.samlSummary().get("type")));
            var response = SecureXml.parse(content.readDecodedSaml(rejection)).getDocumentElement();
            require(P.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName()));
            require(REJECTION_STATUSES.contains(topLevelStatus(response))
                    && REJECTION_STATUSES.contains(String.valueOf(rejection.samlSummary().get("statusCode"))));
            // Consistency: a successful correlated response would contradict the rejection record.
            require(entries.values().stream().noneMatch(entry ->
                    entry.direction() == Direction.INBOUND && SUCCESS.equals(entry.samlSummary().get("statusCode"))
                            && requestId.equals(String.valueOf(entry.samlSummary().get("inResponseTo")))));
            lastEvidence = latest(lastEvidence, rejection.timestamp());
        }
        require(kinds.equals(REQUIRED_CONTROLS));
        return lastEvidence;
    }

    private static Positive verifyPositive(JsonNode positive, Map<String, TranscriptEntry> entries,
            Map<String, TranscriptEntry> preparedByVariant, TranscriptContentReader content,
            ConfigurationProof configuration, String runId, String campaignId, String targetEntityId,
            NativeSources nativeSources) throws Exception {
        require(positive.isObject());
        var variant = text(positive, "variant");
        var requestId = text(positive, "requestId");
        require(!variant.isBlank() && !requestId.isBlank());
        var prepared = requireOriginalFixture(preparedByVariant, variant, content);
        var embedded = embeddedKeyInfoCertificateSha256(content.readDecodedSaml(prepared));
        require(embedded.equals(requiredHex(positive, "embeddedKeyInfoCertificateSha256")));
        require(requestId.equals(text(positive, "inResponseTo")));
        var request = entries.get(reference(positive, "requestReference"));
        require(request != null && request.direction() == Direction.OUTBOUND
                && requestId.equals(request.samlSummary().get("id"))
                && variant.equals(request.samlSummary().get("variant"))
                && "AuthnRequest".equals(request.samlSummary().get("type")));
        require(!configuration.entry().timestamp().isAfter(request.timestamp()));
        var response = entries.get(reference(positive, "responseReference"));
        require(response != null && response.direction() == Direction.INBOUND
                && requestId.equals(response.samlSummary().get("inResponseTo"))
                && SUCCESS.equals(response.samlSummary().get("statusCode"))
                && "Response".equals(response.samlSummary().get("type"))
                && !response.timestamp().isBefore(request.timestamp()));
        var bytes = content.readDecodedSaml(response);
        require(hash(bytes).equals(requiredHex(positive, "responseSha256")));
        var responseXml = SecureXml.parse(bytes).getDocumentElement();
        require(P.equals(responseXml.getNamespaceURI()) && "Response".equals(responseXml.getLocalName())
                && SUCCESS.equals(topLevelStatus(responseXml)));
        if (nativeSources != null) {
            verifyNativeValidation(positive, "nativeValidationReference", "nativeValidationSha256",
                    entries, prepared, content, configuration, nativeSources, runId, campaignId,
                    targetEntityId, variant, true);
        }
        return new Positive(prepared, request, response, embedded);
    }

    /**
     * Pins the exact SimpleSAMLphp implementation used by the native alternative.  The reference
     * adapter posts these product-owned source originals through Recorder before invoking the
     * validator; hashes or class names in a receipt are not sufficient by themselves.
     */
    private static NativeSources verifyNativeSources(JsonNode node, Map<String, TranscriptEntry> entries,
            TranscriptContentReader content) throws Exception {
        require(node.isObject());
        var parser = sourceOriginal(node.path("samlParser"), entries, content,
                "public function validateSignature(array $certificates): bool",
                "retrieveCertificate", "->validate($key)", "Could not validate signature");
        var mdq = sourceOriginal(node.path("mdq"), entries, content,
                "private ?array $validateCertificate", "validateSignature($this->validateCertificate)",
                "could not verify signature for entity");
        var metaloader = sourceOriginal(node.path("metaLoader"), entries, content,
                "private function processCertificates", "array_key_exists('certificates', $source)",
                "validateSignature($source['certificates'])");
        var configuration = sourceOriginal(node.path("configuration"), entries, content,
                "VERSION", "class Configuration");
        var adapter = sourceOriginal(node.path("adapter"), entries, content,
                "MetaDataStorageSource::getSource", "validateCertificate", "postOriginal",
                "metadata-signature-native-validation");
        var source = new String(content.readDecodedSaml(configuration), StandardCharsets.UTF_8);
        var match = java.util.regex.Pattern.compile(
                "public\\s+const(?:\\s+string)?\\s+VERSION\\s*=\\s*['\\\"]([^'\\\"]+)['\\\"]\\s*;")
                .matcher(source);
        require(match.find() && !match.group(1).isBlank());
        return new NativeSources(parser, mdq, metaloader, configuration, adapter, match.group(1));
    }

    private static TranscriptEntry sourceOriginal(JsonNode node, Map<String, TranscriptEntry> entries,
            TranscriptContentReader content, String... requiredText) throws Exception {
        var entry = entries.get(reference(node, "reference"));
        require(entry != null && entry.direction() == Direction.INBOUND
                && "POST".equals(entry.method()) && Integer.valueOf(204).equals(entry.status()));
        var raw = content.readDecodedSaml(entry);
        require(hash(raw).equals(requiredHex(node, "sha256")));
        var source = new String(raw, StandardCharsets.UTF_8);
        for (var required : requiredText) require(source.contains(required));
        return entry;
    }

    /** Strict native one-of branch for products that correctly refuse before a SAML Response exists. */
    private static TranscriptEntry verifyNativeValidation(JsonNode receiptNode, String referenceField, String hashField,
            Map<String, TranscriptEntry> entries, TranscriptEntry prepared, TranscriptContentReader content,
            ConfigurationProof configuration, NativeSources sources, String runId, String campaignId,
            String targetEntityId, String variant, boolean accepted) throws Exception {
        var entry = entries.get(reference(receiptNode, referenceField));
        require(entry != null && entry.direction() == Direction.INBOUND
                && "POST".equals(entry.method()) && Integer.valueOf(204).equals(entry.status())
                && entry.url() != null && entry.url().contains("/p/plan_")
                && entry.url().contains("/sp/paos?run=" + runId)
                && !entry.timestamp().isBefore(prepared.timestamp())
                && !entry.timestamp().isBefore(configuration.entry().timestamp()));
        for (var source : java.util.List.of(
                sources.parser(), sources.mdq(), sources.metaloader(), sources.configuration(), sources.adapter())) {
            require(!entry.timestamp().isBefore(source.timestamp()));
        }
        var raw = content.readDecodedSaml(entry);
        require(hash(raw).equals(requiredHex(receiptNode, hashField)));
        var record = new JsonCodec().mapper().readTree(raw);
        require(NATIVE_SCHEMA.equals(text(record, "schema"))
                && NATIVE_ARTIFACT.equals(text(record, "artifact"))
                && runId.equals(text(record, "runId"))
                && campaignId.equals(text(record, "campaignId"))
                && targetEntityId.equals(text(record, "targetEntityId"))
                && variant.equals(text(record, "variant"))
                && "simplesamlphp".equals(text(record, "product"))
                && sources.productVersion().equals(text(record, "productVersion"))
                && hash(content.readDecodedSaml(prepared)).equals(text(record, "fixtureSha256"))
                && "SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData".equals(text(record, "entryPoint"))
                && "SimpleSAML\\Metadata\\SAMLParser::validateSignature".equals(text(record, "verifier"))
                && configuration.entry().id().equals(text(record, "configurationReference"))
                && configuration.effectiveEntry().id().equals(text(record, "effectiveConfigurationReference"))
                && configuration.contentSha256().equals(text(record, "configurationSha256"))
                && configuration.certificateLocation().equals(text(record, "certificateLocation"))
                && !record.path("genericParserOnly").asBoolean(true)
                && record.path("validationCallCount").asInt(-1) == 1);
        var expectedPath = java.util.List.of(
                "SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData",
                "SimpleSAML\\Metadata\\SAMLParser::parseString",
                "SimpleSAML\\Metadata\\SAMLParser::validateSignature");
        require(record.path("callPath").isArray()
                && new JsonCodec().mapper().convertValue(record.path("callPath"),
                        new com.fasterxml.jackson.core.type.TypeReference<java.util.List<String>>() {})
                        .equals(expectedPath));
        var anchors = configuration.anchors();
        require(anchors.size() == 1
                && anchors.contains(requiredHex(record, "trustAnchorCertificateSha256")));
        var fixtureEntities = entityIds(content.readDecodedSaml(prepared));
        require(fixtureEntities.size() == 1
                && fixtureEntities.contains(text(record, "metadataEntityId")));
        require(record.path("parserAccepted").asBoolean(false));
        if (accepted) {
            require("accepted".equals(text(record, "outcome"))
                    && record.path("signatureVerified").asBoolean(false) == true
                    && record.path("exception").isNull());
        } else {
            require("rejected".equals(text(record, "outcome"))
                    && !record.path("signatureVerified").asBoolean(true)
                    && record.path("exception").isObject()
                    && "Exception".equals(text(record.path("exception"), "class")));
            var message = text(record.path("exception"), "message");
            require(message.startsWith("SimpleSAML\\Metadata\\Sources\\MDQ: error, could not verify signature for entity: ")
                    && message.contains(text(record, "metadataEntityId")));
        }
        var sourceHashes = record.path("sourceSha256");
        require(sourceHashes.isObject()
                && hash(content.readDecodedSaml(sources.parser())).equals(text(sourceHashes, "samlParser"))
                && hash(content.readDecodedSaml(sources.mdq())).equals(text(sourceHashes, "mdq"))
                && hash(content.readDecodedSaml(sources.metaloader())).equals(text(sourceHashes, "metaLoader"))
                && hash(content.readDecodedSaml(sources.configuration())).equals(text(sourceHashes, "configuration"))
                && hash(content.readDecodedSaml(sources.adapter())).equals(text(sourceHashes, "adapter")));
        return entry;
    }

    private static ConfigurationProof configurationProof(
            Artifact artifact, TranscriptContentReader content) throws Exception {
        return new ConfigurationProof(
                artifact.entry(), trustAnchors(artifact.json()), hash(content.readDecodedSaml(artifact.entry())),
                "legacy-json", artifact.entry(), artifact.entry().timestamp());
    }

    /**
     * v4 reads the product's actual PHP configuration, effective Configuration read-back, and PEM
     * trust anchor from Recorder originals.  No enabled boolean or naked digest can substitute for
     * these bytes.
     */
    private static ConfigurationProof configurationOriginal(Map<String, TranscriptEntry> entries, JsonNode ref,
            TranscriptContentReader content) throws Exception {
        var configured = original(entries, ref, "reference", "sha256", content);
        var effective = original(entries, ref, "effectiveReference", "effectiveSha256", content);
        var certificate = original(entries, ref, "trustAnchorReference", "trustAnchorOriginalSha256", content);
        var configuredRaw = content.readDecodedSaml(configured);
        var effectiveJson = new JsonCodec().mapper().readTree(content.readDecodedSaml(effective));
        var location = text(ref, "certificateLocation");
        require(location.matches("[A-Za-z0-9._-]{1,128}")
                && new String(configuredRaw, StandardCharsets.UTF_8).contains("validateCertificate")
                && new String(configuredRaw, StandardCharsets.UTF_8).contains(location));
        require(effectiveJson.isArray());
        var matching = 0;
        for (var source : effectiveJson) {
            if (!"mdq".equals(text(source, "type"))) continue;
            require("http://127.0.0.1:8081".equals(text(source, "server"))
                    && source.path("cachelength").asInt(-1) == 0
                    && source.path("validateCertificate").isArray()
                    && source.path("validateCertificate").size() == 1
                    && location.equals(source.path("validateCertificate").get(0).asText()));
            matching++;
        }
        require(matching == 1);
        var certificateRaw = content.readDecodedSaml(certificate);
        var parsed = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificateRaw));
        var fingerprint = hash(parsed.getEncoded());
        require(fingerprint.equals(requiredHex(ref, "trustAnchorCertificateSha256")));
        require(!configured.timestamp().isAfter(effective.timestamp())
                && !effective.timestamp().isAfter(certificate.timestamp()));
        return new ConfigurationProof(configured, Set.of(fingerprint), hash(configuredRaw), location, effective,
                latest(configured.timestamp(), effective.timestamp(), certificate.timestamp()));
    }

    private static Instant latest(Instant first, Instant... rest) {
        var result = first;
        for (var value : rest) if (value != null && value.isAfter(result)) result = value;
        return result;
    }

    private static TranscriptEntry original(Map<String, TranscriptEntry> entries, JsonNode node,
            String referenceField, String hashField, TranscriptContentReader content) throws Exception {
        var entry = entries.get(reference(node, referenceField));
        require(entry != null && entry.direction() == Direction.INBOUND
                && "POST".equals(entry.method()) && Integer.valueOf(204).equals(entry.status()));
        require(hash(content.readDecodedSaml(entry)).equals(requiredHex(node, hashField)));
        return entry;
    }

    private static Artifact configurationArtifact(Map<String, TranscriptEntry> entries, JsonNode ref,
            String runId, String targetEntityId, TranscriptContentReader content) throws Exception {
        var artifact = readArtifact(entries, ref, "reference", "sha256", CONFIGURATION_ARTIFACT, runId,
                targetEntityId, content);
        require("enabled".equals(text(artifact.json(), "signatureVerification")));
        return artifact;
    }

    private static Artifact restorationArtifact(Map<String, TranscriptEntry> entries, JsonNode ref,
            String referenceField, String hashField, String runId, String targetEntityId,
            TranscriptContentReader content) throws Exception {
        var artifact = readArtifact(entries, ref, referenceField, hashField, RESTORED_ARTIFACT, runId,
                targetEntityId, content);
        require(artifact.json().path("restored").asBoolean(false) && trustAnchors(artifact.json()).isEmpty());
        return artifact;
    }

    private static Artifact readArtifact(Map<String, TranscriptEntry> entries, JsonNode node,
            String referenceField, String hashField, String expectedArtifact, String runId,
            String targetEntityId, TranscriptContentReader content) throws Exception {
        var entry = entries.get(reference(node, referenceField));
        require(entry != null);
        var bytes = content.readDecodedSaml(entry);
        require(hash(bytes).equals(requiredHex(node, hashField)));
        var json = new JsonCodec().mapper().readTree(bytes);
        require(expectedArtifact.equals(text(json, "artifact"))
                && runId.equals(text(json, "runId"))
                && targetEntityId.equals(text(json, "targetEntityId")));
        return new Artifact(entry, json);
    }

    private static Set<String> trustAnchors(JsonNode json) throws Exception {
        var certificates = json.path("trustAnchorCertificates");
        require(certificates.isArray());
        var fingerprints = new HashSet<String>();
        for (var certificate : certificates) {
            require(certificate.isTextual() && !certificate.asText().isBlank());
            fingerprints.add(hash(Base64.getDecoder().decode(certificate.asText().replaceAll("\\s", ""))));
        }
        return fingerprints;
    }

    private static Set<String> entityIds(byte[] target) {
        var ids = new HashSet<String>();
        var entities = SecureXml.parse(target).getElementsByTagNameNS(MD, "EntityDescriptor");
        for (var index = 0; index < entities.getLength(); index++) {
            var id = ((Element) entities.item(index)).getAttribute("entityID");
            if (!id.isBlank()) ids.add(id);
        }
        return ids;
    }

    private static String topLevelStatus(Element response) {
        for (var child = response.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element status) || !P.equals(status.getNamespaceURI())
                    || !"Status".equals(status.getLocalName())) continue;
            for (var inner = status.getFirstChild(); inner != null; inner = inner.getNextSibling()) {
                if (inner instanceof Element code && P.equals(code.getNamespaceURI())
                        && "StatusCode".equals(code.getLocalName())) {
                    return code.getAttribute("Value");
                }
            }
        }
        return "";
    }

    /**
     * The certificate in the original metadata document's own Signature/KeyInfo, rather than
     * a role's published key or a separately signed child EntityDescriptor. Ambiguous signature
     * or certificate scopes cannot establish the embedded-key control.
     */
    static String embeddedKeyInfoCertificateSha256(byte[] fixture) throws Exception {
        var root = SecureXml.parse(fixture).getDocumentElement();
        require(MD.equals(root.getNamespaceURI())
                && ("EntityDescriptor".equals(root.getLocalName())
                        || "EntitiesDescriptor".equals(root.getLocalName())));
        var signature = singleDirectChild(root, DS, "Signature");
        var keyInfo = singleDirectChild(signature, DS, "KeyInfo");
        var x509Data = singleDirectChild(keyInfo, DS, "X509Data");
        var certificate = singleDirectChild(x509Data, DS, "X509Certificate");
        var encoded = certificate.getTextContent();
        require(encoded != null && !encoded.isBlank());
        var der = Base64.getDecoder().decode(encoded.replaceAll("\\s", ""));
        require(der.length > 0);
        return hash(der);
    }

    private static Element singleDirectChild(Element parent, String namespace, String name) {
        Element selected = null;
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (!(child instanceof Element element) || !namespace.equals(element.getNamespaceURI())
                    || !name.equals(element.getLocalName())) continue;
            require(selected == null);
            selected = element;
        }
        require(selected != null);
        return selected;
    }

    private static TranscriptEntry requireOriginalFixture(Map<String, TranscriptEntry> preparedByVariant,
            String variant, TranscriptContentReader content) {
        var prepared = preparedByVariant.get(variant);
        require(prepared != null);
        return prepared;
    }

    private static String requiredHex(JsonNode node, String field) {
        var value = text(node, field);
        require(value.matches("[0-9a-f]{64}"));
        return value;
    }

    private static String reference(JsonNode node, String field) {
        var value = text(node, field);
        require(value.matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));
        return value;
    }

    private static String text(JsonNode node, String field) {
        return node.path(field).asText("");
    }

    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Metadata signature verification unproven");
    }
}
