package com.samlscope.runner.cases;

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
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Reads a Run-scoped Shibboleth RSA-1.5 prevention A/B/A campaign. */
final class AlgorithmPreventionEvidenceFile {
    static final String CASE_A = "IIP-ALG08-a-idp-01";
    static final String CASE_B = "IIP-ALG08-b-idp-01";
    static final String OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    static final String RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
    static final String TRIPLEDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
    static final String AES128 = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    private static final String SCHEMA = "samlscope-shibboleth-algorithm-prevention-v2";
    private static final String IMAGE = "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a";
    private static final String VERSION = "5.2.3";
    private static final String CONTAINER = "samlscope-reference-shibboleth";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String X = "http://www.w3.org/2001/04/xmlenc#";
    private static final String SOAP = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final int RECEIPT_LIMIT = 2_097_152;
    private static final String CONFIG_ID = "samlscope.AlgorithmPreventionEncryptionConfiguration";
    private static final String SECURITY_CONFIG_ID = "samlscope.AlgorithmPreventionSecurityConfiguration";
    private static final String GLOBAL_MARKER = "<!-- samlscope-algorithm-prevention-set -->";
    private static final String RELYING_MARKER = "<!-- samlscope-algorithm-prevention-policy -->";
    private static final List<String> PHASES = List.of("allowed-before", "blocked", "allowed-after");

    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    private final Function<String, String> profiles;
    private final ReferenceIdentity reference;

    AlgorithmPreventionEvidenceFile(Path directory, TranscriptContentReader content,
            Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys,
            Function<String, String> profiles) {
        this(directory, content, metadata, keys, profiles,
                new ReferenceIdentity(IMAGE, VERSION, CONTAINER));
    }

    AlgorithmPreventionEvidenceFile(Path directory, TranscriptContentReader content,
            Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys,
            Function<String, String> profiles, ReferenceIdentity reference) {
        this.directory = directory.toAbsolutePath().normalize();
        this.content = java.util.Objects.requireNonNull(content);
        this.metadata = java.util.Objects.requireNonNull(metadata);
        this.keys = java.util.Objects.requireNonNull(keys);
        this.profiles = java.util.Objects.requireNonNull(profiles);
        this.reference = java.util.Objects.requireNonNull(reference);
    }

    boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(runId + ".json"), LinkOption.NOFOLLOW_LINKS);
    }

    String receiptSha256(String runId) throws Exception {
        require(exists(runId));
        var file = directory.resolve(runId + ".json");
        require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                && Files.size(file) > 0 && Files.size(file) <= RECEIPT_LIMIT);
        return hash(Files.readAllBytes(file));
    }

    Optional<Proof> read(CaseContext context) {
        if (!exists(context.runId()) || !context.transcriptComplete()) return Optional.empty();
        try {
            var file = directory.resolve(context.runId() + ".json");
            require(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)
                    && Files.size(file) > 0 && Files.size(file) <= RECEIPT_LIMIT);
            var before = Files.readAllBytes(file);
            var receipt = new JsonCodec().mapper().readTree(before);
            if (KeycloakAlgorithmPreventionEvidenceFile.SCHEMA.equals(receipt.path("schema").asText())) {
                var proof = new KeycloakAlgorithmPreventionEvidenceFile(content, metadata, keys, profiles)
                        .read(context, receipt, hash(before));
                require(Arrays.equals(before, Files.readAllBytes(file)));
                return proof;
            }
            requireFields(receipt, Set.of("schema", "runId", "profile", "targetEntityId",
                    "targetMetadataSha256", "suiteMetadata", "configuration", "runtime",
                    "phases", "operationCounts"));
            require(SCHEMA.equals(text(receipt, "schema")));
            require(context.runId().equals(text(receipt, "runId")));
            var expectedProfile = profiles.apply(context.runId());
            require(Set.of("browser_sso_idp", "ecp_idp").contains(expectedProfile));
            require(expectedProfile.equals(text(receipt, "profile")));

            var targetRaw = metadata.apply(context.runId());
            require(targetRaw != null && targetRaw.length > 0);
            require(hash(targetRaw).equals(text(receipt, "targetMetadataSha256")));
            var target = SecureXml.parse(targetRaw).getDocumentElement();
            require(MD.equals(target.getNamespaceURI()) && "EntityDescriptor".equals(target.getLocalName()));
            var targetEntity = target.getAttribute("entityID");
            require(!targetEntity.isBlank() && targetEntity.equals(text(receipt, "targetEntityId")));
            var signingKeys = MetadataAlgorithmEvidence.signingKeys(target);
            require(!signingKeys.isEmpty());

            var suiteRaw = blob(receipt.path("suiteMetadata"), 524_288);
            var suite = SecureXml.parse(suiteRaw).getDocumentElement();
            require(MD.equals(suite.getNamespaceURI()) && "EntityDescriptor".equals(suite.getLocalName()));
            var suiteEntity = suite.getAttribute("entityID");
            require(!suiteEntity.isBlank());
            require(children(suite, MD, "SPSSODescriptor").size() == 1);

            verifyConfiguration(receipt.path("configuration"), context.runId(), suiteRaw);
            requireFields(receipt.path("runtime"), Set.of("initial", "restored"));
            var initial = runtime(receipt.path("runtime").path("initial"));
            var restored = runtime(receipt.path("runtime").path("restored"));
            require(initial.containerId().equals(restored.containerId()));
            require(!restored.startedAt().isBefore(initial.startedAt()));

            var entries = new HashMap<String, TranscriptEntry>();
            for (var entry : context.transcript().list(context.runId())) {
                require(context.runId().equals(entry.runId()) && entries.putIfAbsent(entry.id(), entry) == null);
            }
            if ("ecp_idp".equals(expectedProfile)) verifyEcpOperations(entries);
            require(receipt.path("phases").isArray() && receipt.path("phases").size() == PHASES.size());
            var decryptionKey = keys.keyFor(context.runId()).orElseThrow();
            var evidence = new ArrayList<EvidenceRef>();
            var algorithms = new ArrayList<String>();
            var references = new HashSet<String>();
            Instant previousStart = initial.startedAt();
            for (var index = 0; index < PHASES.size(); index++) {
                var phase = receipt.path("phases").get(index);
                requireFields(phase, Set.of("name", "globalReadBack", "relyingPartyReadBack",
                        "runtime", "requestReference", "responseReference"));
                var name = PHASES.get(index);
                require(name.equals(text(phase, "name")));
                var phaseRuntime = runtime(phase.path("runtime"));
                require(phaseRuntime.containerId().equals(initial.containerId())
                        && phaseRuntime.startedAt().isAfter(previousStart));
                previousStart = phaseRuntime.startedAt();
                var expectedGlobal = configuredGlobal(
                        blob(receipt.path("configuration").path("originalGlobal"), 524_288),
                        "blocked".equals(name));
                require(Arrays.equals(expectedGlobal, blob(phase.path("globalReadBack"), 524_288)));
                var expectedRelying = configuredRelyingParty(
                        blob(receipt.path("configuration").path("originalRelyingParty"), 524_288));
                require(Arrays.equals(expectedRelying, blob(phase.path("relyingPartyReadBack"), 524_288)));

                var request = entry(entries, text(phase, "requestReference"), Direction.OUTBOUND);
                var response = entry(entries, text(phase, "responseReference"), Direction.INBOUND);
                require(references.add(request.id()) && references.add(response.id()));
                var requestRoot = SecureXml.parse(original(request)).getDocumentElement();
                var authn = element(requestRoot, P, "AuthnRequest");
                require(authn != null && !authn.getAttribute("ID").isBlank());
                var issuers = children(authn, S, "Issuer");
                require(issuers.size() == 1 && suiteEntity.equals(issuers.getFirst().getTextContent()));
                var responseRoot = SecureXml.parse(original(response)).getDocumentElement();
                var samlResponse = element(responseRoot, P, "Response");
                require(samlResponse != null && authn.getAttribute("ID").equals(samlResponse.getAttribute("InResponseTo")));
                if ("ecp_idp".equals(expectedProfile)) {
                    require(SOAP.equals(requestRoot.getNamespaceURI()) && "Envelope".equals(requestRoot.getLocalName()));
                    require(SOAP.equals(responseRoot.getNamespaceURI()) && "Envelope".equals(responseRoot.getLocalName()));
                    require("EcpSoapRequest".equals(request.samlSummary().get("type"))
                            && "EcpSoapResponse".equals(response.samlSummary().get("type")));
                    require(request.correlationId() != null && request.correlationId().equals(response.correlationId()));
                    require(request.url() != null && request.url().equals(response.url())
                            && response.status() != null && response.status() == 200);
                } else {
                    require(requestRoot == authn && responseRoot == samlResponse);
                    require("AuthnRequest".equals(request.samlSummary().get("type"))
                            && "Response".equals(response.samlSummary().get("type")));
                    require(Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))
                            || Boolean.TRUE.equals(response.samlSummary().get("activeProbeAccepted")));
                    require(response.url() != null && response.url().equals(samlResponse.getAttribute("Destination")));
                }
                require(!response.timestamp().isBefore(request.timestamp()));
                require(!samlResponse.getAttribute("Destination").isBlank());
                require(SUCCESS.equals(firstAttribute(samlResponse, P, "StatusCode", "Value")));
                var verified = new VerifiedSignatureAlgorithms().read(samlResponse, targetEntity, signingKeys);
                require(verified.stream().anyMatch(value -> "Response".equals(value.element())));
                var encrypted = samlResponse.getElementsByTagNameNS(S, "EncryptedAssertion");
                require(encrypted.getLength() == 1);
                var wrapper = (Element) encrypted.item(0);
                var encryptedData = element(wrapper, X, "EncryptedData");
                require(encryptedData != null);
                var dataMethods = children(encryptedData, X, "EncryptionMethod");
                require(dataMethods.size() == 1);
                require(AES128.equals(dataMethods.getFirst().getAttribute("Algorithm")));
                var keysOnWire = wrapper.getElementsByTagNameNS(X, "EncryptedKey");
                require(keysOnWire.getLength() == 1);
                var transport = firstAttribute((Element) keysOnWire.item(0), X, "EncryptionMethod", "Algorithm");
                require(Set.of(RSA15, OAEP).contains(transport));
                var plaintext = new SamlXmlDecrypter().decrypt(wrapper, decryptionKey);
                require(S.equals(plaintext.getNamespaceURI()) && "Assertion".equals(plaintext.getLocalName()));
                algorithms.add(transport);
                evidence.add(new EvidenceRef("transcript", request.id()));
                evidence.add(new EvidenceRef("transcript", response.id()));
            }
            require(restored.startedAt().isAfter(previousStart));
            verifyCounts(receipt.path("operationCounts"), expectedProfile);
            require(Arrays.equals(before, Files.readAllBytes(file)));
            var outcome = algorithms.equals(List.of(RSA15, OAEP, RSA15)) ? Result.SATISFIED
                    : algorithms.equals(List.of(RSA15, RSA15, RSA15)) ? Result.VIOLATED : Result.UNPROVEN;
            return outcome == Result.UNPROVEN ? Optional.empty()
                    : Optional.of(new Proof(outcome, List.copyOf(evidence), List.copyOf(algorithms), hash(before)));
        } catch (Exception unproven) {
            return Optional.empty();
        }
    }

    private void verifyConfiguration(JsonNode node, String runId, byte[] suiteRaw) throws Exception {
        requireFields(node, Set.of("originalGlobal", "originalRelyingParty", "originalProviders",
                "providerConfiguredReadBack", "fixtureReadBack", "restoredGlobal",
                "restoredRelyingParty", "restoredProviders", "temporaryMetadataRemoved", "restored"));
        var originalGlobal = blob(node.path("originalGlobal"), 524_288);
        var originalRelying = blob(node.path("originalRelyingParty"), 524_288);
        var originalProviders = blob(node.path("originalProviders"), 524_288);
        require(!new String(originalGlobal, StandardCharsets.UTF_8).contains(GLOBAL_MARKER));
        require(!new String(originalRelying, StandardCharsets.UTF_8).contains(RELYING_MARKER)
                && !new String(originalRelying, StandardCharsets.UTF_8).contains(CONFIG_ID)
                && !new String(originalRelying, StandardCharsets.UTF_8).contains(SECURITY_CONFIG_ID));
        require(Arrays.equals(suiteRaw, blob(node.path("fixtureReadBack"), 524_288)));
        require(Arrays.equals(providerConfiguration(originalProviders, runId),
                blob(node.path("providerConfiguredReadBack"), 524_288)));
        require(Arrays.equals(originalGlobal, blob(node.path("restoredGlobal"), 524_288)));
        require(Arrays.equals(originalRelying, blob(node.path("restoredRelyingParty"), 524_288)));
        require(Arrays.equals(originalProviders, blob(node.path("restoredProviders"), 524_288)));
        require(node.path("temporaryMetadataRemoved").isBoolean()
                && node.path("temporaryMetadataRemoved").asBoolean());
        require(node.path("restored").isBoolean() && node.path("restored").asBoolean());
    }

    private RuntimeIdentity runtime(JsonNode node) throws Exception {
        requireFields(node, Set.of("inspect", "version"));
        var inspectRaw = blob(node.path("inspect"), 262_144);
        var versionRaw = blob(node.path("version"), 4096);
        require(reference.productVersion().equals(new String(versionRaw, StandardCharsets.UTF_8).trim()));
        var inspected = new JsonCodec().mapper().readTree(inspectRaw);
        require(inspected.isArray() && inspected.size() == 1);
        var item = inspected.get(0);
        require(("/" + reference.containerName()).equals(item.path("Name").asText()));
        require(item.path("Id").asText().matches("[0-9a-f]{64}"));
        require(reference.imageId().equals(item.path("Image").asText()));
        require(item.path("State").path("Running").asBoolean(false));
        var started = Instant.parse(item.path("State").path("StartedAt").asText());
        return new RuntimeIdentity(item.path("Id").asText(), started);
    }

    private byte[] original(TranscriptEntry entry) {
        require(entry.decodedSamlRef() != null && entry.decodedSamlBytes() > 0);
        var raw = content.readDecodedSaml(entry);
        require(raw != null && raw.length == entry.decodedSamlBytes());
        return raw;
    }

    private static TranscriptEntry entry(Map<String, TranscriptEntry> entries, String id, Direction direction) {
        var entry = entries.get(id);
        require(entry != null && entry.direction() == direction);
        return entry;
    }

    static byte[] configuredGlobal(byte[] original, boolean blocked) {
        var overlay = "\n    " + GLOBAL_MARKER + "\n"
                + "    <util:set id=\"shibboleth.IncludedEncryptionAlgorithms\">"
                + "<value>" + AES128 + "</value>"
                + (blocked ? "" : "<value>" + RSA15 + "</value>")
                + "<value>" + OAEP + "</value></util:set>\n"
                + "    <util:set id=\"shibboleth.ExcludedEncryptionAlgorithms\">"
                + "<value>" + TRIPLEDES + "</value>"
                + (blocked ? "<value>" + RSA15 + "</value>" : "") + "</util:set>\n";
        return insertBefore(original, "</beans>", overlay);
    }

    static byte[] configuredRelyingParty(byte[] original) {
        var text = new String(original, StandardCharsets.UTF_8);
        var defaultBean = "<bean id=\"shibboleth.DefaultRelyingParty\" parent=\"RelyingParty\">";
        require(!text.contains(RELYING_MARKER) && !text.contains(CONFIG_ID)
                && !text.contains(SECURITY_CONFIG_ID) && occurrences(text, defaultBean) == 1);
        text = text.replace(defaultBean, "<bean id=\"shibboleth.DefaultRelyingParty\" parent=\"RelyingParty\""
                + " p:securityConfiguration-ref=\"" + SECURITY_CONFIG_ID + "\">");
        var overlay = "\n    " + RELYING_MARKER + "\n"
                + "    <bean id=\"" + CONFIG_ID + "\" parent=\"shibboleth.BasicEncryptionConfiguration\""
                + " p:keyTransportKeyInfoGeneratorManager-ref=\"NamedKeyInfoGeneratorManager\">\n"
                + "      <property name=\"dataEncryptionAlgorithms\"><list><value>" + AES128
                + "</value></list></property>\n"
                + "      <property name=\"keyTransportEncryptionAlgorithms\"><list><value>" + RSA15
                + "</value><value>" + OAEP + "</value></list></property>\n"
                + "    </bean>\n"
                + "    <bean id=\"" + SECURITY_CONFIG_ID + "\" parent=\"shibboleth.DefaultSecurityConfiguration\""
                + " p:encryptionConfiguration-ref=\"" + CONFIG_ID + "\" />\n";
        return insertBefore(text.getBytes(StandardCharsets.UTF_8), "</beans>", overlay);
    }

    static byte[] providerConfiguration(byte[] original, String runId) {
        var overlay = "\n    <MetadataProvider id=\"AlgorithmPrevention" + runId
                + "\" xsi:type=\"FilesystemMetadataProvider\" metadataFile=\"/opt/reference-idp/metadata/algorithm-prevention-"
                + runId + ".xml\" />\n";
        return insertBefore(original, "</MetadataProvider>", overlay);
    }

    private static byte[] insertBefore(byte[] original, String closing, String overlay) {
        var text = new String(original, StandardCharsets.UTF_8);
        var index = text.lastIndexOf(closing);
        require(index >= 0);
        return (text.substring(0, index) + overlay + text.substring(index)).getBytes(StandardCharsets.UTF_8);
    }

    private static int occurrences(String value, String needle) {
        var count = 0;
        for (var index = 0; (index = value.indexOf(needle, index)) >= 0; index += needle.length()) count++;
        return count;
    }

    private static Element element(Element root, String namespace, String local) {
        if (namespace.equals(root.getNamespaceURI()) && local.equals(root.getLocalName())) return root;
        var values = root.getElementsByTagNameNS(namespace, local);
        return values.getLength() == 1 ? (Element) values.item(0) : null;
    }

    private static List<Element> children(Element parent, String namespace, String local) {
        var result = new ArrayList<Element>();
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && local.equals(element.getLocalName())) result.add(element);
        return result;
    }

    private static String firstAttribute(Element root, String namespace, String local, String attribute) {
        var values = root.getElementsByTagNameNS(namespace, local);
        return values.getLength() == 1 ? ((Element) values.item(0)).getAttribute(attribute) : "";
    }

    private static byte[] blob(JsonNode node, int limit) throws Exception {
        requireFields(node, Set.of("base64", "sha256"));
        var raw = Base64.getDecoder().decode(node.path("base64").asText());
        require(raw.length <= limit && hash(raw).equals(node.path("sha256").asText()));
        return raw;
    }

    private static String text(JsonNode node, String field) {
        require(node.path(field).isTextual() && !node.path(field).asText().isBlank());
        return node.path(field).asText();
    }

    private static void verifyCounts(JsonNode node, String profile) {
        requireFields(node, Set.of("productConfigurationWrites", "productRestarts",
                "metadataReloads", "protocolOperations", "humanOperations"));
        require(node.path("productConfigurationWrites").asInt(-1) == 9);
        require(node.path("productRestarts").asInt(-1) == 4);
        require(node.path("metadataReloads").asInt(-1) == 0);
        require(node.path("protocolOperations").asInt(-1)
                == ("ecp_idp".equals(profile) ? 7 : 3));
        require(node.path("humanOperations").asInt(-1) == 0);
    }

    private static void verifyEcpOperations(Map<String, TranscriptEntry> entries) {
        var requests = entries.values().stream()
                .filter(entry -> entry.direction() == Direction.OUTBOUND
                        && "EcpSoapRequest".equals(entry.samlSummary().get("type")))
                .toList();
        require(requests.size() == 7);
        require(requests.stream().map(TranscriptEntry::correlationId).filter(java.util.Objects::nonNull)
                .distinct().count() == 7);
        for (var request : requests) {
            var matching = entries.values().stream()
                    .filter(entry -> entry.direction() == Direction.INBOUND
                            && "EcpSoapResponse".equals(entry.samlSummary().get("type"))
                            && request.id().equals(entry.samlSummary().get("request_transcript"))
                            && request.correlationId().equals(entry.correlationId())
                            && request.url().equals(entry.url()))
                    .count();
            require(matching == 1);
        }
    }

    private static void requireFields(JsonNode node, Set<String> expected) {
        require(node.isObject());
        var actual = new HashSet<String>();
        node.fieldNames().forEachRemaining(actual::add);
        require(actual.equals(expected));
    }

    private static String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Algorithm-prevention evidence unproven");
    }

    enum Result { SATISFIED, VIOLATED, UNPROVEN }
    record Proof(Result result, List<EvidenceRef> evidence, List<String> algorithms, String receiptSha256) {}
    record ReferenceIdentity(String imageId, String productVersion, String containerName) {}
    private record RuntimeIdentity(String containerId, Instant startedAt) {}
}
