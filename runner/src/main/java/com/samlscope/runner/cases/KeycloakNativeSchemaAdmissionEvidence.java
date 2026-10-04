package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.*;
import java.io.ByteArrayInputStream;
import java.net.URLClassLoader;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.*;
import java.util.*;
import javax.xml.XMLConstants;
import javax.xml.stream.*;
import org.w3c.dom.Element;

/** A single valid EndpointType counterexample. No claim about every import route or runtime keys. */
final class KeycloakNativeSchemaAdmissionEvidence {
    static final String ID = "IIP-MD05-b-idp-01";
    static final String TEST = "schema-sso-endpoint-set", CONTRAST = "schema-sso-endpoint-without-foreign";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata", DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String FOREIGN = "urn:samlscope:test:foreign";
    private static final String ADMIN = "http://localhost:18180/admin/realms/samlscope";
    private static final String IMAGE = "sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067";
    static final Map<String,String> NATIVE_JARS = Map.of(
        "org.keycloak.keycloak-saml-core-26.7.2.jar", "191794d8be9289121c628f5e69380771b67f72ea869207248c2bbda253979e84",
        "org.keycloak.keycloak-saml-core-public-26.7.2.jar", "e1262687b87e92edb759b02d568fed8518d5e00b32a70749bee61a787178bbb2",
        "org.keycloak.keycloak-services-26.7.2.jar", "213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9",
        "org.apache.santuario.xmlsec-3.0.6.jar", "395eccc3496063ac7b1d6af2422a11670ee5ded807f51542818eccd5fbb5e20c",
        "org.jboss.logging.jboss-logging-3.6.2.Final.jar", "f423e07bffce73bf2b6cc872f30981c06fe9cfd5a86a0b4f5fbdd11cfe0148e0");
    private static final ObjectMapper JSON = new ObjectMapper();
    private final Path directory;
    private final TranscriptContentReader content;
    KeycloakNativeSchemaAdmissionEvidence(Path directory, TranscriptContentReader content) {
        this.directory = directory.toAbsolutePath().normalize(); this.content = content;
    }
    boolean exists(String run) { return run.matches("run_[0-9A-HJKMNP-TV-Z]{26}") && Files.exists(path(run), LinkOption.NOFOLLOW_LINKS); }
    private Path path(String run) { return directory.resolve(run + ".keycloak-schema-admission.json"); }
    private static void require(boolean yes) { if (!yes) throw new IllegalArgumentException("native_schema_original_invalid"); }
    private static String sha(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    private Path safe(Path path) throws Exception {
        var value = path.toAbsolutePath().normalize(); require(value.startsWith(directory));
        for (var at = value; at != null; at = at.getParent()) require(!Files.isSymbolicLink(at));
        require(Files.isRegularFile(value, LinkOption.NOFOLLOW_LINKS)); return value;
    }
    private record Original(TranscriptEntry entry, JsonNode json) {}
    private Original original(JsonNode reference, String run, String targetHash,
            Map<String,TranscriptEntry> entries, List<EvidenceRef> evidence) throws Exception {
        require(reference.isObject()); var e = entries.get(reference.path("reference").asText());
        require(e != null && e.direction() == Direction.INBOUND && run.equals(e.runId()));
        var raw = content.readDecodedSaml(e);
        require(raw != null && raw.length == e.decodedSamlBytes() && sha(raw).equals(reference.path("sha256").asText()));
        var json = JSON.readTree(raw);
        require(run.equals(json.path("runId").asText()) && targetHash.equals(json.path("targetMetadataSha256").asText()));
        evidence.add(new EvidenceRef("transcript", e.id())); return new Original(e, json);
    }
    private static JsonNode http(Original original, String method, String url, int status) throws Exception {
        var node = original.json().path("native");
        require(method.equals(node.path("method").asText()) && url.equals(node.path("url").asText())
                && node.path("status").isInt() && status == node.path("status").asInt());
        if (node.has("response_projection") || node.has("redactions")) {
            require("GET".equals(method) && status == 200 && url.matches(java.util.regex.Pattern.quote(ADMIN) + "/clients/[0-9a-f-]{36}")
                    && "native-client-public-readback-v1".equals(node.path("response_projection").asText())
                    && node.path("redactions").isArray());
            var seen = new HashSet<String>();
            for (var removed : node.path("redactions")) require(removed.isTextual() && Set.of("$.secret", "$.registrationAccessToken").contains(removed.asText()) && seen.add(removed.asText()));
        }
        var raw = Base64.getDecoder().decode(node.path("response_base64").asText());
        require(sha(raw).equals(node.path("response_sha256").asText()));
        var json = JSON.readTree(raw); require(!sensitive(json)); return json;
    }
    private static boolean sensitive(JsonNode value) {
        if (value.isObject()) {
            var fields = value.fields();
            while (fields.hasNext()) { var field = fields.next();
                if (field.getKey().toLowerCase(Locale.ROOT).matches(".*(private|password|secret|credential|token).*")) {
                    // Public native creation metadata is not a credential. All other matching fields remain forbidden.
                    if (!"client.secret.creation.time".equals(field.getKey()) || !field.getValue().isTextual()
                            || !field.getValue().asText().matches("[0-9]+")) return true;
                }
                if (sensitive(field.getValue())) return true;
            }
        } else if (value.isArray()) for (var item : value) if (sensitive(item)) return true;
        return false;
    }
    private record Prepared(TranscriptEntry entry, byte[] raw, Element xml) {}
    private Prepared prepared(JsonNode member, String variant, Map<String,TranscriptEntry> entries,
            List<EvidenceRef> evidence) throws Exception {
        return prepared(member, variant, entries, evidence, true);
    }
    private Prepared prepared(JsonNode member, String variant, Map<String,TranscriptEntry> entries,
            List<EvidenceRef> evidence, boolean schemaValid) throws Exception {
        var e = entries.get(member.path("preparedReference").asText());
        require(e != null && e.direction() == Direction.OUTBOUND && Integer.valueOf(200).equals(e.status())
                && "MetadataPrepared".equals(e.samlSummary().get("type")) && variant.equals(e.samlSummary().get("variant"))
                && "PREPARED".equals(e.samlSummary().get("delivery")));
        var fetch = entries.get(String.valueOf(e.samlSummary().get("fetchTranscriptId")));
        require(fetch != null && fetch.direction() == Direction.INBOUND && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant")) && Integer.valueOf(200).equals(fetch.status())
                && fetch.id().equals(e.correlationId()) && Objects.equals(fetch.url(), e.url()) && !e.timestamp().isBefore(fetch.timestamp()));
        var raw = content.readDecodedSaml(e); require(raw != null && raw.length == e.decodedSamlBytes()
                && sha(raw).equals(e.samlSummary().get("metadataSha256")) && sha(raw).equals(member.path("fixtureSha256").asText()));
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName())
                && SamlSchemaValidation.isValid(root, SamlSchemaValidation.SchemaKind.METADATA) == schemaValid);
        var signatures = MetadataAlgorithmEvidence.children(root, DS, "Signature"); require(signatures.size() == 1);
        var certs = signatures.getFirst().getElementsByTagNameNS(DS, "X509Certificate"); require(certs.getLength() == 1);
        var cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(Base64.getMimeDecoder().decode(certs.item(0).getTextContent())));
        require(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, cert));
        evidence.add(new EvidenceRef("transcript", fetch.id())); evidence.add(new EvidenceRef("transcript", e.id()));
        return new Prepared(e, raw, root);
    }
    /** Exact semantic contrast, disregarding signature bytes and generation-time expiry only. */
    private static Object semantic(Element element, boolean root) {
        var attrs = new TreeMap<String,String>();
        for (int index = 0; index < element.getAttributes().getLength(); index++) {
            var a = element.getAttributes().item(index);
            if (XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(a.getNamespaceURI()) || (root && "validUntil".equals(a.getLocalName()))) continue;
            if (element.hasAttribute("Binding") && element.hasAttribute("Location") && FOREIGN.equals(a.getNamespaceURI())) continue;
            attrs.put(Objects.toString(a.getNamespaceURI(), "") + ":" + Objects.toString(a.getLocalName(), a.getNodeName()), a.getNodeValue());
        }
        var children = new ArrayList<Object>();
        for (var n = element.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element child) {
                if (DS.equals(child.getNamespaceURI()) && "Signature".equals(child.getLocalName())) continue;
                if (element.hasAttribute("Binding") && element.hasAttribute("Location") && FOREIGN.equals(child.getNamespaceURI())) continue;
                children.add(semantic(child, false));
            } else if (!n.getTextContent().isBlank()) children.add(n.getTextContent());
        }
        return List.of(Objects.toString(element.getNamespaceURI(), ""), element.getLocalName(), attrs, children);
    }
    private static void nativeParse(ClassLoader loader, byte[] bytes, boolean rejects) throws Exception {
        var factory = XMLInputFactory.newFactory(); factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        var xml = factory.createXMLEventReader(new ByteArrayInputStream(bytes));
        try {
            var type = loader.loadClass("org.keycloak.saml.processing.core.parsers.saml.SAMLParser");
            var parser = type.getMethod("getInstance").invoke(null);
            try { var parsed = type.getMethod("parse", XMLEventReader.class).invoke(parser, xml);
                require(!rejects && parsed.getClass().getName().equals("org.keycloak.dom.saml.v2.metadata.EntityDescriptorType"));
            } catch (java.lang.reflect.InvocationTargetException failure) {
                var cause = failure.getCause(); require(rejects && cause.getClass().getName().equals("org.keycloak.saml.common.exceptions.ParsingException")
                        && Objects.toString(cause.getMessage(), "").contains("PL00062: Parser : Unknown tag:endpoint"));
            }
        } finally { xml.close(); }
    }
    CaseOutcome evaluate(CaseContext context, byte[] targetMetadata) {
        var evidence = new ArrayList<EvidenceRef>();
        try {
            require(context.targetRole() == com.samlscope.core.plan.TargetRole.IDP && context.transcriptComplete() && exists(context.runId()));
            var receiptRaw = Files.readAllBytes(safe(path(context.runId()))); var receipt = JSON.readTree(receiptRaw);
            var target = SecureXml.parse(targetMetadata).getDocumentElement(); var targetHash = sha(targetMetadata);
            require("http://localhost:18180/realms/samlscope".equals(target.getAttribute("entityID"))
                    && "samlscope-keycloak-native-schema-admission-v1".equals(receipt.path("schema").asText())
                    && "keycloak-native-endpoint-parser-v1".equals(receipt.path("adapter").asText())
                    && context.runId().equals(receipt.path("runId").asText())
                    && "metadata-native-schema-admission".equals(receipt.path("campaignId").asText())
                    && targetHash.equals(receipt.path("targetMetadataSha256").asText())
                    && target.getAttribute("entityID").equals(receipt.path("targetEntityId").asText()));
            var entries = new HashMap<String,TranscriptEntry>();
            for (var e : context.transcript().list(context.runId())) require(context.runId().equals(e.runId()) && entries.put(e.id(), e) == null);
            var control = MetadataAlgorithmEvidence.collect(List.of("control"), context, content, targetMetadata);
            require(control.issues().isEmpty() && control.exchanges().size() == 1);
            var peer = control.exchanges().getFirst().metadata().getAttribute("entityID"); evidence.addAll(control.exchanges().getFirst().evidence());
            var test = prepared(receipt.path("test"), TEST, entries, evidence);
            var contrast = prepared(receipt.path("contrast"), CONTRAST, entries, evidence);
            var invalid = prepared(receipt.path("schemaInvalidControl"), "schema-invalid-endpoint-location", entries, evidence, false);
            require(peer.equals(test.xml().getAttribute("entityID")) && peer.equals(contrast.xml().getAttribute("entityID"))
                    && semantic(test.xml(), true).equals(semantic(contrast.xml(), true))
                    && test.xml().getElementsByTagNameNS(FOREIGN, "endpoint").getLength() > 0
                    && contrast.xml().getElementsByTagNameNS(FOREIGN, "endpoint").getLength() == 0);
            var refused = original(receipt.path("test").path("conversion"), context.runId(), targetHash, entries, evidence);
            var admitted = original(receipt.path("contrast").path("conversion"), context.runId(), targetHash, entries, evidence);
            var invalidObserved = original(receipt.path("schemaInvalidControl").path("conversion"), context.runId(), targetHash, entries, evidence);
            for (var pair : List.of(Map.entry(test, refused), Map.entry(contrast, admitted), Map.entry(invalid, invalidObserved))) {
                require("samlscope-keycloak-schema-conversion-v1".equals(pair.getValue().json().path("schema").asText())
                        && sha(pair.getKey().raw()).equals(pair.getValue().json().path("fixtureSha256").asText())
                        && sha(pair.getKey().raw()).equals(pair.getValue().json().path("native").path("request_sha256").asText())
                        && Arrays.equals(pair.getKey().raw(), Base64.getDecoder().decode(pair.getValue().json().path("native").path("request_base64").asText()))
                        && !pair.getValue().entry().timestamp().isBefore(pair.getKey().entry().timestamp()));
            }
            var error = http(refused, "POST", ADMIN + "/client-description-converter", 400);
            require(Instant.parse(test.xml().getAttribute("validUntil")).isAfter(refused.entry().timestamp())
                    && Instant.parse(contrast.xml().getAttribute("validUntil")).isAfter(admitted.entry().timestamp()));
            require(error.size() == 1 && "HTTP 400 Bad Request".equals(error.path("error").asText()));
            var client = http(admitted, "POST", ADMIN + "/client-description-converter", 200);
            require(peer.equals(client.path("clientId").asText()) && "saml".equals(client.path("protocol").asText()));
            // The approved invalid-input control is observed, not an invented reject obligation.
            // It cannot independently create a conclusive outcome in this counterexample reader.
            var invalidStatus = invalidObserved.json().path("native").path("status").asInt();
            require(Set.of(200, 400, 500).contains(invalidStatus));
            var invalidBody = http(invalidObserved, "POST", ADMIN + "/client-description-converter", invalidStatus);
            if (invalidStatus == 200) require(peer.equals(invalidBody.path("clientId").asText()) && "saml".equals(invalidBody.path("protocol").asText()));
            var before = original(receipt.path("before"), context.runId(), targetHash, entries, evidence);
            var after = original(receipt.path("after"), context.runId(), targetHash, entries, evidence);
            for (var scope : List.of(before, after)) {
                require("samlscope-keycloak-schema-runtime-scope-v1".equals(scope.json().path("schema").asText())
                        && peer.equals(scope.json().path("peerEntityId").asText())
                        && IMAGE.equals(scope.json().path("runtime").path("image").asText())
                        && scope.json().path("runtime").path("running").asBoolean()
                        && scope.json().path("nativeJars").equals(JSON.valueToTree(NATIVE_JARS)));
                var inventory = http(scope, "GET", ADMIN + "/clients?clientId=" + java.net.URLEncoder.encode(peer, java.nio.charset.StandardCharsets.UTF_8), 200);
                require(inventory.isArray() && inventory.isEmpty());
            }
            require(before.json().path("runtime").equals(after.json().path("runtime"))
                    && before.json().path("globalPolicy").equals(after.json().path("globalPolicy"))
                    && !before.entry().timestamp().isAfter(test.entry().timestamp())
                    && !before.entry().timestamp().isAfter(contrast.entry().timestamp())
                    && !after.entry().timestamp().isBefore(refused.entry().timestamp())
                    && !after.entry().timestamp().isBefore(admitted.entry().timestamp())
                    && !before.entry().timestamp().isAfter(invalid.entry().timestamp())
                    && !after.entry().timestamp().isBefore(invalidObserved.entry().timestamp()));
            var baseline = original(receipt.path("baselineClient"), context.runId(), targetHash, entries, evidence);
            var baselineConverted = original(receipt.path("baselineConversion"), context.runId(), targetHash, entries, evidence);
            var controlPrepared = prepared(receipt.path("baseline"), "control", entries, evidence);
            require("samlscope-keycloak-schema-conversion-v1".equals(baselineConverted.json().path("schema").asText())
                    && sha(controlPrepared.raw()).equals(baselineConverted.json().path("fixtureSha256").asText())
                    && sha(controlPrepared.raw()).equals(baselineConverted.json().path("native").path("request_sha256").asText())
                    && Arrays.equals(controlPrepared.raw(), Base64.getDecoder().decode(baselineConverted.json().path("native").path("request_base64").asText())));
            var nativeConverter = http(baselineConverted, "POST", ADMIN + "/client-description-converter", 200);
            var nativeClient = http(baseline, "GET", ADMIN + "/clients/" + baseline.json().path("nativeClientId").asText(), 200);
            require("native-client-public-readback-v1".equals(baseline.json().path("native").path("response_projection").asText())
                    && "samlscope-keycloak-schema-baseline-client-v1".equals(baseline.json().path("schema").asText())
                    && peer.equals(nativeClient.path("clientId").asText()) && "saml".equals(nativeClient.path("protocol").asText())
                    && nativeClient.path("enabled").asBoolean() && !sensitive(nativeClient)
                    && nativeClient.path("id").asText().matches("[0-9a-f-]{36}")
                    && nativeClient.path("id").asText().equals(baseline.json().path("nativeClientId").asText())
                    && peer.equals(nativeConverter.path("clientId").asText()) && "saml".equals(nativeConverter.path("protocol").asText()));
            var attrs = nativeConverter.path("attributes").fields();
            while (attrs.hasNext()) { var attr = attrs.next(); require(attr.getValue().equals(nativeClient.path("attributes").get(attr.getKey()))); }
            require(!before.entry().timestamp().isAfter(controlPrepared.entry().timestamp())
                    && !baselineConverted.entry().timestamp().isBefore(controlPrepared.entry().timestamp())
                    && !baseline.entry().timestamp().isBefore(baselineConverted.entry().timestamp()));
            var baselineRequest = control.exchanges().getFirst().evidence().stream().map(EvidenceRef::reference).map(entries::get)
                    .filter(Objects::nonNull).filter(e -> e.direction() == Direction.OUTBOUND && "AuthnRequest".equals(e.samlSummary().get("type")))
                    .findFirst().orElseThrow();
            require(!baseline.entry().timestamp().isAfter(baselineRequest.timestamp()));
            require(control.exchanges().getFirst().evidence().stream().map(EvidenceRef::reference)
                    .map(entries::get).filter(Objects::nonNull).allMatch(e -> !e.timestamp().isAfter(after.entry().timestamp())));
            var urls = new ArrayList<java.net.URL>();
            for (var jar : NATIVE_JARS.entrySet()) {
                var source = safe(directory.resolve(context.runId() + ".keycloak-schema-admission").resolve(jar.getKey()));
                require(sha(Files.readAllBytes(source)).equals(jar.getValue()));
                if (!jar.getKey().contains("services")) urls.add(source.toUri().toURL());
            }
            try (var loader = new URLClassLoader(urls.toArray(java.net.URL[]::new), ClassLoader.getPlatformClassLoader())) {
                nativeParse(loader, test.raw(), true); nativeParse(loader, contrast.raw(), false);
            }
            evidence.add(new EvidenceRef("native-schema-admission-evidence", context.runId() + ".keycloak-schema-admission.json#" + sha(receiptRaw)));
            return new CaseOutcome(Outcome.VIOLATED, null, "metadata.schema.native-valid-endpoint-extension-rejected",
                    "metadata.schema.native-valid-endpoint-extension-rejected", evidence.stream().distinct().toList(),
                    Map.of("adapter", "keycloak-native-endpoint-parser-v1", "run_id", context.runId(),
                            "counterexample_variant", TEST, "schema_valid", true, "native_parser_replayed", true,
                            "native_consumer_route", "client-description-converter", "runtime_key_interpretation_proven", false,
                            "restoration_verified", true, "receipt_sha256", sha(receiptRaw),
                            "schema_invalid_control", invalidStatus == 200 ? "native-accepted" : invalidStatus == 400 ? "native-rejected" : "native-error"));
        } catch (Exception invalid) {
            return CaseOutcome.notVerified("native_schema_admission_incomplete", "metadata.schema.native-admission-incomplete");
        }
    }
}
