package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataFullUiComparison.require;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.zip.ZipFile;

/** Complete UI values from the running native MetadataResolverService, rather than import success.
 * The public reader never accepts a developer-mutated native model. Model mutants may be checked
 * by an explicitly permitted offline replay using the same value comparison. */
public final class ShibbolethMetadataFullUiEvidence {
    public static final String SCHEMA = "samlscope-metadata-full-ui-native-v1";
    public static final String ADAPTER = "shibboleth-metadata-resolver-full-ui-v1";
    public static final String CAMPAIGN = "native-metadata-full-ui";
    public static final String ORIGINAL = "samlscope-metadata-full-ui-original-v1";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    static final Map<String, String> JARS = Map.of(
            "native-conf.jar", "428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba",
            "native-saml.jar", "9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581",
            "native-profile.jar", "aaa769a9ccdfb1428173e3932d598ced0302908fab3b8bfe2100331678c9f405",
            "native-cli.jar", "2258de2a92d4c079398d36265cda8a59e40e66bdce8dfb84571be418faa7dc7c");
    private final Path directory;
    private final TranscriptContentReader content;
    private final boolean offline;
    public ShibbolethMetadataFullUiEvidence(Path directory, TranscriptContentReader content) {
        this(directory, content, false);
    }
    ShibbolethMetadataFullUiEvidence(Path directory, TranscriptContentReader content, boolean offline) {
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content); this.offline = offline;
    }
    public boolean exists(String run) {
        return validRun(run) && Files.exists(directory.resolve(run), LinkOption.NOFOLLOW_LINKS);
    }
    private static boolean validRun(String run) { return run != null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"); }
    static String sha(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static String text(JsonNode n, String field) {
        require(n.path(field).isTextual() && !n.path(field).asText().isBlank()); return n.path(field).asText();
    }
    private static Instant at(JsonNode n, String field) { return Instant.parse(text(n, field)); }
    private static byte[] b64(JsonNode n, String field) { return Base64.getDecoder().decode(text(n, field)); }
    private static void flag(JsonNode n, String field, boolean expected) {
        require(n.path(field).isBoolean() && n.path(field).asBoolean() == expected);
    }
    private byte[] raw(Path folder, String name, long maximum) throws Exception {
        require(!name.isBlank() && !Path.of(name).isAbsolute()); var p = folder.resolve(name).normalize();
        require(p.startsWith(folder) && !p.equals(folder));
        for (var parent = p; parent != null; parent = parent.getParent()) require(!Files.isSymbolicLink(parent));
        require(Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) && Files.size(p) > 0 && Files.size(p) <= maximum);
        return Files.readAllBytes(p);
    }
    private byte[] file(Path folder, JsonNode manifest, String name) throws Exception {
        var bytes = raw(folder, name, 16777216); require(sha(bytes).equals(text(manifest.path("files"), name))); return bytes;
    }
    private byte[] decoded(TranscriptEntry e) throws Exception {
        require(e != null && e.decodedSamlRef() != null); var bytes = content.readDecodedSaml(e);
        require(bytes != null && bytes.length == e.decodedSamlBytes()); return bytes;
    }
    private record Original(JsonNode value, TranscriptEntry entry) {}
    private Original original(CaseContext c, Path folder, JsonNode m, String kind,
            Map<String, TranscriptEntry> entries, List<EvidenceRef> refs) throws Exception {
        var ref = m.path("originals").path(kind); String id = text(ref, "reference");
        var entry = entries.get(id); var bytes = decoded(entry);
        require(sha(bytes).equals(text(ref, "sha256"))
                && Arrays.equals(bytes, file(folder, m, "native-originals/" + kind + ".json")));
        require(entry.direction() == Direction.INBOUND && Objects.equals(entry.status(), 204)
                && "POST".equals(entry.method()) && "application/json".equals(entry.contentType())
                && (text(m, "peerEntityId") + "/sp/paos?run=" + c.runId()).equals(entry.url()));
        var n = JSON.readTree(bytes);
        require(ORIGINAL.equals(text(n, "schema")) && CAMPAIGN.equals(text(n, "campaignId"))
                && c.runId().equals(text(n, "runId")) && kind.equals(text(n, "kind"))
                && m.path("peerEntityId").equals(n.path("peerEntityId"))
                && m.path("targetMetadataSha256").equals(n.path("targetMetadataSha256"))
                && !at(n, "recordedAt").isAfter(entry.timestamp()) && !sensitive(n));
        refs.add(new EvidenceRef("transcript", id)); return new Original(n, entry);
    }
    public Optional<CaseOutcome> evaluate(CaseContext context, byte[] targetMetadata) {
        if (!exists(context.runId())) return Optional.empty();
        String stage = "receipt"; var refs = new ArrayList<EvidenceRef>();
        try {
            require(context.transcriptComplete()); var folder = directory.resolve(context.runId());
            var bytes = raw(folder, "manifest.json", 262144); var m = JSON.readTree(bytes);
            require(SCHEMA.equals(text(m, "schema")) && ADAPTER.equals(text(m, "adapter"))
                    && CAMPAIGN.equals(text(m, "campaignId")) && context.runId().equals(text(m, "runId")));
            flag(m, "counterfactualCalibrationOnly", false);
            String peer = text(m, "peerEntityId");
            require(text(m, "planId").matches("plan_[0-9A-HJKMNP-TV-Z]{26}")
                    && java.net.URI.create(peer).isAbsolute()
                    && java.net.URI.create(peer).getRawQuery() == null && java.net.URI.create(peer).getRawFragment() == null
                    && java.net.URI.create(peer).getPath().equals("/p/" + text(m, "planId"))
                    && sha(targetMetadata).equals(text(m, "targetMetadataSha256"))
                    && text(m, "targetEntityId").equals(SecureXml.parse(targetMetadata).getDocumentElement().getAttribute("entityID")));
            var entries = new LinkedHashMap<String, TranscriptEntry>();
            for (var e : context.transcript().list(context.runId())) require(context.runId().equals(e.runId())
                    && entries.put(e.id(), e) == null && (e.decodedSamlRef() == null
                    || ("transcripts/" + context.runId() + "/" + e.id() + ".saml.xml").equals(e.decodedSamlRef())));
            stage = "configuration-restoration";
            var before = original(context, folder, m, "before", entries, refs).value();
            var control = original(context, folder, m, "control-readback", entries, refs).value();
            var loaded = original(context, folder, m, "full-ui-readback", entries, refs).value();
            var after = original(context, folder, m, "after", entries, refs).value();
            var source = original(context, folder, m, "native-source", entries, refs).value();
            var operations = original(context, folder, m, "operations", entries, refs).value();
            flag(before, "temporaryAbsent", true); flag(after, "temporaryAbsent", true); flag(after, "restored", true);
            require(Arrays.equals(b64(before, "providersBase64"), b64(after, "providersBase64")));
            verifyRuntime(before.path("runtime"));
            for (var n : List.of(control, loaded, after)) require(before.path("runtime").equals(n.path("runtime")));
            require(before.path("sourceSha256").equals(after.path("sourceSha256"))
                    && before.path("sourceSha256").equals(source.path("sourceSha256")));
            stage = "native-resolver-source"; verifySource(folder, m, source);
            stage = "prepared-fixtures";
            var controlPrepared = prepared(context, entries, "control", refs);
            var fullPrepared = prepared(context, entries, "full-ui-info", refs);
            require(controlPrepared.timestamp().isAfter(at(before, "recordedAt"))
                    && fullPrepared.timestamp().isAfter(controlPrepared.timestamp()));
            var controlBytes = decoded(controlPrepared); var input = decoded(fullPrepared);
            var expected = MetadataFullUiComparison.input(input); require(peer.equals(expected.entityId()));
            require(peer.equals(SecureXml.parse(controlBytes).getDocumentElement().getAttribute("entityID")));
            require(Arrays.equals(input, b64(loaded, "fixtureBase64"))
                    && Arrays.equals(controlBytes, b64(control, "fixtureBase64")));
            verifyProvider(context.runId(), peer, before, control, loaded, after);
            stage = "native-model-values";
            var controlOutput = nativeQuery(control, peer, controlPrepared.timestamp());
            require(peer.equals(SecureXml.parse(controlOutput).getDocumentElement().getAttribute("entityID")));
            var nativeOutput = nativeQuery(loaded, peer, fullPrepared.timestamp());
            require(at(loaded, "recordedAt").isAfter(at(control.path("query"), "finishedAt"))
                    && at(after, "recordedAt").isAfter(at(loaded.path("query"), "finishedAt")));
            // A bare failed setup, HTTP error or partial native output cannot become a product finding.
            var actual = MetadataFullUiComparison.output(nativeOutput);
            require(MetadataFullUiComparison.matches(expected, actual));
            stage = "operation-counts"; verifyOperations(operations);
            boolean violated = false;
            if (m.has("calibration")) {
                require(offline); stage = "offline-native-model-control";
                violated = verifyCalibration(folder, m, nativeOutput, expected, loaded.path("runtime"));
            }
            require(Arrays.equals(bytes, raw(folder, "manifest.json", 262144)));
            refs.add(new EvidenceRef("native-full-ui", context.runId() + "/manifest.json#" + sha(bytes)));
            String reason = violated ? "metadata.full-ui.native-extension-ignored" : "metadata.full-ui.native-values-observed";
            return Optional.of(new CaseOutcome(violated ? Outcome.VIOLATED : Outcome.SATISFIED,
                    null, reason, reason, refs.stream().distinct().toList(), Map.of(
                            "native_full_ui_values_verified", true, "native_metadata_resolver_verified", true,
                            "restoration_verified", true, "counterfactual_calibration_only", violated,
                            "known_value_groups", expected.knownValues().keySet().stream().sorted().toList(),
                            "unknown_extension_retention_required", false,
                            "full_ui_tester_logins", operations.path("fullUiTesterLogins").asInt(),
                            "full_ui_saml_submissions", operations.path("fullUiSamlSubmissions").asInt())));
        } catch (Exception unavailable) {
            return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED, "native_full_ui_values_unproven",
                    "metadata.full-ui.native-values-unproven", "metadata.full-ui.native-values-unproven",
                    List.of(), Map.of("evidence_issue", stage)));
        }
    }
    private TranscriptEntry prepared(CaseContext c, Map<String, TranscriptEntry> entries, String variant,
            List<EvidenceRef> refs) throws Exception {
        var selected = entries.values().stream().filter(e -> e.direction() == Direction.OUTBOUND
                && "MetadataPrepared".equals(e.samlSummary().get("type"))
                && variant.equals(e.samlSummary().get("variant"))).toList(); require(selected.size() == 1);
        var e = selected.getFirst(); var bytes = decoded(e);
        require(sha(bytes).equals(e.samlSummary().get("metadataSha256"))
                && Objects.equals(e.status(), 200) && "PREPARED".equals(e.samlSummary().get("delivery")));
        var fetch = entries.get(String.valueOf(e.samlSummary().get("fetchTranscriptId")));
        require(fetch != null && fetch.direction() == Direction.INBOUND && "MetadataFetch".equals(fetch.samlSummary().get("type"))
                && variant.equals(fetch.samlSummary().get("variant")) && Objects.equals(fetch.status(), 200)
                && Objects.equals(fetch.id(), e.correlationId()) && Objects.equals(fetch.url(), e.url())
                && !fetch.timestamp().isAfter(e.timestamp()));
        var root = SecureXml.parse(bytes).getDocumentElement();
        var sig = MetadataFullUiComparison.one(MetadataFullUiComparison.children(root, DS, "Signature"));
        var certificates = sig.getElementsByTagNameNS(DS, "X509Certificate"); require(certificates.getLength() == 1);
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(certificates.item(0).getTextContent())));
        require(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, certificate));
        refs.add(new EvidenceRef("transcript", fetch.id())); refs.add(new EvidenceRef("transcript", e.id())); return e;
    }
    private static void verifyRuntime(JsonNode n) {
        flag(n, "running", true); require(text(n, "containerId").matches("[a-f0-9]{64}")
                && "sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a".equals(text(n, "image"))
                && n.path("mounts").isArray() && n.path("mounts").isEmpty()); at(n, "startedAt");
    }
    private static byte[] nativeQuery(JsonNode n, String entity, Instant preparedAt) throws Exception {
        var q = n.path("query"); var expected = List.of("env", "-u", "CLASSPATH", "-u", "JAVA_OPTS", "-u", "SHIB_OPTS",
                "/opt/reference-idp/bin/mdquery.sh", "-u", "http://localhost:8080/idp", "-e", entity);
        require(q.path("command").equals(JSON.valueToTree(expected)) && q.path("exitCode").isInt() && q.path("exitCode").asInt() == 0);
        var output = b64(q, "stdoutBase64"); var error = q.path("stderrBase64").asText("");
        require(sha(output).equals(text(q, "stdoutSha256"))
                && sha(Base64.getDecoder().decode(error)).equals(text(q, "stderrSha256"))
                && !at(q, "startedAt").isBefore(preparedAt) && !at(q, "finishedAt").isBefore(at(q, "startedAt"))
                && !at(q, "finishedAt").isAfter(at(n, "recordedAt")));
        return output;
    }
    private static void verifyProvider(String run, String entity, JsonNode before, JsonNode control,
            JsonNode loaded, JsonNode after) throws Exception {
        String path = "/opt/reference-idp/metadata/full-ui-" + run + ".xml";
        require(path.equals(text(before, "temporaryPath")) && path.equals(text(after, "temporaryPath")));
        require(Arrays.equals(b64(control, "providersBase64"), b64(loaded, "providersBase64")));
        var xml = SecureXml.parse(b64(loaded, "providersBase64")).getDocumentElement();
        var providers = xml.getElementsByTagNameNS("urn:mace:shibboleth:2.0:metadata", "MetadataProvider");
        int matches = 0;
        for (int i = 0; i < providers.getLength(); i++) {
            var p = (org.w3c.dom.Element) providers.item(i);
            if (path.equals(p.getAttribute("metadataFile"))) {
                matches++; require(("FullUi" + run).equals(p.getAttribute("id"))
                        && "FilesystemMetadataProvider".equals(p.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "type")));
            }
        }
        require(matches == 1 && !Arrays.equals(b64(before, "providersBase64"), b64(loaded, "providersBase64")));
    }
    private void verifySource(Path folder, JsonNode m, JsonNode source) throws Exception {
        require(source.path("sourceSha256").isObject());
        for (var pin : JARS.entrySet()) {
            var bytes = file(folder, m, pin.getKey());
            require(sha(bytes).equals(pin.getValue()) && pin.getValue().equals(text(source.path("sourceSha256"), pin.getKey())));
        }
        flag(source, "mdqueryViewOverrideAbsent", true);
        var inventoryBytes = file(folder, m, "native-override-inventory.txt");
        require(sha(inventoryBytes).equals(text(source, "overrideInventorySha256")));
        String inventory = new String(inventoryBytes, java.nio.charset.StandardCharsets.UTF_8);
        require(sha(inventoryBytes).equals(text(source.path("sourceSha256"), "overrideInventory")));
        for (String path : inventory.lines().toList()) require(path.startsWith("/opt/reference-idp/")
                && !path.endsWith("/admin/mdquery.vm") && !path.contains("/flows/admin/mdquery")
                && !path.endsWith(".jar") && !path.endsWith(".class"));
        require("e372c0461662e808f05be876feafceb8d405c03f4c13fd7fcfa605af1a7aafb4".equals(
                text(source.path("sourceSha256"), "mdquery.sh"))
                && "8d434c82391fdc9340a6a9988b2ed758a9e33f0eeedf8d86c58519885e133dec".equals(
                        text(source.path("sourceSha256"), "runclass.sh")));
        for (String script : List.of("mdquery.sh", "runclass.sh"))
            require(sha(file(folder, m, "native-" + script)).equals(text(source.path("sourceSha256"), script)));
        try (var jar = new ZipFile(folder.resolve("native-conf.jar").toFile())) {
            var entry = jar.getEntry("net/shibboleth/idp/flows/admin/mdquery-beans.xml"); require(entry != null);
            try (var input = jar.getInputStream(entry)) {
                String xml = new String(input.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                require(xml.contains("shibboleth.MetadataResolver") && xml.contains("PredicateRoleDescriptorResolver"));
            }
        }
    }
    static void verifyOperations(JsonNode n) {
        flag(n, "restored", true);
        for (var field : List.of("fullUiTesterLogins", "fullUiSamlSubmissions", "productRestarts", "humanOperations",
                "initialBaselineSubmissions", "initialCredentialSubmissions", "configurationWriteAttempts",
                "restorationWrites", "metadataReloadAttempts", "nativeModelQueries"))
            require(n.path(field).isInt() && n.path(field).asInt() >= 0);
        var ledger = n.path("ledger"); require(ledger.isArray());
        var counts = new HashMap<String, Integer>(); int restores = 0;
        for (var row : ledger) {
            String operation = text(row, "operation"); Instant.parse(text(row, "startedAt"));
            flag(row, "completed", row.path("completed").asBoolean());
            require(Set.of("write", "reload", "query", "remove", "restart").contains(operation));
            counts.merge(operation, 1, Integer::sum);
            if (operation.equals("write") && text(row, "label").startsWith("restore-")) restores++;
        }
        require(counts.getOrDefault("write", 0) == n.path("configurationWriteAttempts").asInt()
                && counts.getOrDefault("reload", 0) == n.path("metadataReloadAttempts").asInt()
                && counts.getOrDefault("query", 0) == n.path("nativeModelQueries").asInt()
                && counts.getOrDefault("restart", 0) == n.path("productRestarts").asInt()
                && restores == n.path("restorationWrites").asInt());
    }
    private boolean verifyCalibration(Path folder, JsonNode m, byte[] nativeOutput,
            MetadataFullUiComparison.Values expected, JsonNode expectedRuntime) throws Exception {
        // This payload is never installed with a production receipt. Both real native executions
        // and their public source/invocation originals must exist before evaluating the mutant.
        var cal = m.path("calibration"); flag(cal, "counterfactualCalibrationOnly", true);
        var original = file(folder, m, text(cal, "inputFile")); require(Arrays.equals(original, nativeOutput));
        var stock = file(folder, m, text(cal, "stockOutputFile"));
        var mutant = file(folder, m, text(cal, "mutantOutputFile"));
        var operations = JSON.readTree(file(folder, m, text(cal, "operationsFile")));
        require("samlscope-full-ui-model-calibration-v1".equals(text(operations, "schema"))
                && m.path("runId").equals(operations.path("runId")));
        require(operations.path("nativeRuntimeBefore").equals(expectedRuntime)
                && operations.path("nativeRuntimeAfter").equals(expectedRuntime));
        flag(operations, "counterfactualCalibrationOnly", true);
        require(operations.path("invocations").isArray() && operations.path("invocations").size() == 2);
        var producer = file(folder, m, text(cal, "producerFile"));
        require(sha(producer).equals(text(cal, "producerSha256"))
                && "a59228b9daabf838ca5975c1ffcc6f8cd74a72bb2ef7c11308d838c18796639a".equals(sha(producer)));
        for (int i = 0; i < 2; i++) {
            var row = operations.path("invocations").get(i); String mode = i == 0 ? "stock" : "ignore-full-ui";
            require(mode.equals(text(row, "mode")) && row.path("exitCode").asInt(-1) == 0
                    && sha(original).equals(text(row, "inputSha256")) && sha(producer).equals(text(row, "producerSha256"))
                    && sha(i == 0 ? stock : mutant).equals(text(row, "outputSha256"))
                    && !at(row, "finishedAt").isBefore(at(row, "startedAt")));
            var command = row.path("command"); require(command.isArray() && command.size() == 6
                    && "java".equals(command.get(0).asText()) && "-cp".equals(command.get(1).asText())
                    && "FullUiNativeModelControl".equals(command.get(3).asText()) && mode.equals(command.get(4).asText())
                    && command.get(2).asText().endsWith(":/usr/local/tomcat/webapps/idp/WEB-INF/lib/*")
                    && command.get(5).asText().endsWith("/input.xml"));
            var error = file(folder, m, text(row, "stderrFile"));
            require(sha(error).equals(text(row, "stderrSha256")));
            String observed = new String(error, java.nio.charset.StandardCharsets.UTF_8);
            for (String name : List.of("org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl",
                    "org.opensaml.saml.ext.saml2mdui.impl.UIInfoUnmarshaller",
                    "org.opensaml.saml.ext.saml2mdui.impl.DiscoHintsUnmarshaller"))
                require(observed.contains("FULL_UI_MODEL_SOURCE|" + name + "|" + JARS.get("native-saml.jar")));
        }
        require(MetadataFullUiComparison.matches(expected, MetadataFullUiComparison.output(stock)));
        var ignored = MetadataFullUiComparison.output(mutant);
        require(expected.entityId().equals(ignored.entityId()) && ignored.knownValues().isEmpty());
        return true;
    }
    private static boolean sensitive(JsonNode node) {
        if (node.isObject()) {
            var fields = node.fields(); while (fields.hasNext()) {
                var e = fields.next(); String key = e.getKey().toLowerCase(Locale.ROOT).replaceAll("[-_.]", "");
                if (Set.of("cookie", "setcookie", "authorization", "password", "secret", "privatekey", "token", "credentials").contains(key)
                        || sensitive(e.getValue())) return true;
            }
        } else if (node.isArray()) for (var item : node) if (sensitive(item)) return true;
        return false;
    }
}
