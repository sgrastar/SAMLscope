package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** No credentials or private keys are needed: native schema admission has no key-use claim. */
public final class VerifyKeycloakNativeSchemaAdmissionEvidence {
    private static final JsonCodec JSON = new JsonCodec();
    private static String sha(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    private static void require(boolean value, String why) { if (!value) throw new IllegalArgumentException(why); }
    private static TranscriptEntry normalized(TranscriptEntry e, byte[] raw) {
        return raw == null || raw.length == e.decodedSamlBytes() ? e : new TranscriptEntry(e.id(), e.runId(), e.direction(), e.timestamp(),
                e.correlationId(), e.method(), e.url(), e.status(), e.headers(), e.bodyRef(), e.bodyBytes(), e.decodedSamlRef(), raw.length,
                e.contentType(), e.rawQuery(), e.samlSummary());
    }
    private static CaseOutcome observe(Path directory, String run, List<TranscriptEntry> entries, Map<String,byte[]> bodies, byte[] target) {
        var actual = entries.stream().map(e -> normalized(e, bodies.get(e.id()))).toList();
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) { require(run.equals(id), "Requested foreign Run"); return actual; }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String c, Map<String,Object> s) { throw new UnsupportedOperationException(); }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        return new KeycloakNativeSchemaAdmissionEvidence(directory, e -> bodies.get(e.id())).evaluate(context, target);
    }
    private static void rewriteOriginal(ObjectNode ref, Map<String,byte[]> bodies, java.util.function.Consumer<ObjectNode> change) throws Exception {
        var id = ref.path("reference").asText(); var node = (ObjectNode) JSON.mapper().readTree(bodies.get(id));
        change.accept(node); var raw = JSON.mapper().writeValueAsBytes(node); bodies.put(id, raw); ref.put("sha256", sha(raw));
    }
    private static void rewriteBody(ObjectNode source, java.util.function.Consumer<JsonNode> change) {
        try {
            var nativeNode = (ObjectNode) source.path("native"); var json = JSON.mapper().readTree(Base64.getDecoder().decode(nativeNode.path("response_base64").asText()));
            change.accept(json); var raw = JSON.mapper().writeValueAsBytes(json);
            nativeNode.put("response_base64", Base64.getEncoder().encodeToString(raw)); nativeNode.put("response_sha256", sha(raw));
        } catch (Exception error) { throw new IllegalArgumentException(error); }
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 3, "folder data output required"); var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[2]); require(!Files.exists(output), "Immutable replay exists");
        var run = JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var entries = List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var byId = new HashMap<String,TranscriptEntry>();
        for (var entry : entries) require(run.equals(entry.runId()) && byId.put(entry.id(), entry) == null, "Foreign/duplicate original history");
        var bodies = new HashMap<String,byte[]>();
        for (var row : JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            require(path.getParent().equals(folder.resolve("decoded")) && !Files.isSymbolicLink(path), "Original path invalid");
            var raw = Files.readAllBytes(path); var entry = byId.get(row.path("id").asText());
            require(entry != null && raw.length == entry.decodedSamlBytes() && sha(raw).equals(row.path("sha256").asText())
                    && bodies.put(entry.id(), raw) == null, "Original hash/length invalid");
        }
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receipt = (ObjectNode) JSON.mapper().readTree(folder.resolve("qualified-receipt.json").toFile());
        var temporary = Files.createTempDirectory("kc-schema-replay-");
        try {
            var path = temporary.resolve(run + ".keycloak-schema-admission.json"); var jars = temporary.resolve(run + ".keycloak-schema-admission"); Files.createDirectory(jars);
            for (var name : KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS.keySet()) Files.copy(folder.resolve("native-runtime").resolve(name), jars.resolve(name));
            Files.write(path, Files.readAllBytes(folder.resolve("qualified-receipt.json")));
            var base = observe(temporary, run, entries, bodies, target);
            require(base.outcome() == Outcome.VIOLATED, "Actual native schema counterexample incomplete: " + base);
            var checks = new TreeMap<String,String>(); checks.put("native-valid-endpoint-counterexample", base.outcome().name());
            for (var name : List.of("wrong-adapter", "wrong-campaign", "wrong-run", "wrong-target", "missing-test-original", "missing-contrast-original",
                    "missing-baseline-original", "missing-restoration", "http500-is-not-rejection", "native-http200-contradiction", "wrong-native-route",
                    "unrelated-same-length-response", "request-hash-changed", "request-bytes-changed", "foreign-native-run", "restored-client-remains",
                    "native-runtime-changed", "native-source-pins-changed", "native-policy-changed", "baseline-client-identity-changed",
                    "baseline-signature-policy-changed", "foreign-transcript-run", "duplicate-transcript", "directory-receipt", "symlink-receipt",
                    "missing-schema-invalid-control", "invalid-control-auth-failure", "invalid-control-request-changed", "invalid-control-fixture-changed", "public-readback-extra-redaction", "public-readback-missing-projection",
                    "public-readback-required-field-redaction", "public-readback-sensitive-field")) {
                var altered = receipt.deepCopy(); var changed = new HashMap<>(bodies); var history = new ArrayList<>(entries);
                if (name.equals("wrong-adapter")) altered.put("adapter", "claims-only");
                else if (name.equals("wrong-campaign")) altered.put("campaignId", "another-campaign");
                else if (name.equals("wrong-run")) altered.put("runId", "run_00000000000000000000000000");
                else if (name.equals("wrong-target")) altered.put("targetMetadataSha256", "0".repeat(64));
                else if (name.equals("missing-test-original")) altered.remove("test");
                else if (name.equals("missing-contrast-original")) altered.remove("contrast");
                else if (name.equals("missing-baseline-original")) altered.remove("baselineClient");
                else if (name.equals("missing-restoration")) altered.remove("after");
                else if (name.equals("missing-schema-invalid-control")) altered.remove("schemaInvalidControl");
                else if (name.equals("foreign-transcript-run")) {
                    var e = history.getFirst(); history.set(0, new TranscriptEntry(e.id(), "run_00000000000000000000000000", e.direction(), e.timestamp(), e.correlationId(),
                            e.method(), e.url(), e.status(), e.headers(), e.bodyRef(), e.bodyBytes(), e.decodedSamlRef(), e.decodedSamlBytes(), e.contentType(), e.rawQuery(), e.samlSummary()));
                } else if (name.equals("duplicate-transcript")) history.add(history.getFirst());
                else if (!Set.of("directory-receipt", "symlink-receipt").contains(name)) {
                    var ref = (ObjectNode) (name.startsWith("restored") || name.startsWith("native-runtime") || name.startsWith("native-policy") || name.startsWith("native-source")
                            ? altered.path("after") : name.startsWith("baseline") || name.startsWith("public-readback") ? altered.path("baselineClient")
                            : name.startsWith("invalid-control") ? altered.path("schemaInvalidControl").path("conversion") : altered.path("test").path("conversion"));
                    rewriteOriginal(ref, changed, original -> {
                        var nativeNode = (ObjectNode) original.path("native");
                        switch (name) {
                            case "http500-is-not-rejection" -> nativeNode.put("status", 500);
                            case "native-http200-contradiction" -> nativeNode.put("status", 200);
                            case "wrong-native-route" -> nativeNode.put("url", "http://localhost:18180/realms/samlscope/protocol/saml");
                            case "request-hash-changed" -> nativeNode.put("request_sha256", "0".repeat(64));
                            case "request-bytes-changed" -> nativeNode.put("request_base64", Base64.getEncoder().encodeToString("unrelated XML".getBytes()));
                            case "invalid-control-auth-failure" -> nativeNode.put("status", 401);
                            case "invalid-control-request-changed" -> nativeNode.put("request_sha256", "0".repeat(64));
                            case "invalid-control-fixture-changed" -> original.put("fixtureSha256", "0".repeat(64));
                            case "foreign-native-run" -> original.put("runId", "run_00000000000000000000000000");
                            case "native-runtime-changed" -> ((ObjectNode) original.path("runtime")).put("image", "changed");
                            case "native-source-pins-changed" -> ((ObjectNode) original.path("nativeJars")).put(KeycloakNativeSchemaAdmissionEvidence.NATIVE_JARS.keySet().iterator().next(), "0".repeat(64));
                            case "native-policy-changed" -> ((ObjectNode) original.path("globalPolicy")).put("unrelated", true);
                            case "restored-client-remains" -> rewriteBody(original, json -> ((ArrayNode) json).addObject().put("id", "remaining"));
                            case "public-readback-extra-redaction" -> ((ArrayNode) nativeNode.path("redactions")).add("$.attributes.password");
                            case "public-readback-missing-projection" -> nativeNode.remove("response_projection");
                            case "public-readback-required-field-redaction" -> ((ArrayNode) nativeNode.path("redactions")).add("$.attributes.saml.client.signature");
                            case "public-readback-sensitive-field" -> rewriteBody(original, json -> ((ObjectNode) json.path("attributes")).put("saml.signing.private.key", "forbidden"));
                            case "baseline-client-identity-changed" -> rewriteBody(original, json -> ((ObjectNode) json).put("clientId", "https://foreign.example"));
                            case "baseline-signature-policy-changed" -> rewriteBody(original, json -> ((ObjectNode) json.path("attributes")).put("saml.client.signature", "false"));
                            case "unrelated-same-length-response" -> rewriteBody(original, json -> ((ObjectNode) json).put("error", "HTTP 401 Bad Request"));
                            default -> throw new IllegalArgumentException(name);
                        }
                    });
                }
                Files.deleteIfExists(path);
                if (name.equals("directory-receipt")) Files.createDirectory(path);
                else if (name.equals("symlink-receipt")) { var other = temporary.resolve("outside.json"); Files.write(other, JSON.mapper().writeValueAsBytes(altered)); Files.createSymbolicLink(path, other); }
                else Files.write(path, JSON.mapper().writeValueAsBytes(altered));
                var outcome = observe(temporary, run, history, changed, target);
                require(outcome.outcome() == Outcome.NOT_VERIFIED, "Altered original became conclusive: " + name + " " + outcome);
                checks.put(name, outcome.outcome().name());
            }
            var report = new TreeMap<String,Object>(); report.put("runId", run); report.put("caseId", KeycloakNativeSchemaAdmissionEvidence.ID);
            report.put("caseOutcome", base); report.put("checks", checks); report.put("privateKeyExported", false);
            report.put("runtimeKeyInterpretationProven", false); report.put("originalTranscriptUnchanged", true);
            JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(), report);
        } finally { try (var paths = Files.walk(temporary)) { for (var p : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(p); } }
    }
}
