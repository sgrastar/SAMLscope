package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Replays the actual production reader and evidence tamper controls against native originals. */
public final class VerifyShibbolethRoleSigningTransportEvidence {
    private static final JsonCodec JSON = new JsonCodec();

    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    private static Outcome evaluate(Path root, ObjectNode manifest, List<TranscriptEntry> entries,
            Map<String, byte[]> bodies, String run, byte[] target) throws Exception {
        var folder = root.resolve(run + ".refresh");
        Files.write(folder.resolve("manifest.json"), JSON.mapper().writeValueAsBytes(manifest));
        var recorder = new TranscriptRecorder() {
            @Override public List<TranscriptEntry> list(String id) {
                if (!run.equals(id)) throw new IllegalArgumentException("Wrong Run");
                return entries;
            }
            @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            @Override public TranscriptEntry updateSamlAnalysis(String id, String correlation,
                    Map<String, Object> summary) { throw new UnsupportedOperationException(); }
        };
        TranscriptContentReader content = entry -> bodies.get(entry.id());
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(),
                new TestPlan.Parameters(180, manifest.path("refreshWaitSeconds").asInt(), "",
                        TestPlan.RequestSigningMode.REQUIRED), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, recorder, true);
        var result = new ShibbolethRoleSigningTransportEvidenceFile(root, content).evaluate(context,target).orElseGet(() -> com.samlscope.core.evaluation.CaseOutcome.notVerified("missing_scope","scope.unproven"));
        if (result.outcome() != Outcome.SATISFIED_WITH_NOTE && result.outcome() != Outcome.NOT_VERIFIED)
            throw new IllegalStateException("Unexpected outcome " + result.outcome());
        if (result.outcome() == Outcome.NOT_VERIFIED && manifest.path("replayDiagnostic").asBoolean(false))
            throw new IllegalStateException("Valid evidence rejected " + result.details());
        return result.outcome();
    }

    private static TranscriptEntry replacement(TranscriptEntry entry, String run, java.time.Instant at,
            Map<String, List<String>> headers) {
        return new TranscriptEntry(entry.id(), run, entry.direction(), at, entry.correlationId(),
                entry.method(), entry.url(), entry.status(), headers, entry.bodyRef(), entry.bodyBytes(),
                entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(),
                entry.samlSummary());
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("campaign-folder output-report required");
        var folder = Path.of(args[0]).toAbsolutePath();
        var output = Path.of(args[1]).toAbsolutePath();
        if (Files.exists(output)) throw new IllegalArgumentException("Refusing to replace report");
        var run = JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var scopeBase = (ObjectNode) JSON.mapper().readTree(folder.resolve("http-scope.json").toFile());
        var base = (ObjectNode) JSON.mapper().readTree(folder.resolve("metadata-refresh-manifest.json").toFile());
        var entries = List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var bodies = new HashMap<String, byte[]>();
        for (var row : JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            if (!path.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Unsafe original");
            var raw = Files.readAllBytes(path);
            if (!hash(raw).equals(row.path("sha256").asText())) throw new IllegalArgumentException("Original hash");
            bodies.put(row.path("id").asText(), raw);
        }
        var files = new HashMap<String, byte[]>();
        try (var paths = Files.list(folder)) {
            for (var source : paths.filter(Files::isRegularFile).toList())
                files.put(source.getFileName().toString(), Files.readAllBytes(source));
        }
        var temporary = Files.createTempDirectory("samlscope-shib-refresh-replay-");
        var receipt = temporary.resolve(run + ".refresh");
        Files.createDirectory(receipt);
        var checks = new LinkedHashMap<String, String>();
        try {
            for (var item : files.entrySet()) Files.write(receipt.resolve(item.getKey()), item.getValue());
            var diagnostic = base.deepCopy().put("replayDiagnostic", true);
            if (evaluate(temporary, diagnostic, entries, bodies, run, target) != Outcome.SATISFIED_WITH_NOTE)
                throw new IllegalStateException("Native campaign does not prove refresh");
            for (var mutation : List.of("wrong-run", "wrong-adapter", "wrong-entity", "wrong-url",
                    "missing-control", "wrong-response", "restoration-byte-change", "audit-restoration-change",
                    "same-metadata-key", "native-load-missing", "wrong-native-rejection", "wrong-rejection-request",
                    "native-success-missing", "write-during-campaign", "product-replacement", "source-config-changed",
                    "missing-native-fetch", "foreign-run-transcript", "duplicate-response", "operator-only-fetch",
                    "old-key-request", "valid-negative-control", "early-refresh")) {
                for (var item : files.entrySet()) Files.write(receipt.resolve(item.getKey()), item.getValue());
                var changed = base.deepCopy();
                var changedEntries = new ArrayList<>(entries);
                var changedBodies = new HashMap<>(bodies);
                var phaseA = (ObjectNode) changed.path("phaseA");
                var phaseB = (ObjectNode) changed.path("phaseB");
                String file = null, field = null;
                byte[] raw = null;
                switch (mutation) {
                    case "wrong-run" -> changed.put("runId", "run_00000000000000000000000000");
                    case "wrong-adapter" -> changed.put("adapter", "unknown-adapter");
                    case "wrong-entity" -> changed.put("entityId", "https://invalid.example");
                    case "wrong-url" -> changed.put("metadataUrl", "http://samlscope-reference-suite:8080/other");
                    case "missing-control" -> phaseB.remove("controlRequestReference");
                    case "wrong-response" -> phaseB.put("responseReference", phaseA.path("responseReference").asText());
                    case "restoration-byte-change", "audit-restoration-change" -> {
                        file = mutation.startsWith("audit-") ? "final-audit.xml" : "final-providers.xml";
                        field = mutation.startsWith("audit-") ? "finalAuditSha256" : "finalConfigSha256";
                        raw = "changed original".getBytes(StandardCharsets.UTF_8);
                    }
                    case "same-metadata-key" -> {
                        file = "metadata-b.xml"; field = "metadataBSha256"; raw = files.get("metadata-a.xml");
                    }
                    case "native-load-missing" -> {
                        file = "native-refresh.log"; field = "nativeRefreshSha256"; raw = new byte[0];
                    }
                    case "wrong-native-rejection", "wrong-rejection-request", "native-success-missing" -> {
                        file = "native-signature-audit.log"; field = "nativeAuditSha256";
                        var text = new String(files.get(file), StandardCharsets.UTF_8);
                        if (mutation.equals("wrong-native-rejection")) text = text.replace("MessageAuthenticationError", "OtherError");
                        else if (mutation.equals("wrong-rejection-request")) {
                            var control = entries.stream().filter(value -> value.id().equals(
                                    phaseB.path("controlRequestReference").asText())).findFirst().orElseThrow();
                            text = text.replace(control.correlationId(), "_different-request");
                        } else text = text.replace("|Success|", "|Unrelated|");
                        raw = text.getBytes(StandardCharsets.UTF_8);
                    }
                    case "write-during-campaign" -> {
                        file = "operation-counts.json"; field = "operationCountsSha256";
                        var value = JSON.mapper().readTree(files.get(file));
                        ((ObjectNode) value.path("operations").get(0)).put("recordedAt",
                                entries.stream().filter(entry -> entry.id().equals(phaseB.path("requestReference").asText()))
                                        .findFirst().orElseThrow().timestamp().getEpochSecond());
                        raw = JSON.mapper().writeValueAsBytes(value);
                    }
                    case "product-replacement" -> {
                        file = "target-runtime-end.json"; field = "targetRuntimeEndSha256";
                        var value = (ObjectNode) JSON.mapper().readTree(files.get(file));
                        value.withObject("/binding").put("container_id", "0".repeat(64));
                        raw = JSON.mapper().writeValueAsBytes(value);
                    }
                    case "source-config-changed" -> {
                        file = "configured-providers.xml"; field = "configuredConfigSha256";
                        raw = new String(files.get(file), StandardCharsets.UTF_8)
                                .replace("maxRefreshDelay=\"PT10S\"", "maxRefreshDelay=\"PT20S\"").getBytes(StandardCharsets.UTF_8);
                    }
                    case "missing-native-fetch" -> changedEntries.removeIf(entry -> entry.id().equals(phaseB.path("fetchReference").asText()));
                    case "foreign-run-transcript", "operator-only-fetch", "early-refresh" -> {
                        var id = phaseB.path("fetchReference").asText();
                        var entry = changedEntries.stream().filter(value -> value.id().equals(id)).findFirst().orElseThrow();
                        changedEntries.set(changedEntries.indexOf(entry), replacement(entry,
                                mutation.equals("foreign-run-transcript") ? "run_00000000000000000000000000" : entry.runId(),
                                mutation.equals("early-refresh") ? entries.get(0).timestamp() : entry.timestamp(),
                                mutation.equals("operator-only-fetch") ? Map.of("User-Agent", List.of("Python-urllib")) : entry.headers()));
                    }
                    case "duplicate-response" -> changedEntries.add(entries.stream().filter(entry -> entry.id().equals(
                            phaseB.path("responseReference").asText())).findFirst().orElseThrow());
                    case "old-key-request" -> changedBodies.put(phaseB.path("requestReference").asText(),
                            bodies.get(phaseA.path("requestReference").asText()));
                    case "valid-negative-control" -> changedBodies.put(phaseB.path("controlRequestReference").asText(),
                            bodies.get(phaseB.path("requestReference").asText()));
                    default -> throw new IllegalStateException(mutation);
                }
                if (file != null) {
                    Files.write(receipt.resolve(file), raw);
                    changed.put(field, hash(raw));
                }
                if (evaluate(temporary, changed, changedEntries, changedBodies, run, target) != Outcome.NOT_VERIFIED)
                    throw new IllegalStateException("Invalid evidence accepted: " + mutation);
                checks.put(mutation, "NOT_VERIFIED");
            }

            for (var mutation : List.of("wrong-scope-run", "wrong-scope-target", "https-listener", "extra-tls-listener",
                    "https-native-source", "missing-native-source", "changed-native-source-after", "late-scope-before",
                    "early-scope-after", "https-transcript-url", "invalid-target-response-signature")) {
                for (var item : files.entrySet()) Files.write(receipt.resolve(item.getKey()), item.getValue());
                var scope = scopeBase.deepCopy();
                var changedEntries = new ArrayList<>(entries);
                var changedBodies = new HashMap<>(bodies);
                switch (mutation) {
                    case "wrong-scope-run" -> scope.put("runId", "run_00000000000000000000000000");
                    case "wrong-scope-target" -> scope.put("targetMetadataSha256", "0".repeat(64));
                    case "late-scope-before" -> ((ObjectNode)scope.path("before")).put("recordedAt", "2099-01-01T00:00:00Z");
                    case "early-scope-after" -> ((ObjectNode)scope.path("after")).put("recordedAt", "2000-01-01T00:00:00Z");
                    case "missing-native-source" -> ((com.fasterxml.jackson.databind.node.ArrayNode)scope.at("/before/files")).remove(0);
                    case "https-listener", "extra-tls-listener" -> {
                        for (var phase : List.of("before", "after")) {
                            var row = (ObjectNode)scope.path(phase);
                            var doc = com.samlscope.saml.normal.SecureXml.parse(files.get(row.path("serverFile").asText()));
                            var connector = (org.w3c.dom.Element)doc.getElementsByTagName("Connector").item(0);
                            if (mutation.equals("https-listener")) connector.setAttribute("scheme", "https");
                            else connector.getParentNode().appendChild(connector.cloneNode(true));
                            var raw = com.samlscope.saml.normal.SecureXml.serialize(doc);
                            Files.write(receipt.resolve(row.path("serverFile").asText()),raw);
                            row.put("serverSha256",hash(raw));
                        }
                    }
                    case "https-native-source", "changed-native-source-after" -> {
                        for (var phase : mutation.equals("changed-native-source-after") ? List.of("after") : List.of("before", "after")) {
                            var row = (ObjectNode)scope.at("/"+phase+"/files/0");
                            var raw = new String(files.get(row.path("file").asText()),StandardCharsets.UTF_8)
                                    .replace("http://localhost:","https://localhost:").getBytes(StandardCharsets.UTF_8);
                            if (java.util.Arrays.equals(raw,files.get(row.path("file").asText()))) throw new IllegalStateException("Source mutation not effective");
                            Files.write(receipt.resolve(row.path("file").asText()),raw);row.put("sha256",hash(raw));
                        }
                    }
                    case "https-transcript-url" -> {
                        var old = changedEntries.getFirst();
                        changedEntries.set(0,new TranscriptEntry(old.id(),old.runId(),old.direction(),old.timestamp(),old.correlationId(),old.method(),
                                old.url().replace("http:","https:"),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),old.decodedSamlRef(),old.decodedSamlBytes(),old.contentType(),old.rawQuery(),old.samlSummary()));
                    }
                    case "invalid-target-response-signature" -> {
                        var reference = base.at("/phaseB/responseReference").asText();
                        var doc = com.samlscope.saml.normal.SecureXml.parse(bodies.get(reference));
                        doc.getDocumentElement().setAttribute("Destination", "http://invalid.example");
                        changedBodies.put(reference,com.samlscope.saml.normal.SecureXml.serialize(doc));
                    }
                }
                Files.write(receipt.resolve("http-scope.json"),JSON.mapper().writeValueAsBytes(scope));
                if (evaluate(temporary,base.deepCopy(),changedEntries,changedBodies,run,target) != Outcome.NOT_VERIFIED)
                    throw new IllegalStateException("Invalid transport scope accepted: "+mutation);
                checks.put(mutation,"NOT_VERIFIED");
            }
            var report = new LinkedHashMap<String, Object>();
            report.put("runId", run);
            report.put("productionOutcome", "SATISFIED_WITH_NOTE");
            report.put("tamperControls", checks);
            Files.write(output, JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
            System.out.println("Production reader SATISFIED_WITH_NOTE; " + checks.size() + " tamper controls rejected");
        } finally {
            try (var paths = Files.walk(temporary)) {
                for (var path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }
}
