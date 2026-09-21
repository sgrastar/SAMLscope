package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Read-only production replay, with temporary receipt mutations that must never produce SATISFIED. */
public final class VerifyNativeCertificateEvidence {
    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]);
        var mapper = new JsonCodec().mapper();
        var run = mapper.readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var originals = new HashMap<String, byte[]>();
        for (var row : mapper.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var file = folder.resolve(row.path("file").asText()).normalize();
            if (!file.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Original path mismatch");
            var raw = Files.readAllBytes(file);
            if (!hash(raw).equals(row.path("sha256").asText()) || originals.put(row.path("id").asText(), raw) != null) {
                throw new IllegalArgumentException("Original hash mismatch");
            }
        }
        var entries = List.of(mapper.readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run"); return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-native-certificate-receipt.json"));
        var temporary = Files.createTempDirectory("samlscope-certificate-replay-");
        var receiptPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            var reader = new NativeCertificateEvidenceFile(temporary);
            var samples = reader.read(context, target, e -> originals.get(e.id()));
            var outcomes = new LinkedHashMap<String, CaseOutcome>();
            for (var id : NativeCertificateComparison.CASES.stream().sorted().toList()) {
                var outcome = NativeCertificateComparison.evaluate(id, samples, List.of());
                if (outcome.outcome() != Outcome.VIOLATED) throw new IllegalStateException("Unexpected native comparison: " + outcome);
                outcomes.put(id, outcome);
            }
            for (String mutation : List.of("wrong-target", "wrong-run", "not-restored", "missing", "duplicate",
                    "wrong-original", "signature-disabled", "wrong-certificate", "changed-policy", "wrong-event-id",
                    "wrong-event-time", "wrong-event-issuer", "generic-http-error", "missing-event", "wrong-response")) {
                var receipt = (ObjectNode) mapper.readTree(receiptRaw);
                var conditions = (ArrayNode) receipt.path("conditions");
                var first = (ObjectNode) conditions.get(0);
                var attrs = (ObjectNode) first.path("nativeClient").path("attributes");
                var negative = (ObjectNode) first.path("negative");
                var event = (ObjectNode) negative.path("nativeEvent");
                switch (mutation) {
                    case "wrong-target" -> receipt.put("targetMetadataSha256", "0".repeat(64));
                    case "wrong-run" -> receipt.put("runId", "other");
                    case "not-restored" -> receipt.put("restored", false);
                    case "missing" -> conditions.remove(1);
                    case "duplicate" -> conditions.set(1, first.deepCopy());
                    case "wrong-original" -> ((ObjectNode) receipt.path("rawEvidence").get(0)).put("sha256", "0".repeat(64));
                    case "signature-disabled" -> attrs.put("saml.client.signature", "false");
                    case "wrong-certificate" -> attrs.put("saml.signing.certificate", "invalid");
                    case "changed-policy" -> attrs.put("saml.signature.algorithm", "RSA_SHA1");
                    case "wrong-event-id" -> event.put("request_id", "unrelated");
                    case "wrong-event-time" -> event.put("event_time", 0);
                    case "wrong-event-issuer" -> event.put("issuer", "other-client");
                    case "generic-http-error" -> ((ObjectNode) negative.path("nativeHttp")).put("response_status", 500);
                    case "missing-event" -> negative.remove("nativeEvent");
                    case "wrong-response" -> ((ObjectNode) first.path("positive")).put("responseReference", "other");
                    default -> throw new IllegalStateException();
                }
                Files.write(receiptPath, mapper.writeValueAsBytes(receipt));
                boolean rejected = false;
                try { reader.read(context, target, e -> originals.get(e.id())); }
                catch (Exception unproven) { rejected = true; }
                if (!rejected) throw new IllegalStateException("Invalid evidence accepted: " + mutation);
                checks.put(mutation, "REJECTED");
            }
            var report = Map.of("run", run, "production_comparison", outcomes, "negative_controls", checks,
                    "receipt_sha256", hash(receiptRaw), "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                    "verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Production comparison bound; " + checks.size() + " invalid evidence controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath); Files.deleteIfExists(temporary);
        }
    }
}
