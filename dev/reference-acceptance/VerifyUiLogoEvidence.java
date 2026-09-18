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
public final class VerifyUiLogoEvidence {
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
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-ui-logo-receipt.json"));
        var temporary = Files.createTempDirectory("samlscope-ui-replay-");
        var receiptPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            var testCase = new UiLogoBrowserEvidenceTestCase(e -> originals.get(e.id()), ignored -> target, temporary);
            var positive = testCase.observe(context);
            if (positive.outcome() != Outcome.SATISFIED) throw new IllegalStateException("Production positive replay failed: " + positive.details());
            for (String mutation : List.of("always-default", "always-localized", "hidden", "wrong-target", "wrong-request", "duplicate", "missing")) {
                var receipt = (ObjectNode) mapper.readTree(receiptRaw);
                var rows = (ArrayNode) receipt.path("observations");
                if (mutation.equals("wrong-target")) receipt.put("targetMetadataSha256", "0".repeat(64));
                else if (mutation.equals("wrong-request")) ((ObjectNode) rows.get(0)).put("requestSha256", "0".repeat(64));
                else if (mutation.equals("duplicate")) rows.set(1, rows.get(0).deepCopy());
                else if (mutation.equals("missing")) rows.remove(1);
                else for (var row : rows) {
                    var browser = (ObjectNode) mapper.readTree(Base64.getDecoder().decode(row.path("browserBase64").asText()));
                    if (mutation.equals("hidden")) browser.put("status", "not-observed");
                    else browser.put("selected_candidate", mutation.equals("always-default") ? "default" : "localized");
                    var changed = mapper.writeValueAsBytes(browser);
                    ((ObjectNode) row).put("browserBase64", Base64.getEncoder().encodeToString(changed));
                    ((ObjectNode) row).put("browserSha256", hash(changed));
                }
                Files.write(receiptPath, mapper.writeValueAsBytes(receipt));
                var negative = testCase.observe(context);
                if (negative.outcome() != Outcome.NOT_VERIFIED) throw new IllegalStateException("Mutation accepted: " + mutation);
                checks.put(mutation, negative.outcome().name());
            }
            var report = Map.of("run", run, "production_comparison", positive, "negative_controls", checks,
                    "receipt_sha256", hash(receiptRaw), "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                    "verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Production comparison satisfied; " + checks.size() + " negative controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath); Files.deleteIfExists(temporary);
        }
    }
}
