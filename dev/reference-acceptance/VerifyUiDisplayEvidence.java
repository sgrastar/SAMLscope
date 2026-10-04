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
public final class VerifyUiDisplayEvidence {
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
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-ui-display-receipt.json"));
        var temporary = Files.createTempDirectory("samlscope-ui-replay-");
        var receiptPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            var testCase = new UiDisplayBrowserEvidenceTestCase(e -> originals.get(e.id()), ignored -> target, temporary);
            var positive = testCase.observe(context);
            boolean missingEntity = positive.outcome() == Outcome.NOT_VERIFIED
                    && List.of("selection_unobserved_entity").equals(positive.details().get("evidence_issues"))
                    && positive.evidence().size() == 12;
            if (positive.outcome() != Outcome.SATISFIED && !missingEntity) {
                throw new IllegalStateException("Production evidence binding failed: " + positive.details());
            }
            for (String mutation : List.of("always-entity", "always-display", "hidden", "wrong-target", "wrong-request", "duplicate", "missing",
                    "wrong-template", "wrong-mapping", "wrong-language", "wrong-endpoint", "reordered", "wrong-browser-run")) {
                var receipt = (ObjectNode) mapper.readTree(receiptRaw);
                var rows = (ArrayNode) receipt.path("observations");
                if (mutation.equals("wrong-target")) receipt.put("targetMetadataSha256", "0".repeat(64));
                else if (mutation.equals("wrong-request")) ((ObjectNode) rows.get(0)).put("requestSha256", "0".repeat(64));
                else if (mutation.equals("duplicate")) rows.set(1, rows.get(0).deepCopy());
                else if (mutation.equals("missing")) rows.remove(1);
                else if (mutation.equals("wrong-template")) ((ObjectNode) receipt.path("nativePreparation")).put("templateUnchanged", false);
                else for (var row : rows) {
                    var browser = (ObjectNode) mapper.readTree(Base64.getDecoder().decode(row.path("browserBase64").asText()));
                    if (mutation.equals("hidden")) {
                        browser.put("status", "not-observed"); browser.remove("selected_candidate");
                    } else if (mutation.equals("wrong-mapping")) browser.put("candidate_mapping_sha256", "0".repeat(64));
                    else if (mutation.equals("wrong-language")) browser.put("preferred_language", "fr");
                    else if (mutation.equals("wrong-endpoint")) browser.put("expected_path", "/other");
                    else if (mutation.equals("reordered")) browser.put("observed_at", "2000-01-01T00:00:00Z");
                    else if (mutation.equals("wrong-browser-run")) browser.put("run_id", "other-run");
                    else {
                        browser.put("status", "observed");
                        browser.put("selected_candidate", mutation.equals("always-entity") ? "entity" : "display");
                    }
                    var changed = mapper.writeValueAsBytes(browser);
                    ((ObjectNode) row).put("browserBase64", Base64.getEncoder().encodeToString(changed));
                    ((ObjectNode) row).put("browserSha256", hash(changed));
                }
                Files.write(receiptPath, mapper.writeValueAsBytes(receipt));
                var negative = testCase.observe(context);
                var expected = mutation.equals("always-entity") ? Outcome.VIOLATED : Outcome.NOT_VERIFIED;
                if (negative.outcome() != expected) throw new IllegalStateException("Mutation unexpectedly classified: " + mutation + " " + negative.outcome());
                checks.put(mutation, negative.outcome().name());
            }
            var report = Map.of("run", run, "production_comparison", positive, "negative_controls", checks,
                    "receipt_sha256", hash(receiptRaw), "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                    "verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Production comparison " + positive.outcome() + "; " + checks.size() + " negative controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath); Files.deleteIfExists(temporary);
        }
    }
}
