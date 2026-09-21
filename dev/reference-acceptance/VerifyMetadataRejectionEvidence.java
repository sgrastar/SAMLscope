package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/**
 * Read-only production replay of the native metadata-rejection adapter: the real receipt must bind the
 * Run original, and every temporary mutation of that receipt must fail to prove a rejection. No Run
 * verdict is adopted here.
 */
public final class VerifyMetadataRejectionEvidence {
    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    static boolean provesRejection(MetadataRejectionEvidenceFile reader, com.samlscope.core.caseexec.CaseContext context,
            byte[] target, TranscriptContentReader content) {
        try {
            return !reader.rejectedVariants(context, target, content).isEmpty();
        } catch (Exception unproven) {
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]);
        var variants = (args.length > 2 ? args[2] : "expired").split(",");
        var adapter = args.length > 3 ? args[3] : "shibboleth-resolver";
        var expectedVariants = new java.util.TreeMap<String, String>();
        for (var name : variants) expectedVariants.put(name, adapter);
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
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run");
                return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        TranscriptContentReader content = entry -> originals.get(entry.id());
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-metadata-rejection-receipt.json"));
        var temporary = Files.createTempDirectory("samlscope-rejection-replay-");
        var receiptPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            var reader = new MetadataRejectionEvidenceFile(temporary);
            var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                    TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
            var proven = reader.rejectedVariants(context, target, content);
            if (!expectedVariants.equals(new java.util.TreeMap<>(proven))) {
                throw new IllegalStateException("Production receipt did not prove the rejection: " + proven);
            }
            var base = (ObjectNode) mapper.readTree(receiptRaw);
            for (String mutation : List.of("wrong-target", "wrong-run", "not-restored", "unknown-adapter",
                    "empty-raw-evidence", "unknown-original-ref", "wrong-original-hash", "duplicate-original",
                    "empty-rejections", "wrong-reject-variant", "wrong-fixture-hash", "detail-not-hex",
                    "wrong-source", "condition-issues", "wrong-schema")) {
                var receipt = base.deepCopy();
                var raw = (ArrayNode) receipt.path("rawEvidence");
                var rejections = (ArrayNode) receipt.path("rejections");
                var rejection = (ObjectNode) rejections.get(0);
                var nativeRejection = (ObjectNode) rejection.path("nativeRejection");
                switch (mutation) {
                    case "wrong-target" -> receipt.put("targetMetadataSha256", "0".repeat(64));
                    case "wrong-run" -> receipt.put("runId", "run_00000000000000000000000000");
                    case "not-restored" -> receipt.put("restored", false);
                    case "unknown-adapter" -> receipt.put("evidenceAdapter", "unknown-adapter");
                    case "empty-raw-evidence" -> receipt.set("rawEvidence", mapper.createArrayNode());
                    case "unknown-original-ref" -> ((ObjectNode) raw.get(0)).put("reference", "tx_UNKNOWNORIGINALREFERENCE");
                    case "wrong-original-hash" -> ((ObjectNode) raw.get(0)).put("sha256", "0".repeat(64));
                    case "duplicate-original" -> raw.set(1, raw.get(0).deepCopy());
                    case "empty-rejections" -> receipt.set("rejections", mapper.createArrayNode());
                    case "wrong-reject-variant" -> rejection.put("variant", "__mutation-unrelated-variant__");
                    case "wrong-fixture-hash" -> rejection.put("fixtureSha256", "0".repeat(64));
                    case "detail-not-hex" -> nativeRejection.put("detailSha256", "not-a-sha256");
                    case "wrong-source" -> nativeRejection.put("source", "other-adapter");
                    case "condition-issues" -> { var issues = mapper.createArrayNode(); issues.add("unsupported"); receipt.set("conditionIssues", issues); }
                    case "wrong-schema" -> receipt.put("schema", "other-schema");
                    default -> throw new IllegalStateException();
                }
                Files.write(receiptPath, mapper.writeValueAsBytes(receipt));
                if (provesRejection(reader, context, target, content)) {
                    throw new IllegalStateException("Invalid evidence accepted: " + mutation);
                }
                checks.put(mutation, "NOT_VERIFIED");
            }
            Files.deleteIfExists(receiptPath);
            if (provesRejection(reader, context, target, content)) {
                throw new IllegalStateException("Missing receipt proved a rejection");
            }
            checks.put("missing-file", "NOT_VERIFIED");
            var incomplete = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(),
                    TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, false);
            if (provesRejection(reader, incomplete, target, content)) {
                throw new IllegalStateException("Incomplete transcript proved a rejection");
            }
            checks.put("transcript-incomplete", "NOT_VERIFIED");
            var report = Map.of("run", run, "variant", String.join(",", variants), "adapter", adapter,
                    "proven_variants", proven, "negative_controls", checks,
                    "receipt_sha256", hash(receiptRaw),
                    "target_metadata_sha256", hash(target),
                    "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                    "verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Rejection evidence bound; " + checks.size() + " invalid evidence controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath);
            Files.deleteIfExists(temporary);
        }
    }
}
