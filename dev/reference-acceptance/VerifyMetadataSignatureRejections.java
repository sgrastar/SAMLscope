package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Replay the production native signature-rejection branch against retained product originals. */
public final class VerifyMetadataSignatureRejections {
    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]).toAbsolutePath().normalize();
        var mapper = new JsonCodec().mapper();
        var run = mapper.readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var originals = new HashMap<String, byte[]>();
        for (var row : mapper.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            if (!path.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Original path");
            var raw = Files.readAllBytes(path);
            if (!hash(raw).equals(row.path("sha256").asText())
                    || originals.put(row.path("id").asText(), raw) != null) throw new IllegalArgumentException("Original hash");
        }
        var entries = List.of(mapper.readValue(folder.resolve("transcript-before-receipt.json").toFile(),
                TranscriptEntry[].class));
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run");
                return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-metadata-rejection-receipt.json"));
        var signatureSource = folder.resolve("signature-verification-receipt-repaired-v2.json");
        if (!Files.exists(signatureSource)) signatureSource = folder.resolve("signature-verification-receipt.json");
        var signatureRaw = Files.readAllBytes(signatureSource);
        var temporary = Files.createTempDirectory("samlscope-native-signature-replay-");
        var receiptPath = temporary.resolve(run + ".json");
        var signaturePath = temporary.resolve(run + ".signature-verification.json");
        var reader = new MetadataRejectionEvidenceFile(temporary);
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            Files.write(signaturePath, signatureRaw);
            var proven = reader.rejectedVariants(context, target, entry -> originals.get(entry.id()));
            var base = (ObjectNode) mapper.readTree(receiptRaw);
            var expected = new TreeMap<String, String>();
            for (var row : base.path("rejections")) expected.put(row.path("variant").asText(),
                    "simplesamlphp-native-mdq-signature");
            if (!new TreeMap<>(proven).equals(expected) || expected.isEmpty()) throw new IllegalStateException("Unproven baseline");
            for (var mutation : List.of("run", "target", "adapter", "restored", "schema", "empty-rejections",
                    "raw-hash", "raw-ref", "duplicate-raw", "fixture-hash", "variant", "native-ref",
                    "native-hash", "config-ref", "effective-ref", "anchor-ref", "anchor-fingerprint",
                    "condition-issue", "missing-gate", "gate-control-missing",
                    "native-wrong-run", "native-wrong-variant", "native-accepted", "native-generic-error",
                    "native-wrong-source", "native-parser-only", "native-wrong-target")) {
                var changed = base.deepCopy();
                var changedOriginals = new HashMap<>(originals);
                var raws = (ArrayNode) changed.path("rawEvidence");
                var rejected = (ObjectNode) changed.path("rejections").get(0);
                for (var item : changed.path("rejections")) if ("unsigned".equals(item.path("variant").asText()))
                    rejected = (ObjectNode) item;
                var nativeRef = (ObjectNode) rejected.path("nativeRejection");
                var configuration = (ObjectNode) nativeRef.path("configurationReadBack");
                switch (mutation) {
                    case "run" -> changed.put("runId", "run_00000000000000000000000000");
                    case "target" -> changed.put("targetMetadataSha256", "0".repeat(64));
                    case "adapter" -> changed.put("evidenceAdapter", "unknown");
                    case "restored" -> changed.put("restored", false);
                    case "schema" -> changed.put("schema", "unknown");
                    case "empty-rejections" -> changed.set("rejections", mapper.createArrayNode());
                    case "raw-hash" -> ((ObjectNode) raws.get(0)).put("sha256", "0".repeat(64));
                    case "raw-ref" -> ((ObjectNode) raws.get(0)).put("reference", "tx_00000000000000000000000000");
                    case "duplicate-raw" -> raws.add(raws.get(0).deepCopy());
                    case "fixture-hash" -> rejected.put("fixtureSha256", "0".repeat(64));
                    case "variant" -> rejected.put("variant", "control");
                    case "native-ref" -> nativeRef.put("reference", "tx_00000000000000000000000000");
                    case "native-hash" -> nativeRef.put("detailSha256", "0".repeat(64));
                    case "config-ref" -> configuration.put("reference", "tx_00000000000000000000000000");
                    case "effective-ref" -> configuration.put("effectiveReference", "tx_00000000000000000000000000");
                    case "anchor-ref" -> configuration.put("trustAnchorReference", "tx_00000000000000000000000000");
                    case "anchor-fingerprint" -> configuration.put("trustAnchorCertificateSha256", "0".repeat(64));
                    case "condition-issue" -> { var issues = mapper.createArrayNode(); issues.add("unknown"); changed.set("conditionIssues", issues); }
                    case "missing-gate" -> Files.delete(signaturePath);
                    case "gate-control-missing" -> {
                        var signature = (ObjectNode) mapper.readTree(signatureRaw);
                        signature.set("negativeControls", mapper.createArrayNode());
                        Files.write(signaturePath, mapper.writeValueAsBytes(signature));
                    }
                    default -> {
                        var reference = nativeRef.path("reference").asText();
                        var record = (ObjectNode) mapper.readTree(originals.get(reference));
                        switch (mutation) {
                            case "native-wrong-run" -> record.put("runId", "run_00000000000000000000000000");
                            case "native-wrong-variant" -> record.put("variant", "control");
                            case "native-accepted" -> { record.put("outcome", "accepted"); record.put("signatureVerified", true); }
                            case "native-generic-error" -> ((ObjectNode) record.path("exception")).put("message", "generic HTTP 500");
                            case "native-wrong-source" -> ((ObjectNode) record.path("sourceSha256")).put("mdq", "0".repeat(64));
                            case "native-parser-only" -> record.put("genericParserOnly", true);
                            case "native-wrong-target" -> record.put("targetEntityId", "https://other.example/idp");
                            default -> throw new IllegalArgumentException(mutation);
                        }
                        var raw = mapper.writeValueAsBytes(record);
                        changedOriginals.put(reference, raw);
                        nativeRef.put("detailSha256", hash(raw));
                        for (var row : raws) if (reference.equals(row.path("reference").asText()))
                            ((ObjectNode) row).put("sha256", hash(raw));
                    }
                }
                Files.write(receiptPath, mapper.writeValueAsBytes(changed));
                boolean accepted;
                try { accepted = !reader.rejectedVariants(context, target, entry -> changedOriginals.get(entry.id())).isEmpty(); }
                catch (Exception unproven) { accepted = false; }
                if (accepted) throw new IllegalStateException("Invalid evidence accepted: " + mutation);
                checks.put(mutation, "NOT_VERIFIED");
                Files.write(signaturePath, signatureRaw);
            }
            var report = new LinkedHashMap<String, Object>();
            report.put("run", run);
            report.put("receipt_sha256", hash(receiptRaw));
            report.put("signature_receipt_sha256", hash(signatureRaw));
            report.put("target_metadata_sha256", hash(target));
            report.put("proven_variants", new TreeMap<>(proven));
            report.put("negative_controls", checks);
            report.put("verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Native signature rejection bound; " + checks.size() + " invalid controls rejected");
        } finally {
            Files.deleteIfExists(receiptPath);
            Files.deleteIfExists(signaturePath);
            Files.delete(temporary);
        }
    }
}
