package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.plan.TargetRole;
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
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Read-only production-reader replay with fail-closed receipt and original tamper controls. */
public final class VerifyMetadataSignatureEvidence {
    private static final String CAMPAIGN = "metadata-fixture-refresh";

    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static boolean proves(Path receiptPath, ObjectNode receipt, Map<String, byte[]> originals,
            List<TranscriptEntry> entries, String run, byte[] target, boolean complete) throws Exception {
        var mapper = new JsonCodec().mapper();
        Files.write(receiptPath, mapper.writeValueAsBytes(receipt));
        var recorder = new TranscriptRecorder() {
            @Override public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run");
                return entries;
            }
            @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            @Override public TranscriptEntry updateSamlAnalysis(
                    String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        TranscriptContentReader content = entry -> originals.get(entry.id());
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(),
                com.samlscope.core.plan.TestPlan.Parameters.defaults(),
                com.samlscope.core.plan.TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                recorder, complete);
        try {
            return new MetadataSignatureVerificationEvidenceFile(receiptPath.getParent()).verify(
                    context, target, content, CAMPAIGN) != null;
        } catch (Exception unproven) {
            return false;
        }
    }

    private static void requireRejected(String name, Path receiptPath, ObjectNode receipt,
            Map<String, byte[]> originals, List<TranscriptEntry> entries, String run, byte[] target,
            Map<String, String> checks) throws Exception {
        if (proves(receiptPath, receipt, originals, entries, run, target, true)) {
            throw new IllegalStateException("Invalid evidence accepted: " + name);
        }
        checks.put(name, "NOT_VERIFIED");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("usage: <campaign-folder> <output-report>");
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]).toAbsolutePath().normalize();
        if (Files.exists(output)) throw new IllegalArgumentException("Refusing to overwrite report");
        var mapper = new JsonCodec().mapper();
        var run = mapper.readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var originals = new HashMap<String, byte[]>();
        for (var row : mapper.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var source = folder.resolve(row.path("file").asText()).normalize();
            if (!source.getParent().equals(folder.resolve("decoded"))) {
                throw new IllegalArgumentException("Original path mismatch");
            }
            var raw = Files.readAllBytes(source);
            if (!hash(raw).equals(row.path("sha256").asText())
                    || originals.put(row.path("id").asText(), raw) != null) {
                throw new IllegalArgumentException("Original hash or identity mismatch");
            }
        }
        var transcriptPath = folder.resolve("transcript-before-receipt.json");
        var entries = List.of(mapper.readValue(transcriptPath.toFile(), TranscriptEntry[].class));
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receiptSource = folder.resolve("signature-verification-receipt-repaired-v2.json");
        if (!Files.exists(receiptSource)) receiptSource = folder.resolve("signature-verification-receipt.json");
        var receiptRaw = Files.readAllBytes(receiptSource);
        var base = (ObjectNode) mapper.readTree(receiptRaw);
        var temporary = Files.createTempDirectory("samlscope-signature-replay-");
        var receiptPath = temporary.resolve(run + ".signature-verification.json");
        var checks = new LinkedHashMap<String, String>();
        try {
            if (!proves(receiptPath, base, originals, entries, run, target, true)) {
                throw new IllegalStateException("Production receipt did not prove signature validation");
            }
            for (var mutation : List.of(
                    "schema", "run", "campaign", "target-hash", "target-entity", "adapter",
                    "config-ref", "config-hash", "effective-ref", "anchor-ref", "anchor-fingerprint",
                    "source-hash", "positive-response", "positive-embedded", "positive-native-ref",
                    "invalid-native-ref", "invalid-anchor", "embedded-anchor", "restoration-ref",
                    "missing-control", "duplicate-control")) {
                var changed = base.deepCopy();
                var controls = (ArrayNode) changed.path("negativeControls");
                var invalid = (ObjectNode) controls.get(0);
                var embedded = (ObjectNode) controls.get(1);
                switch (mutation) {
                    case "schema" -> changed.put("schema", "other-schema");
                    case "run" -> changed.put("runId", "run_00000000000000000000000000");
                    case "campaign" -> changed.put("campaignId", "other-campaign");
                    case "target-hash" -> changed.put("targetMetadataSha256", "0".repeat(64));
                    case "target-entity" -> changed.put("targetEntityId", "https://invalid.example/idp");
                    case "adapter" -> changed.put("evidenceAdapter", "unknown-adapter");
                    case "config-ref" -> ((ObjectNode) changed.path("configurationReadBack"))
                            .put("reference", "tx_00000000000000000000000000");
                    case "config-hash" -> ((ObjectNode) changed.path("configurationReadBack"))
                            .put("sha256", "0".repeat(64));
                    case "effective-ref" -> ((ObjectNode) changed.path("configurationReadBack"))
                            .put("effectiveReference", "tx_00000000000000000000000000");
                    case "anchor-ref" -> ((ObjectNode) changed.path("configurationReadBack"))
                            .put("trustAnchorReference", "tx_00000000000000000000000000");
                    case "anchor-fingerprint" -> ((ObjectNode) changed.path("configurationReadBack"))
                            .put("trustAnchorCertificateSha256", "0".repeat(64));
                    case "source-hash" -> ((ObjectNode) changed.path("nativeSources").path("adapter"))
                            .put("sha256", "0".repeat(64));
                    case "positive-response" -> ((ObjectNode) changed.path("positive"))
                            .put("responseSha256", "0".repeat(64));
                    case "positive-embedded" -> ((ObjectNode) changed.path("positive"))
                            .put("embeddedKeyInfoCertificateSha256", "0".repeat(64));
                    case "positive-native-ref" -> ((ObjectNode) changed.path("positive"))
                            .put("nativeValidationReference", "tx_00000000000000000000000000");
                    case "invalid-native-ref" -> invalid.put(
                            "nativeRejectionReference", "tx_00000000000000000000000000");
                    case "invalid-anchor" -> ((ObjectNode) invalid.path("configurationReadBack"))
                            .put("trustAnchorCertificateSha256", "0".repeat(64));
                    case "embedded-anchor" -> ((ObjectNode) embedded.path("configurationReadBack"))
                            .put("trustAnchorCertificateSha256", "0".repeat(64));
                    case "restoration-ref" -> ((ObjectNode) changed.path("restorationReadBack"))
                            .put("finalReference", "tx_00000000000000000000000000");
                    case "missing-control" -> controls.remove(1);
                    case "duplicate-control" -> controls.set(1, controls.get(0).deepCopy());
                    default -> throw new IllegalStateException();
                }
                requireRejected(mutation, receiptPath, changed, originals, entries, run, target, checks);
            }

            // Updating a receipt hash cannot legitimize a semantically forged product original.
            for (var mutation : List.of(
                    "accepted-with-signature-false", "accepted-generic-parser", "accepted-wrong-call-path",
                    "rejection-changed-to-accepted", "configuration-self-report", "restoration-byte-change")) {
                var changedReceipt = base.deepCopy();
                var changedOriginals = new HashMap<>(originals);
                if (mutation.startsWith("accepted-")) {
                    var positive = (ObjectNode) changedReceipt.path("positive");
                    var id = positive.path("nativeValidationReference").asText();
                    var record = (ObjectNode) mapper.readTree(changedOriginals.get(id));
                    if ("accepted-with-signature-false".equals(mutation)) record.put("signatureVerified", false);
                    else if ("accepted-generic-parser".equals(mutation)) record.put("genericParserOnly", true);
                    else ((ArrayNode) record.path("callPath")).set(2,
                            mapper.getNodeFactory().textNode("SimpleSAML\\Metadata\\SAMLParser::parseString"));
                    var raw = mapper.writeValueAsBytes(record);
                    changedOriginals.put(id, raw);
                    positive.put("nativeValidationSha256", hash(raw));
                } else if ("rejection-changed-to-accepted".equals(mutation)) {
                    var invalid = (ObjectNode) changedReceipt.path("negativeControls").get(0);
                    var id = invalid.path("nativeRejectionReference").asText();
                    var record = (ObjectNode) mapper.readTree(changedOriginals.get(id));
                    record.put("outcome", "accepted");
                    record.put("signatureVerified", true);
                    record.putNull("exception");
                    var raw = mapper.writeValueAsBytes(record);
                    changedOriginals.put(id, raw);
                    invalid.put("nativeRejectionSha256", hash(raw));
                } else if ("configuration-self-report".equals(mutation)) {
                    var config = (ObjectNode) changedReceipt.path("configurationReadBack");
                    var id = config.path("reference").asText();
                    var raw = "{\"signatureVerification\":\"enabled\"}".getBytes(StandardCharsets.UTF_8);
                    changedOriginals.put(id, raw);
                    config.put("sha256", hash(raw));
                } else {
                    var restoration = (ObjectNode) changedReceipt.path("restorationReadBack");
                    var id = restoration.path("finalReference").asText();
                    var raw = "<?php // not the original configuration\n".getBytes(StandardCharsets.UTF_8);
                    changedOriginals.put(id, raw);
                    restoration.put("finalSha256", hash(raw));
                }
                requireRejected(mutation, receiptPath, changedReceipt, changedOriginals, entries,
                        run, target, checks);
            }

            Files.deleteIfExists(receiptPath);
            if (Files.exists(receiptPath)) throw new IllegalStateException();
            checks.put("missing-receipt", "NOT_VERIFIED");
            if (proves(receiptPath, base, originals, entries, run, target, false)) {
                throw new IllegalStateException("Incomplete transcript accepted");
            }
            checks.put("transcript-incomplete", "NOT_VERIFIED");
            if (!proves(receiptPath, base, originals, entries, run, target, true)) {
                throw new IllegalStateException("Baseline replay changed after controls");
            }
            var report = new LinkedHashMap<String, Object>();
            report.put("schema", "samlscope-metadata-signature-replay-v1");
            report.put("run", run);
            report.put("adapter", base.path("evidenceAdapter").asText());
            report.put("anchor_certificate_sha256",
                    base.at("/configurationReadBack/trustAnchorCertificateSha256").asText());
            report.put("embedded_keyinfo_certificate_sha256",
                    base.at("/positive/embeddedKeyInfoCertificateSha256").asText());
            report.put("receipt_sha256", hash(receiptRaw));
            report.put("target_metadata_sha256", hash(target));
            report.put("transcript_sha256", hash(Files.readAllBytes(transcriptPath)));
            report.put("negative_controls", checks);
            report.put("verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report),
                    StandardOpenOption.CREATE_NEW);
            System.out.println("Signature evidence bound; " + checks.size()
                    + " invalid evidence controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath);
            Files.deleteIfExists(temporary);
        }
    }
}
