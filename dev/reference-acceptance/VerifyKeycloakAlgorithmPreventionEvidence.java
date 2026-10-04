package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Production-reader replay. Private keys stay in the Suite's data volume. */
public final class VerifyKeycloakAlgorithmPreventionEvidence {
    private static final JsonCodec JSON = new JsonCodec();
    private static final Map<String, String> checks = new LinkedHashMap<>();

    private static Optional<AlgorithmPreventionEvidenceFile.Proof> prove(ObjectNode receipt, String run,
            List<TranscriptEntry> entries, Map<String, byte[]> originals, byte[] target,
            PrivateKey key, boolean complete, String profile) throws Exception {
        var recorder = new TranscriptRecorder() {
            @Override public List<TranscriptEntry> list(String id) { return entries; }
            @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            @Override public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(),
                com.samlscope.core.plan.TestPlan.Parameters.defaults(),
                com.samlscope.core.plan.TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
        return new KeycloakAlgorithmPreventionEvidenceFile(entry -> originals.get(entry.id()),
                id -> target, id -> Optional.of(key), id -> profile).read(context, receipt, "replay-only");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException("usage: <campaign-folder> <suite-data> <output>");
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[2]);
        if (Files.exists(output)) throw new IllegalArgumentException("Refusing to overwrite report");
        var receipt = (ObjectNode) JSON.mapper().readTree(folder.resolve("algorithm-prevention-receipt.json").toFile());
        var run = receipt.path("runId").asText();
        var plan = JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/planId").asText();
        if (plan.isBlank()) plan = JSON.mapper().readTree(folder.resolve("plan.json").toFile()).at("/plan/plan/id").asText();
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(
                Path.of(args[1]).resolve("keys").resolve(plan).resolve("signing-key.pk8"))));
        var entries = List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var originals = new HashMap<String, byte[]>();
        for (var row : JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            if (!path.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Unsafe original path");
            var raw = Files.readAllBytes(path);
            var hash = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw));
            if (!hash.equals(row.path("sha256").asText()) || originals.put(row.path("id").asText(), raw) != null)
                throw new IllegalArgumentException("Original inventory/hash differs");
        }
        var positive = prove(receipt, run, entries, originals, target, key, true, "browser_sso_idp");
        if (positive.isEmpty() || positive.orElseThrow().result() != AlgorithmPreventionEvidenceFile.Result.SATISFIED)
            throw new IllegalStateException("Complete native campaign did not prove prevention");
        checks.put("complete-native-campaign", "SATISFIED");
        var mutations = new LinkedHashMap<String, java.util.function.Consumer<ObjectNode>>();
        mutations.put("wrong-run", value -> value.put("runId", "run_00000000000000000000000000"));
        mutations.put("wrong-profile", value -> value.put("profile", "ecp_idp"));
        mutations.put("target-hash", value -> value.put("targetMetadataSha256", "0".repeat(64)));
        mutations.put("missing-phase", value -> value.withArray("phases").remove(6));
        mutations.put("different-client", value -> value.put("clientDatabaseId", "00000000-0000-0000-0000-000000000000"));
        mutations.put("restoration-original", value -> value.withObject("/configuration/restoredPolicies").put("reference", "tx_00000000000000000000000000"));
        mutations.put("original-hash", value -> value.withObject("/configuration/originalProfiles").put("sha256", "0".repeat(64)));
        mutations.put("set-not-added", value -> ((ObjectNode) value.withArray("phases").get(1)).set("policiesOriginal", value.withArray("phases").get(0).path("policiesOriginal")));
        mutations.put("wrong-rejection", value -> ((ObjectNode) value.withArray("phases").get(1)).set("clientUpdateOriginal", value.withArray("phases").get(0).path("clientUpdateOriginal")));
        mutations.put("duplicate-operation", value -> value.withArray("phases").set(3, value.withArray("phases").get(0)));
        mutations.put("human-operation", value -> value.withObject("/operationCounts").put("humanOperations", 1));
        mutations.put("protocol-count", value -> value.withObject("/operationCounts").put("protocolOperations", 6));
        for (var item : mutations.entrySet()) {
            ObjectNode changed = receipt.deepCopy();
            item.getValue().accept(changed);
            if (prove(changed, run, entries, originals, target, key, true, "browser_sso_idp").isPresent())
                throw new IllegalStateException("Invalid receipt accepted: " + item.getKey());
            checks.put(item.getKey(), "NOT_VERIFIED");
        }
        for (var descriptor : List.of(receipt.at("/configuration/originalProfiles"), receipt.at("/configuration/restoredPolicies"),
                receipt.at("/phases/1/clientUpdateOriginal"), receipt.at("/phases/2/policiesOriginal"))) {
            var changed = new HashMap<>(originals);
            changed.remove(descriptor.path("reference").asText());
            if (prove(receipt, run, entries, changed, target, key, true, "browser_sso_idp").isPresent())
                throw new IllegalStateException("Missing native original accepted");
            checks.put("missing-original-" + checks.size(), "NOT_VERIFIED");
        }
        var pair = java.security.KeyPairGenerator.getInstance("RSA"); pair.initialize(2048);
        if (prove(receipt, run, entries, originals, target, pair.generateKeyPair().getPrivate(), true, "browser_sso_idp").isPresent())
            throw new IllegalStateException("Wrong Run decryption key accepted");
        checks.put("wrong-run-key", "NOT_VERIFIED");
        if (prove(receipt, run, entries, originals, target, key, false, "browser_sso_idp").isPresent())
            throw new IllegalStateException("Incomplete transcript accepted");
        checks.put("incomplete-transcript", "NOT_VERIFIED");
        if (prove(receipt, run, entries, originals, target, key, true, "ecp_idp").isPresent())
            throw new IllegalStateException("Browser campaign reused for ECP");
        checks.put("ecp-not-proven-by-browser", "NOT_VERIFIED");
        JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(), Map.of("runId", run,
                "checks", checks, "privateKeyExported", false, "plaintextPersisted", false,
                "result", positive.orElseThrow().result().name(), "evidenceCount", positive.orElseThrow().evidence().size()));
        System.out.println("Native algorithm prevention replay passed: " + checks.size());
    }
}
