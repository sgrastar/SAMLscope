package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.normal.SecureXml;

/** Local trusted-adapter input; intentionally has no HTTP submission route. */
final class AttributePolicyPreparationFile {
    private final Path directory;
    AttributePolicyPreparationFile(Path directory) { this.directory = directory.toAbsolutePath().normalize(); }

    Optional<AttributePolicyExperimentBinding.Preparation> read(CaseContext context, byte[] target,
            TranscriptContentReader content, AttributePolicyProtocolEvidence.Collected protocol) throws Exception {
        if (!context.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}")) throw new IllegalArgumentException("Invalid Run");
        var path = directory.resolve(context.runId() + ".json");
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return Optional.empty();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 1_048_576) {
            throw new IllegalArgumentException("Invalid preparation file");
        }
        var json = new JsonCodec().mapper();
        var receipt = json.readTree(Files.readAllBytes(path));
        require("samlscope-native-attribute-policy-receipt-v1".equals(receipt.path("schema").asText()));
        require(context.runId().equals(receipt.path("runId").asText()));
        require(hash(target).equals(receipt.path("targetMetadataSha256").asText()));
        require(SecureXml.parse(target).getDocumentElement().getAttribute("entityID").equals(receipt.path("targetEntityId").asText()));
        var preparation = json.treeToValue(receipt.path("preparation"), AttributePolicyExperimentBinding.Preparation.class);
        require(context.runId().equals(preparation.runId()));
        var entries = new HashMap<String, TranscriptEntry>();
        for (var entry : context.transcript().list(context.runId())) {
            require(context.runId().equals(entry.runId()) && entries.put(entry.id(), entry) == null);
        }
        var digests = new HashMap<String, String>();
        for (var original : receipt.path("rawEvidence")) {
            var ref = original.path("reference").asText();
            var digest = original.path("sha256").asText();
            require(digest.matches("[0-9a-f]{64}") && digests.put(ref, digest) == null);
            var entry = entries.get(ref);
            require(entry != null && entry.decodedSamlRef() != null && hash(content.readDecodedSaml(entry)).equals(digest));
        }
        // Every prepared exchange must be among the cryptographically collected originals.
        for (var binding : preparation.exchanges()) {
            var matches = protocol.observations().stream().filter(o -> o.evidence().size() == 4
                    && o.evidence().get(2).reference().equals(binding.requestReference())
                    && o.evidence().get(3).reference().equals(binding.responseReference())).toList();
            require(matches.size() == 1);
            for (var ref : matches.getFirst().evidence().subList(1, 4)) require(digests.containsKey(ref.reference()));
        }
        return Optional.of(preparation);
    }
    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Unbound native preparation"); }
}
