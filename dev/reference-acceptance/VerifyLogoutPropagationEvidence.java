package com.samlscope.runner.cases;

import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.store.JsonCodec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Read-only replay of the production continuation oracle against saved SAML originals. */
public final class VerifyLogoutPropagationEvidence {
    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 2) throw new IllegalArgumentException("usage: <evidence-folder> <output-report>");
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]).toAbsolutePath().normalize();
        if (Files.exists(output)) throw new IllegalArgumentException("Refusing to overwrite report");
        var json = new JsonCodec().mapper();
        var result = json.readTree(folder.resolve("result.json").toFile());
        var run = result.at("/run/id").asText();
        if (run.isBlank()) throw new IllegalArgumentException("Run missing");
        var entries = List.of(json.readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var originals = new HashMap<String, byte[]>();
        for (var item : json.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(item.path("file").asText()).normalize();
            if (!path.startsWith(folder) || !Files.isRegularFile(path)) {
                throw new IllegalArgumentException("Original path invalid");
            }
            var raw = Files.readAllBytes(path);
            if (!hash(raw).equals(item.path("sha256").asText())
                    || originals.put(item.path("id").asText(), raw) != null) {
                throw new IllegalArgumentException("Original hash or identity mismatch");
            }
        }
        var transcript = new TranscriptRecorder() {
            @Override public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Run mismatch");
                return entries;
            }
            @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            @Override public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        TranscriptContentReader content = entry -> originals.get(entry.id());
        var outcome = new LogoutTranscriptProfileCase(
                LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE, List.of()).evaluate(run, transcript, content);
        var report = new LinkedHashMap<String, Object>();
        report.put("schema", "samlscope-slo-propagation-replay-v1");
        report.put("runId", run);
        report.put("transcriptSha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))));
        report.put("originalManifestSha256", hash(Files.readAllBytes(folder.resolve("decoded-manifest.json"))));
        try (var source = LogoutTranscriptProfileCase.class.getResourceAsStream("LogoutTranscriptProfileCase.class")) {
            if (source == null) throw new IllegalStateException("Reader class unavailable");
            report.put("readerClassSha256", hash(source.readAllBytes()));
        }
        report.put("caseId", "IIP-IDP17-r-idp-01");
        report.put("outcome", outcome);
        Files.write(output, json.writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
        System.out.println(run + " " + outcome.outcome() + " " + outcome.reasonCode());
    }
}
