package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import org.yaml.snakeyaml.Yaml;

/** Replay the approved case implementations against one complete native metadata campaign. */
public final class VerifyMetadataSignatureCampaign {
    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static Map<String, TestCase> cases(Path receipts, byte[] target, TranscriptContentReader content, Path catalog) throws Exception {
        var options = new org.yaml.snakeyaml.LoaderOptions();
        options.setMaxAliasesForCollections(5_000);
        options.setAllowDuplicateKeys(false);
        var definitions = CaseDefinitionCatalogMapper.fromDocument(new Yaml(
                new org.yaml.snakeyaml.constructor.SafeConstructor(options)).load(Files.readString(catalog)));
        var result = new LinkedHashMap<String, TestCase>();
        var id = "IIP-MD03-a-idp-01";
        result.put(id, new MetadataRejectionConfigurationTestCase(
                MetadataConfigCaseFactory.create(definitions.require(id)).orElseThrow(), content, run -> target, receipts));
        result.put("IIP-MD05-am-idp-01", new MetadataConsumerObservationTestCase("IIP-MD05-am-idp-01", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM, content, run -> target, receipts));
        result.put("IIP-MD05-an-idp-01", new MetadataConsumerObservationTestCase("IIP-MD05-an-idp-01", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT, content, run -> target, receipts));
        result.put("IIP-MD05-ao-idp-01", new MetadataConsumerObservationTestCase("IIP-MD05-ao-idp-01", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO, content, run -> target, receipts));
        return result;
    }
    private static DefaultCaseContext context(String run, List<TranscriptEntry> entries) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String requested) { if (!run.equals(requested)) throw new IllegalArgumentException(); return entries; }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new UnsupportedOperationException(); }
        };
        return new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
    }
    private static com.samlscope.core.evaluation.CaseOutcome evaluate(TestCase testcase, DefaultCaseContext context) {
        var state = ((CaseStep.AwaitConfig) testcase.start(context)).next();
        return ((CaseStep.Finish) testcase.resume(context, state, new CaseEvent.ConfigConfirmed())).outcome();
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]).toAbsolutePath().normalize();
        var catalog = Path.of(args[2]).toAbsolutePath().normalize();
        var mapper = new JsonCodec().mapper().enable(
                com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var run = mapper.readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var originals = new HashMap<String, byte[]>();
        for (var row : mapper.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(row.path("file").asText()).normalize();
            if (!path.getParent().equals(folder.resolve("decoded"))) throw new IllegalArgumentException("Original path");
            var raw = Files.readAllBytes(path);
            if (!hash(raw).equals(row.path("sha256").asText()) || originals.put(row.path("id").asText(), raw) != null)
                throw new IllegalArgumentException("Original hash");
        }
        var entries = List.of(mapper.readValue(folder.resolve("transcript-before-receipt.json").toFile(), TranscriptEntry[].class));
        var signatureSource = folder.resolve("signature-verification-receipt-repaired-v2.json");
        if (!Files.exists(signatureSource)) signatureSource = folder.resolve("signature-verification-receipt.json");
        var signatureRaw = Files.readAllBytes(signatureSource);
        var rejectionRaw = Files.readAllBytes(folder.resolve("qualified-metadata-rejection-receipt.json"));
        var temporary = Files.createTempDirectory("samlscope-signature-campaign-replay-");
        var signaturePath = temporary.resolve(run + ".signature-verification.json");
        var rejectionPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        var outcomes = new LinkedHashMap<String, Object>();
        try {
            Files.write(signaturePath, signatureRaw);
            Files.write(rejectionPath, rejectionRaw);
            var implementations = cases(temporary, target, entry -> originals.get(entry.id()), catalog);
            var baseContext = context(run, entries);
            for (var item : implementations.entrySet()) {
                var outcome = evaluate(item.getValue(), baseContext);
                if (outcome.outcome() == Outcome.NOT_VERIFIED) throw new IllegalStateException("Incomplete campaign: " + item.getKey());
                outcomes.put(item.getKey(), Map.of("outcome", outcome.outcome().name(), "reason_code", outcome.reasonCode(),
                        "evidence", outcome.evidence(), "details", outcome.details()));
                Files.delete(signaturePath);
                if (evaluate(item.getValue(), baseContext).outcome() != Outcome.NOT_VERIFIED)
                    throw new IllegalStateException("Signature gate missing: " + item.getKey());
                checks.put(item.getKey() + ":missing-signature-gate", "NOT_VERIFIED");
                Files.write(signaturePath, signatureRaw);
            }
            Files.delete(rejectionPath);
            if (evaluate(implementations.get("IIP-MD03-a-idp-01"), baseContext).outcome() != Outcome.NOT_VERIFIED)
                throw new IllegalStateException("Bare signature gate proves MD03.a");
            checks.put("IIP-MD03-a-idp-01:missing-native-refusals", "NOT_VERIFIED");
            Files.write(rejectionPath, rejectionRaw);
            var baselineRequests = entries.stream().filter(entry -> entry.direction() == Direction.OUTBOUND
                    && "AuthnRequest".equals(entry.samlSummary().get("type"))
                    && "control".equals(entry.samlSummary().get("variant")))
                    .map(entry -> entry.samlSummary().get("id")).collect(java.util.stream.Collectors.toSet());
            var noBaseline = entries.stream().filter(entry -> !(entry.direction() == Direction.INBOUND
                    && "Response".equals(entry.samlSummary().get("type"))
                    && baselineRequests.contains(entry.samlSummary().get("inResponseTo")))).toList();
            for (var item : implementations.entrySet()) {
                if (evaluate(item.getValue(), context(run, noBaseline)).outcome() != Outcome.NOT_VERIFIED)
                    throw new IllegalStateException("Missing baseline accepted: " + item.getKey());
                checks.put(item.getKey() + ":missing-baseline-success", "NOT_VERIFIED");
            }
            var report = new LinkedHashMap<String, Object>();
            report.put("run", run); report.put("target_metadata_sha256", hash(target));
            report.put("catalog_sha256", hash(Files.readAllBytes(catalog)));
            report.put("signature_receipt_sha256", hash(signatureRaw)); report.put("rejection_receipt_sha256", hash(rejectionRaw));
            report.put("cases", outcomes); report.put("negative_controls", checks); report.put("verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Production cases replayed; " + checks.size() + " invalid controls rejected");
        } finally {
            Files.deleteIfExists(signaturePath); Files.deleteIfExists(rejectionPath); Files.delete(temporary);
        }
    }
}
