package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.PlanCredentials;
import java.nio.file.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;

/** Read-only replay of saved originals through the production collector. Does not evaluate a case. */
public final class ObserveNameIdOmissionExperiment {
    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var data = Path.of(args[1]);
        var json = new JsonCodec().mapper();
        var created = json.readTree(folder.resolve("created.json").toFile());
        var run = created.at("/run/id").asText();
        var plan = json.readTree(folder.resolve("plan.json").toFile()).at("/plan/plan/id").asText();
        if (!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")) throw new IllegalArgumentException("Invalid plan");
        var originals = new HashMap<String, byte[]>();
        for (var entry : json.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path = folder.resolve(entry.path("file").asText()).normalize();
            if (!path.startsWith(folder)) throw new IllegalArgumentException("Invalid original path");
            var bytes = Files.readAllBytes(path);
            if (!hash(bytes).equals(entry.path("sha256").asText())
                    || originals.put(entry.path("id").asText(), bytes) != null) throw new IllegalArgumentException("Original mismatch");
        }
        var entries = List.of(json.readValue(folder.resolve("transcript.json").toFile(), TranscriptEntry[].class));
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String requested) {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run");
                return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                throw new UnsupportedOperationException();
            }
        };
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var selections = new ArrayList<NameIdOmissionProtocolEvidence.Exchange>();
        var preparedEntries = entries.stream().filter(e -> "MetadataPrepared".equals(e.samlSummary().get("type"))
                && "preloaded-aggregate".equals(e.samlSummary().get("variant"))).toList();
        if (preparedEntries.size() != 1) throw new IllegalArgumentException("Ambiguous prepared metadata");
        for (var observation : json.readTree(folder.resolve("observations.json").toFile())) {
            var selected = new HashSet<String>();
            observation.path("new_transcript_ids").forEach(n -> selected.add(n.asText()));
            var requests = entries.stream().filter(e -> selected.contains(e.id()) && e.direction() == Direction.OUTBOUND
                    && "AuthnRequest".equals(e.samlSummary().get("type"))).toList();
            var responses = entries.stream().filter(e -> selected.contains(e.id()) && e.direction() == Direction.INBOUND
                    && "Response".equals(e.samlSummary().get("type"))).toList();
            if (requests.size() != 1 || responses.size() != 1) throw new IllegalArgumentException("Incomplete exchange originals");
            var condition = switch (observation.path("condition").asText()) {
                case "baseline" -> NameIdOmissionComparison.Condition.BASELINE;
                case "name-id-disabled" -> NameIdOmissionComparison.Condition.NAME_ID_DISABLED;
                default -> throw new IllegalArgumentException("Unknown condition");
            };
            selections.add(new NameIdOmissionProtocolEvidence.Exchange(condition, preparedEntries.getFirst().id(),
                    requests.getFirst().id(), responses.getFirst().id()));
        }
        var collected = NameIdOmissionProtocolEvidence.collect(context, e -> originals.get(e.id()), target, (requested, variant) -> {
            try {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong key scope");
                var keyDirectory = data.resolve("keys").resolve(plan);
                var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyDirectory.resolve("signing-key.pk8"))));
                var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(Files.readAllBytes(keyDirectory.resolve("signing-certificate.der"))));
                return Optional.of(new PlanCredentials(key, certificate));
            } catch (Exception unavailable) { return Optional.empty(); }
        }, selections);
        var observations = collected.observations().stream().map(o -> Map.of(
                "condition", o.condition().name(), "entity_id", o.entityId(), "metadata_sha256", o.metadataHash(),
                "presence", o.presence().name(), "request_fingerprint", o.requestFingerprint(), "evidence", o.evidence())).toList();
        var comparison = new LinkedHashMap<String,Object>();
        if (args.length > 3) {
            var preparation = new NameIdOmissionPreparationFile(Path.of(args[3])).read(context, target, e -> originals.get(e.id()));
            var outcome = NameIdOmissionExperimentBinding.evaluate(collected, preparation);
            if (outcome.outcome() != com.samlscope.core.evaluation.Outcome.SATISFIED) throw new IllegalStateException("Comparison unproven");
            var prepared = preparation.orElseThrow();
            var negative = new ArrayList<String>();
            for (String mutation : List.of("missing", "duplicate", "wrong-response", "mixed-login", "mixed-input")) {
                var changed = new ArrayList<>(prepared.exchanges());
                var last = changed.getLast();
                switch (mutation) {
                    case "missing" -> changed.removeLast();
                    case "duplicate" -> changed.add(last);
                    case "wrong-response", "mixed-login", "mixed-input" -> changed.set(1,
                        new NameIdOmissionExperimentBinding.ExchangePreparation(last.condition(), last.metadataReference(),
                            last.requestReference(), mutation.equals("wrong-response") ? "wrong-response" : last.responseReference(),
                            mutation.equals("mixed-login") ? "0".repeat(64) : last.loginInputFingerprint(),
                            mutation.equals("mixed-input") ? "0".repeat(64) : last.stableInputFingerprint()));
                }
                var rejected = NameIdOmissionExperimentBinding.evaluate(collected, Optional.of(
                    new NameIdOmissionExperimentBinding.Preparation(prepared.runId(), prepared.experimentId(), changed)));
                if (rejected.outcome() != com.samlscope.core.evaluation.Outcome.NOT_VERIFIED) throw new IllegalStateException("Negative control not rejected");
                negative.add(mutation);
            }
            comparison.put("outcome",outcome.outcome().name());comparison.put("evidence",outcome.evidence());
            comparison.put("negative_controls_rejected",negative);
        }
        json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(), Map.of(
                "run", run, "observations", observations, "issues", collected.issues(), "comparison", comparison,
                "verdict_adopted", false, "target_metadata_sha256", hash(target),
                "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json")))));
        System.out.println("Collected " + observations.size() + " exchanges; issues=" + collected.issues());
        if (!collected.issues().isEmpty() || observations.size() != 2) throw new IllegalStateException("Incomplete production observation");
    }
}
