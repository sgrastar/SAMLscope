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

/** Read-only replay of native receipt and cryptographic evidence through the production comparison. */
public final class VerifyRelyingPartyAttributeExperiment {
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
        var collected = RelyingPartyAttributeProtocolEvidence.collect(context, e -> originals.get(e.id()), target, (requested, variant) -> {
            try {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong key scope");
                var keyDirectory = data.resolve("keys").resolve(plan);
                var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyDirectory.resolve("signing-key.pk8"))));
                var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(Files.readAllBytes(keyDirectory.resolve("signing-certificate.der"))));
                return Optional.of(new PlanCredentials(key, certificate));
            } catch (Exception unavailable) { return Optional.empty(); }
        });
        var preparation = new RelyingPartyAttributePreparationFile(Path.of(args[3])).read(context, target,
                e -> originals.get(e.id()), collected);
        var outcome = RelyingPartyAttributeExperimentBinding.evaluate(collected, preparation);
        if (outcome.outcome() != com.samlscope.core.evaluation.Outcome.SATISFIED) {
            throw new IllegalStateException("Native comparison incomplete: " + outcome.details());
        }
        var controls = new ArrayList<String>();
        var good = preparation.orElseThrow();
        for (String mutation : List.of("missing", "duplicate", "wrong-response", "mixed-policy", "mixed-login", "mixed-input")) {
            var changed = new ArrayList<>(good.exchanges());
            var first = changed.getFirst();
            if (mutation.equals("missing")) changed.removeLast();
            else if (mutation.equals("duplicate")) changed.set(1, first);
            else {
                var second = changed.get(1);
                changed.set(1, new RelyingPartyAttributeExperimentBinding.ExchangePreparation(second.condition(),
                    second.requestReference(), mutation.equals("wrong-response") ? first.responseReference() : second.responseReference(),
                    mutation.equals("mixed-policy") ? "f".repeat(64) : second.policyFingerprint(),
                    mutation.equals("mixed-login") ? "f".repeat(64) : second.loginInputFingerprint(),
                    mutation.equals("mixed-input") ? "f".repeat(64) : second.stableInputFingerprint()));
            }
            var rejected = RelyingPartyAttributeExperimentBinding.evaluate(collected,
                Optional.of(new RelyingPartyAttributeExperimentBinding.Preparation(good.runId(), good.experimentId(), changed)));
            if (rejected.outcome() != com.samlscope.core.evaluation.Outcome.NOT_VERIFIED) throw new IllegalStateException("Control accepted: " + mutation);
            controls.add(mutation);
        }
        var observations = collected.observations().stream().map(o -> Map.of(
                "variant", o.variant(), "entity_id", o.entityId(), "metadata_sha256", o.metadataHash(),
                "markers", new TreeSet<>(o.attributes().markers()), "evidence", o.evidence())).toList();
        boolean sameInput = collected.observations().stream().map(o -> o.attributes().attributeInputFingerprint()).distinct().count() == 1;
        json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(), Map.of(
                "run", run, "observations", observations, "issues", collected.issues(),
                "same_attribute_input", sameInput, "authenticated_principal_verified", false,
                "verdict_adopted", false, "comparison", Map.of("outcome", outcome.outcome().name(), "reason_code", outcome.reasonCode(), "evidence", outcome.evidence(), "negative_controls_rejected", controls),
                "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json")))));
        System.out.println("Collected " + observations.size() + " exchanges; issues=" + collected.issues());
        if (!collected.issues().isEmpty() || observations.size() != 3) throw new IllegalStateException("Incomplete production observation");
    }
}
