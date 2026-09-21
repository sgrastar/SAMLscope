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
public final class ObserveAuthnContextExperiment {
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
        var selections = new ArrayList<AuthnContextProtocolEvidence.Exchange>();
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
            if (requests.size() != 1 || responses.size() != 1) continue;
            var condition = observation.path("condition").asText().split("-", 2)[1];
            selections.add(new AuthnContextProtocolEvidence.Exchange(condition, preparedEntries.getFirst().id(),
                    requests.getFirst().id(), responses.getFirst().id()));
        }
        var collected = AuthnContextProtocolEvidence.collect(context, e -> originals.get(e.id()), target, (requested, variant) -> {
            try {
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong key scope");
                var keyDirectory = data.resolve("keys").resolve(plan);
                var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(keyDirectory.resolve("signing-key.pk8"))));
                var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(
                        new java.io.ByteArrayInputStream(Files.readAllBytes(keyDirectory.resolve("signing-certificate.der"))));
                return Optional.of(new PlanCredentials(key, certificate));
            } catch (Exception unavailable) { return Optional.empty(); }
        }, selections);
        var observations = collected.observations().stream().map(o -> {
            var value = new LinkedHashMap<String,Object>();
            value.put("condition",o.condition());value.put("entity_id",o.entityId());
            value.put("metadata_sha256",o.metadataHash());value.put("request_fingerprint",o.requestFingerprint());
            value.put("request",o.request());value.put("response_kind",o.response().kind().name());
            value.put("class_reference",o.response().classReference().orElse(""));
            value.put("declaration_reference",o.response().declarationReference().orElse(""));
            value.put("evidence",o.evidence());return value;
        }).toList();
        var comparisons=new LinkedHashMap<String,Object>();
        if(args.length>3) for(var suffix:List.of("ga","gb","gc","gj")) {
            String caseId="IIP-SSO01-"+suffix+"-idp-01";
            var prepared=new AuthnContextPreparationFile(Path.of(args[3])).read(caseId,context,target,e->originals.get(e.id())).orElseThrow();
            var selected=new HashSet<String>();for(var e:prepared.allExchanges())selected.add(e.requestReference());
            var subset=new AuthnContextProtocolEvidence.Collected(collected.runId(),collected.observations().stream()
                .filter(o->selected.contains(o.evidence().get(2).reference())).toList(),collected.issues());
            var outcome=AuthnContextExperimentBinding.evaluate(subset,prepared);
            var negative=new ArrayList<String>();
            for(var mutation:List.of("missing","duplicate","wrong-response","unverified-controls")) {
                var exchanges=new ArrayList<>(prepared.exchanges());var nativeContext=prepared.nativeContext();
                switch(mutation) {
                    case "missing" -> exchanges.removeLast();
                    case "duplicate" -> exchanges.add(exchanges.getFirst());
                    case "wrong-response" -> {
                        var first=exchanges.getFirst();exchanges.set(0,new AuthnContextExperimentBinding.Exchange(first.condition(),first.metadataReference(),first.requestReference(),"wrong-response"));
                    }
                    default -> nativeContext=new AuthnContextComparison.Preparation(nativeContext.experiment(),nativeContext.entityId(),nativeContext.loginFingerprint(),
                        nativeContext.configurationFingerprint(),nativeContext.contexts(),AuthnContextComparison.Controls.UNVERIFIED);
                }
                var rejected=AuthnContextExperimentBinding.evaluate(subset,new AuthnContextExperimentBinding.Preparation(prepared.runId(),caseId,nativeContext,exchanges,prepared.availabilityControls()));
                if(rejected.outcome()!=com.samlscope.core.evaluation.Outcome.NOT_VERIFIED)throw new IllegalStateException("Binding negative control not rejected");
                negative.add(mutation);
            }
            comparisons.put(caseId,Map.of("outcome",outcome.outcome().name(),"reason_code",outcome.reasonCode(),"details",outcome.details(),
                "evidence",outcome.evidence(),"negative_controls_rejected",negative));
        }
        json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(), Map.of(
                "run",run,"observations",observations,"issues",collected.issues(),"verdict_adopted",false,"comparisons",comparisons,
                "target_metadata_sha256",hash(target),"transcript_sha256",hash(Files.readAllBytes(folder.resolve("transcript.json")))));
        System.out.println("Cryptographically verified " + observations.size() + " exchanges; issues=" + collected.issues());
    }
}
