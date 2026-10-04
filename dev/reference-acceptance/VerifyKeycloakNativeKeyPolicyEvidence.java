package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Read-only production replay, with temporary receipt mutations that must never produce SATISFIED. */
public final class VerifyKeycloakNativeKeyPolicyEvidence {
    static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    static final class RoleFallback implements com.samlscope.core.caseexec.TestCase, ConfigurationPrompt {
        public String id(){return MetadataRoleSigningTransportEvidence.ID;}
        public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Native role signing evidence";}
        public com.samlscope.core.caseexec.CaseStep start(com.samlscope.core.caseexec.CaseContext c){throw new UnsupportedOperationException();}
        public com.samlscope.core.caseexec.CaseStep resume(com.samlscope.core.caseexec.CaseContext c,com.samlscope.core.caseexec.CaseState s,com.samlscope.core.caseexec.CaseEvent e){throw new UnsupportedOperationException();}
    }
    public static void main(String[] args) throws Exception {
        var folder = Path.of(args[0]).toAbsolutePath().normalize();
        var output = Path.of(args[1]);
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
                if (!run.equals(requested)) throw new IllegalArgumentException("Wrong Run"); return entries;
            }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        var context = new DefaultCaseContext(run, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var target = Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receiptRaw = Files.readAllBytes(folder.resolve("qualified-metadata-key-receipt.json"));
        var temporaryRoot=Files.createTempDirectory("samlscope-key-replay-");
        var temporary=Files.createDirectory(temporaryRoot.resolve("metadata-key-evidence"));
        var receiptPath = temporary.resolve(run + ".json");
        var checks = new LinkedHashMap<String, String>();
        try {
            Files.write(receiptPath, receiptRaw);
            var reader = new MetadataKeySelectionEvidenceFile(temporary);
            var outcomes = new LinkedHashMap<String, CaseOutcome>();
            var qualified = new ArrayList<String>();
            for(var id:MetadataKeySelectionComparison.CASES.stream().sorted().toList()) {
                var required=MetadataKeySelectionComparison.required(id);
                var base=(ObjectNode)mapper.readTree(receiptRaw);
                var selected=mapper.createArrayNode();
                for(var row:base.path("conditions"))if(required.contains(row.path("variant").asText()))selected.add(row);
                base.set("conditions",selected);
                Files.write(receiptPath,mapper.writeValueAsBytes(base));
                CaseOutcome outcome;
                try { outcome=MetadataKeySelectionComparison.evaluate(id,reader.read(context,target,e->originals.get(e.id()),required),List.of()); }
                catch(Exception incomplete) {
                    outcome=MetadataKeySelectionComparison.evaluate(id,List.of(),List.of("native_originals_unproven"));
                }
                outcomes.put(id,outcome);
                if(outcome.outcome()==Outcome.NOT_VERIFIED)continue;
                for(String mutation:List.of("wrong-target","wrong-run","not-restored","missing","duplicate",
                        "wrong-import-hash","wrong-import-entity","import-not-verified","wrong-original",
                        "signature-disabled","wrong-certificate","changed-policy","wrong-event-id",
                        "wrong-event-time","wrong-event-issuer","generic-http-error","missing-event","wrong-response")) {
                    var receipt=base.deepCopy();var conditions=(ArrayNode)receipt.path("conditions");
                    var first=(ObjectNode)conditions.get(0);
                    boolean simpleSaml="simplesamlphp-native-http".equals(receipt.path("evidenceAdapter").asText());
                    boolean shibboleth="shibboleth-audit".equals(receipt.path("evidenceAdapter").asText());
                    var imported=(ObjectNode)first.path("nativeImport");
                    var attrs=simpleSaml?imported:shibboleth?mapper.createObjectNode():(ObjectNode)first.path("nativeClient").path("attributes");
                    var negative=(ObjectNode)first.path("negative");
                    var event=simpleSaml?(ObjectNode)negative.path("nativeHttp"):shibboleth?(ObjectNode)negative.path("nativeAudit"):(ObjectNode)negative.path("nativeEvent");
                    switch(mutation) {
                        case "wrong-target" -> receipt.put("targetMetadataSha256","0".repeat(64));
                        case "wrong-run" -> receipt.put("runId","other");
                        case "not-restored" -> receipt.put("restored",false);
                        case "missing" -> conditions.remove(0);
                        case "duplicate" -> conditions.set(1,first.deepCopy());
                        case "wrong-import-hash" -> ((ObjectNode)first.path("nativeImport")).put("fixtureSha256","0".repeat(64));
                        case "wrong-import-entity" -> ((ObjectNode)first.path("nativeImport")).put("entityId","other");
                        case "import-not-verified" -> ((ObjectNode)first.path("nativeImport")).put("readbackVerified",false);
                        case "wrong-original" -> ((ObjectNode)receipt.path("rawEvidence").get(0)).put("sha256","0".repeat(64));
                        case "signature-disabled" -> {if(simpleSaml)imported.put("signaturePolicy",false);else if(shibboleth){event.put("event","");event.put("status","Success");}else attrs.put("saml.client.signature","false");}
                        case "wrong-certificate" -> {if(shibboleth)imported.put("configurationSha256","invalid");else attrs.put(simpleSaml?"parserOutputSha256":"saml.signing.certificate","invalid");}
                        case "changed-policy" -> {if(shibboleth)imported.put("source","unrelated-policy");else attrs.put(simpleSaml?"source":"saml.signature.algorithm","unrelated-policy");}
                        case "wrong-event-id" -> event.put("request_id","unrelated");
                        case "wrong-event-time" -> {if(simpleSaml||shibboleth)event.put(simpleSaml?"observed_at":"timestamp","1970-01-01T00:00:00Z");else event.put("event_time",0);}
                        case "wrong-event-issuer" -> {if(shibboleth)event.put("sp","other-client");else if(simpleSaml)imported.put("entityId","other-client");else event.put("issuer","other-client");}
                        case "generic-http-error" -> {if(shibboleth)event.put("binding","Redirect");else ((ObjectNode)negative.path("nativeHttp")).put("response_status",simpleSaml?400:500);}
                        case "missing-event" -> {if(simpleSaml)event.remove("native_signature_rejection");else if(shibboleth)negative.remove("nativeAudit");else negative.remove("nativeEvent");}
                        case "wrong-response" -> ((ObjectNode)first.path("positive")).put("responseReference","other");
                        default -> throw new IllegalStateException();
                    }
                    Files.write(receiptPath,mapper.writeValueAsBytes(receipt));
                    boolean rejected=false;
                    try { rejected=MetadataKeySelectionComparison.evaluate(id,reader.read(context,target,e->originals.get(e.id()),required),List.of()).outcome()==Outcome.NOT_VERIFIED; }
                    catch(Exception unproven) { rejected=true; }
                    if(!rejected)throw new IllegalStateException("Invalid evidence accepted: "+id+":"+mutation);
                    checks.put(id+":"+mutation,"NOT_VERIFIED");
                }
                qualified.add(id);
            }
            Files.write(receiptPath,receiptRaw);
            var roleCase=new MetadataKeySelectionConfigurationTestCase(new RoleFallback(),e->originals.get(e.id()),r->target,temporary);
            var role=roleCase.observe(context);
            outcomes.put(MetadataRoleSigningTransportEvidence.ID,role);
            if(role.outcome()!=Outcome.SATISFIED_WITH_NOTE)throw new IllegalStateException("Role signing campaign incomplete: "+role);
            qualified.add(MetadataRoleSigningTransportEvidence.ID);
            var nativeReference=mapper.readTree(receiptRaw).at("/roleSigningTransport/reference").asText();
            var nativeRaw=originals.get(nativeReference);
            for(var mutation:List.of("missing-transport","wrong-transport-hash","wrong-native-run","wrong-native-target",
                    "tls-configured","http-disabled","extra-tls-port","wrong-image","missing-xml-control","invented-native-reference","hidden-tls-in-full-text","removed-native-property","wrong-full-text-hash")) {
                var mutated=(ObjectNode)mapper.readTree(receiptRaw);
                var ref=(ObjectNode)mutated.path("roleSigningTransport");
                var nativeJson=(ObjectNode)mapper.readTree(nativeRaw);
                switch(mutation) {
                    case "missing-transport" -> mutated.remove("roleSigningTransport");
                    case "wrong-transport-hash" -> ref.put("sha256","0".repeat(64));
                    case "wrong-native-run" -> nativeJson.put("runId","other");
                    case "wrong-native-target" -> nativeJson.put("targetEntityId","other");
                    case "tls-configured" -> ((ObjectNode)nativeJson.path("nativeConfiguration")).putArray("tlsConfiguration").add("kc.https-certificate-file = cert.pem (ENV)");
                    case "http-disabled" -> ((ObjectNode)nativeJson.path("nativeConfiguration")).putArray("selectedConfiguration").add("kc.http-enabled = false (ENV)");
                    case "extra-tls-port" -> ((ObjectNode)nativeJson.at("/runtime/portBindings")).putArray("8443/tcp");
                    case "wrong-image" -> ((ObjectNode)nativeJson.path("runtime")).put("image","other");
                    case "missing-xml-control" -> {var rows=(ArrayNode)mutated.path("conditions");for(int n=rows.size()-1;n>=0;n--)if("certificate-runtime-other-key".equals(rows.get(n).path("variant").asText()))rows.remove(n);}
                    case "invented-native-reference" -> ref.put("reference","missing");
                    case "wrong-full-text-hash" -> ((ObjectNode)nativeJson.path("nativeConfiguration")).put("originalTextSha256","0".repeat(64));
                    case "hidden-tls-in-full-text", "removed-native-property" -> {
                        var cfg=(ObjectNode)nativeJson.path("nativeConfiguration");
                        var text=cfg.path("originalText").asText();
                        text=mutation.equals("hidden-tls-in-full-text")?text+"\tkc.https-certificate-file = cert.pem (ENV)\n":text.replaceAll("(?m)^.*kc\\.db =.*\n", "");
                        cfg.put("originalText",text).put("originalTextSha256",hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                        ref.put("configurationTextSha256",cfg.path("originalTextSha256").asText());
                    }
                }
                if(Set.of("wrong-native-run","wrong-native-target","tls-configured","http-disabled","extra-tls-port","wrong-image","hidden-tls-in-full-text","removed-native-property","wrong-full-text-hash").contains(mutation)) {
                    var raw=mapper.writeValueAsBytes(nativeJson);originals.put(nativeReference,raw);ref.put("sha256",hash(raw));
                }
                Files.write(receiptPath,mapper.writeValueAsBytes(mutated));
                if(roleCase.observe(context).outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid role evidence accepted: "+mutation);
                checks.put(MetadataRoleSigningTransportEvidence.ID+":"+mutation,"NOT_VERIFIED");
                originals.put(nativeReference,nativeRaw);
            }
            var report = Map.of("run", run, "production_comparison", outcomes, "negative_controls", checks,
                    "receipt_sha256", hash(receiptRaw), "transcript_sha256", hash(Files.readAllBytes(folder.resolve("transcript.json"))),
                    "qualified_cases", qualified, "verdict_adopted", false);
            Files.write(output, mapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(report), StandardOpenOption.CREATE_NEW);
            System.out.println("Production comparison bound; " + checks.size() + " invalid evidence controls rejected; no Run verdict adopted");
        } finally {
            Files.deleteIfExists(receiptPath); Files.deleteIfExists(temporary); Files.deleteIfExists(temporaryRoot);
        }
    }
}
