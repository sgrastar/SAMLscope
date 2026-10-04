package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Replay the archived production reader on originals, then recomputed-JSON and crypto countercontrols. */
public final class VerifyKeycloakAlgorithmPreferenceEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static TranscriptEntry replace(TranscriptEntry e,String run,java.time.Instant time,Map<String,Object> summary) {
        return new TranscriptEntry(e.id(),run,e.direction(),time,e.correlationId(),e.method(),e.url(),e.status(),e.headers(),
            e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),summary);
    }
    private static CaseOutcome observe(String id,String run,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,Path directory) {
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String value){if(!run.equals(value))throw new IllegalArgumentException();return entries;}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        return new KeycloakAlgorithmPreferenceEvidenceFile(directory,e->bodies.get(e.id())).evaluate(id,context,target);
    }
    private static void mutateOriginal(ObjectNode reference,Map<String,byte[]> bodies,java.util.function.Consumer<ObjectNode> mutate)throws Exception {
        var id=reference.path("reference").asText();var original=(ObjectNode)JSON.mapper().readTree(bodies.get(id));
        mutate.accept(original);var raw=JSON.mapper().writeValueAsBytes(original);bodies.put(id,raw);reference.put("sha256",sha(raw));
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=3)throw new IllegalArgumentException("folder data output required");
        var folder=Path.of(args[0]);var output=Path.of(args[2]);if(Files.exists(output))throw new IllegalArgumentException("Immutable output exists");
        var run=JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var byId=new HashMap<String,TranscriptEntry>();for(var e:entries)if(byId.put(e.id(),e)!=null||!e.runId().equals(run))throw new IllegalArgumentException("Foreign transcript");
        var originals=new HashMap<String,byte[]>();
        for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path=folder.resolve(row.path("file").asText()).normalize();if(!path.getParent().equals(folder.resolve("decoded")))throw new IllegalArgumentException();
            var raw=Files.readAllBytes(path);var e=byId.get(row.path("id").asText());
            if(e==null||!sha(raw).equals(row.path("sha256").asText())||raw.length!=e.decodedSamlBytes()||originals.put(e.id(),raw)!=null)throw new IllegalArgumentException("Original mismatch");
        }
        var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var receiptRaw=Files.readAllBytes(folder.resolve("qualified-receipt.json"));
        var receipt=(ObjectNode)JSON.mapper().readTree(receiptRaw);
        var directory=folder.resolve("replay-receipt");Files.createDirectory(directory);var receiptPath=directory.resolve(run+".algorithm-preference.json");
        var reports=new TreeMap<String,Object>();var checks=new TreeMap<String,Map<String,String>>();
        Files.write(receiptPath,receiptRaw);
        var complete=new TreeMap<String,String>();
        for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES) {
            var result=observe(id,run,entries,originals,target,directory);
            var expected=id.equals("IIP-MD05-e7-idp-01")?"metadata.algorithms.producer-preference-unproven":"metadata.algorithms.local-policy-unverified";
            if(result.outcome()!=Outcome.NOT_VERIFIED||!expected.equals(result.reasonCode())||!Boolean.TRUE.equals(result.details().get("signature_capability_controls_verified"))
                ||!Boolean.FALSE.equals(result.details().get("local_policy_verified")))throw new IllegalStateException("Complete diagnostic "+id+" "+result);
            complete.put(id,result.outcome().name());reports.put(id,Map.of("outcome",result.outcome().name(),"reasonCode",result.reasonCode(),"details",result.details(),"evidence",result.evidence()));
        }
        checks.put("complete-native-campaign",complete);
        for(var name:List.of("nonempty-native-policy","altered-native-selector-class","explicit-matrix-selector","foreign-run-original",
            "foreign-target-configuration","changed-capability-encryption-policy","changed-capability-signing-certificate",
            "missing-individual-type-member","foreign-control-campaign","corrupt-native-capability-signature",
            "unusable-alternative-capability","readback-after-operation","restoration-claims-only","restoration-before-end",
            "changed-global-policy","split-matrix-campaign","combined-types-masquerading-as-individual")) {
            var changed=receipt.deepCopy();var bodies=new HashMap<>(originals);var list=new ArrayList<>(entries);
            var matrix=(ArrayNode)changed.path("matrix");var cap=(ObjectNode)changed.path("capabilities").get(1);
            switch(name) {
                case "nonempty-native-policy","altered-native-selector-class" -> {
                    for(var slot:List.of("policyBefore","policyAfter"))mutateOriginal((ObjectNode)changed.path(slot),bodies,original->{
                        if(name.equals("nonempty-native-policy"))((ObjectNode)original.path("clientPolicies")).putArray("policies").addObject().put("name","unproven-local-prohibition");
                        else ((ObjectNode)original.path("nativeClasses")).put("org/keycloak/protocol/saml/SamlClient.class","ZmFrZQ==");
                    });
                }
                case "explicit-matrix-selector" -> mutateOriginal((ObjectNode)matrix.get(0).path("configuration"),bodies,o->((ObjectNode)o.at("/client/samlAttributes")).put("saml.signature.algorithm","RSA_SHA256"));
                case "foreign-run-original" -> mutateOriginal((ObjectNode)cap.path("configuration"),bodies,o->o.put("runId","run_00000000000000000000000000"));
                case "foreign-target-configuration" -> mutateOriginal((ObjectNode)cap.path("configuration"),bodies,o->o.put("targetMetadataSha256","0".repeat(64)));
                case "changed-capability-encryption-policy" -> mutateOriginal((ObjectNode)cap.path("configuration"),bodies,o->((ObjectNode)o.at("/client/samlAttributes")).put("saml.encrypt","false"));
                case "changed-capability-signing-certificate" -> mutateOriginal((ObjectNode)cap.path("configuration"),bodies,o->((ObjectNode)o.at("/client/samlAttributes")).put("saml.signing.certificate","unrelated"));
                case "missing-individual-type-member" -> matrix.remove(matrix.size()-1);
                case "foreign-control-campaign" -> {
                    var response=byId.get(cap.path("responseReference").asText());var request=list.stream().filter(e->"AuthnRequest".equals(e.samlSummary().get("type"))
                        &&Objects.equals(e.samlSummary().get("id"),response.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();
                    var first=byId.get(matrix.get(0).path("responseReference").asText());var source=list.stream().filter(e->"AuthnRequest".equals(e.samlSummary().get("type"))
                        &&Objects.equals(e.samlSummary().get("id"),first.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();
                    var summary=new HashMap<>(request.samlSummary());summary.put("metadataSignatureGroup",source.samlSummary().get("metadataSignatureGroup"));
                    list.set(list.indexOf(request),replace(request,run,request.timestamp(),summary));
                }
                case "corrupt-native-capability-signature" -> {
                    var id=cap.path("responseReference").asText();var doc=SecureXml.parse(bodies.get(id));var signature=doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);
                    var raw=Base64.getMimeDecoder().decode(signature.getTextContent());raw[0]^=1;signature.setTextContent(Base64.getEncoder().encodeToString(raw));bodies.put(id,SecureXml.serialize(doc));
                }
                case "unusable-alternative-capability" -> list.remove(byId.get(cap.path("responseReference").asText()));
                case "readback-after-operation","restoration-before-end" -> {
                    var ref=name.equals("readback-after-operation")?matrix.get(0).path("configuration"):changed.path("restoration");
                    var e=byId.get(ref.path("reference").asText());var time=name.equals("readback-after-operation")?entries.getLast().timestamp().plusSeconds(1):entries.getFirst().timestamp();
                    list.set(list.indexOf(e),replace(e,run,time,e.samlSummary()));
                }
                case "restoration-claims-only" -> mutateOriginal((ObjectNode)changed.path("restoration"),bodies,o->o.putArray("remainingClients").add("unrestored"));
                case "changed-global-policy" -> mutateOriginal((ObjectNode)changed.path("policyAfter"),bodies,o->o.put("additionalNativeChange",true));
                case "split-matrix-campaign" -> {
                    var response=byId.get(matrix.get(1).path("responseReference").asText());var request=list.stream().filter(e->"AuthnRequest".equals(e.samlSummary().get("type"))
                        &&Objects.equals(e.samlSummary().get("id"),response.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();
                    var summary=new HashMap<>(request.samlSummary());summary.put("metadataSignatureGroup","poll_unrelated:1");
                    list.set(list.indexOf(request),replace(request,run,request.timestamp(),summary));
                }
                case "combined-types-masquerading-as-individual" -> {
                    var row=(ObjectNode)matrix.get(matrix.size()-1);row.put("variant","algorithm-entity-digest-order-512-256");
                }
                default -> throw new IllegalArgumentException(name);
            }
            Files.write(receiptPath,JSON.mapper().writeValueAsBytes(changed));var outcomes=new TreeMap<String,String>();
            for(var id:KeycloakAlgorithmPreferenceEvidenceFile.CASES) {
                var result=observe(id,run,list,bodies,target,directory);if(result.outcome()!=Outcome.NOT_VERIFIED
                    ||!"metadata.algorithms.native-preference-incomplete".equals(result.reasonCode()))throw new IllegalStateException("Invalid diagnostic evidence accepted "+name+" "+id+" "+result);
                outcomes.put(id,result.outcome().name());
            }
            checks.put(name,outcomes);
        }
        var outputReport=new TreeMap<String,Object>();outputReport.put("runId",run);outputReport.put("cases",reports);outputReport.put("checks",checks);
        outputReport.put("privateKeyExported",false);outputReport.put("configurationWrites",0);
        Files.write(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(outputReport));
        System.out.println("Production native preference remains NOT_VERIFIED; "+(checks.size()-1)+" invalid diagnostic evidence controls rejected");
    }
}
