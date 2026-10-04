package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.net.URI;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

/** Run with a read-only data volume: replay originals and reject receipt/fixture substitutions. */
public final class VerifyNativeSignedRequestProtocol {
    public static void main(String[] args)throws Exception {
        var folder=Path.of(args[0]).toAbsolutePath().normalize();var data=Path.of(args[1]);var output=Path.of(args[2]);
        var json=new JsonCodec().mapper();
        var run=json.readTree(folder.resolve("created.json").toFile()).path("run").path("id").asText();
        var plan=json.readTree(folder.resolve("plan.json").toFile()).path("plan").path("plan").path("id").asText();
        if(!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Invalid plan");
        for(var name:List.of("signing-key.pk8","signing-certificate.der"))
            if(!Files.isRegularFile(data.resolve("keys").resolve(plan).resolve(name)))throw new IllegalStateException("Existing Run key required");
        var credentials=new FilePlanKeyStore(data,Clock.systemUTC()).getOrCreate(plan);
        var originals=new HashMap<String,byte[]>();
        for(var row:json.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var file=folder.resolve(row.path("file").asText()).normalize();if(!file.startsWith(folder))throw new IllegalArgumentException("Invalid original path");
            var raw=Files.readAllBytes(file);
            if(!hash(raw).equals(row.path("sha256").asText()) || originals.put(row.path("id").asText(),raw)!=null)throw new IllegalArgumentException("Original mismatch");
        }
        var entries=List.of(json.readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException("Wrong Run");return entries;}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var results=new LinkedHashMap<String,Object>();
        for(var caseId:List.of(IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE)) {
            var receipts=folder.resolve("preparation-receipts");var name=run+"-"+caseId+".json";var rawReceipt=Files.readAllBytes(receipts.resolve(name));
            var receipt=json.readTree(rawReceipt);var valid=receipt.path("exchanges").get(0);
            var request=SecureXml.parse(originals.get(valid.path("requestReference").asText())).getDocumentElement();
            var config=new IdpErrorProbeConfiguration(URI.create(request.getAttribute("Destination")),
                MetadataAlgorithmEvidence.children(request,"urn:oasis:names:tc:SAML:2.0:assertion","Issuer").getFirst().getTextContent(),
                URI.create(request.getAttribute("AssertionConsumerServiceURL")),Duration.ofSeconds(30),true,true,true);
            var outcome=new NativeSignedRequestEvidence(caseId,receipts,e->originals.get(e.id()),ignored->target,ignored->config,ignored->Optional.of(credentials))
                .apply(context).orElseThrow();
            if(outcome.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Original evidence incomplete: "+outcome.details());
            boolean nativeHttp="simplesamlphp-native-http".equals(receipt.path("evidenceAdapter").asText());
            boolean nativeKeycloak="keycloak-native-event".equals(receipt.path("evidenceAdapter").asText());
            var mutations=new ArrayList<>(List.of("wrong-run","wrong-case","wrong-request","wrong-event","wrong-metadata","missing-condition","duplicate-fixture","wrong-request-original","wrong-response"));
            if(nativeHttp || nativeKeycloak)mutations.addAll(List.of("wrong-http-status","wrong-http-request-hash","wrong-http-endpoint"));
            if(nativeKeycloak)mutations.addAll(List.of("wrong-native-hash","wrong-native-issuer","wrong-native-time","wrong-native-type","indirect-http-response"));
            var rejected=new ArrayList<String>();var temporary=Files.createTempDirectory("native-signed-controls-");
            try {
                for(var mutation:mutations) {
                    var changed=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(rawReceipt);
                    var exchanges=(com.fasterxml.jackson.databind.node.ArrayNode)changed.path("exchanges");
                    var item=(com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(3);
                    switch(mutation) {
                        case "wrong-run" -> changed.put("runId","other-run");
                        case "wrong-case" -> changed.put("caseId","other-case");
                        case "wrong-metadata" -> changed.put("targetMetadataSha256","0".repeat(64));
                        case "missing-condition" -> exchanges.remove(3);
                        case "duplicate-fixture" -> item.put("fixture","VALID");
                        case "wrong-request-original" -> item.put("requestReference",exchanges.get(0).path("requestReference").asText());
                        case "wrong-request" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path(nativeKeycloak?"nativeEvent":nativeHttp?"nativeHttp":"audit")).put("request_id","other-request");
                        case "wrong-event" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path(nativeKeycloak?"nativeEvent":nativeHttp?"nativeHttp":"audit")).put(nativeKeycloak?"error":nativeHttp?"native_signature_rejection":"event","UNHANDLEDEXCEPTION");
                        case "wrong-http-status" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeHttp")).put("response_status",200);
                        case "wrong-http-request-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeHttp")).put("request_sha256","0".repeat(64));
                        case "wrong-http-endpoint" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeHttp")).put("response_url","https://example.invalid/");
                        case "wrong-native-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeEvent")).put("request_sha256","0".repeat(64));
                        case "wrong-native-issuer" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeEvent")).put("issuer","other-client");
                        case "wrong-native-time" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeEvent")).put("event_time",0);
                        case "wrong-native-type" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeEvent")).put("event_type","LOGOUT_ERROR");
                        case "indirect-http-response" -> ((com.fasterxml.jackson.databind.node.ObjectNode)item.path("nativeHttp")).put("response_url_exact_match",false);
                        case "wrong-response" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(0)).put("responseReference","other-response");
                    }
                    Files.write(temporary.resolve(name),json.writeValueAsBytes(changed));
                    var negative=new NativeSignedRequestEvidence(caseId,temporary,e->originals.get(e.id()),ignored->target,ignored->config,ignored->Optional.of(credentials)).apply(context).orElseThrow();
                    if(negative.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Mutant not rejected: "+mutation);
                    rejected.add(mutation);
                }
            } finally {Files.deleteIfExists(temporary.resolve(name));Files.deleteIfExists(temporary);}
            results.put(caseId,Map.of("outcome",outcome,"negative_controls_rejected",rejected,"receipt_sha256",hash(rawReceipt)));
        }
        json.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("run",run,"cases",results,
            "transcript_sha256",hash(Files.readAllBytes(folder.resolve("transcript.json"))),"product_verdict_assigned",false));
        System.out.println("Original signed-request matrices and negative controls verified");
    }
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
}
