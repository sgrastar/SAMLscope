package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Read-only original evidence replay; creates only a report and disposable negative-control files. */
public final class VerifyNativeEcProtocol {
    public static void main(String[] args) throws Exception {
        var folder=Path.of(args[0]).toAbsolutePath().normalize();
        var receipts=Path.of(args[1]);var json=new JsonCodec().mapper();
        var run=json.readTree(folder.resolve("created.json").toFile()).path("run").path("id").asText();
        var originals=new HashMap<String,byte[]>();
        for(var item:json.readTree(folder.resolve("decoded-manifest.json").toFile())) {
            var path=folder.resolve(item.path("file").asText()).normalize();
            if(!path.startsWith(folder))throw new IllegalArgumentException("Invalid original path");
            var raw=Files.readAllBytes(path);
            if(!hash(raw).equals(item.path("sha256").asText()) || originals.put(item.path("id").asText(),raw)!=null)
                throw new IllegalArgumentException("Original mismatch");
        }
        var entries=List.of(json.readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) {if(!run.equals(id))throw new IllegalArgumentException("Wrong Run");return entries;}
            public TranscriptEntry record(TranscriptInput input) {throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) {throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
            TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var outcome=new NativeEcSignatureEvidence(receipts,e->originals.get(e.id()),ignored->target).apply(context).orElseThrow();
        if(outcome.outcome()!=com.samlscope.core.evaluation.Outcome.SATISFIED
                && !(outcome.outcome()==com.samlscope.core.evaluation.Outcome.VIOLATED
                    && "ec-signature.native-unsupported-verifier".equals(outcome.reasonCode()))
                && !(outcome.outcome()==com.samlscope.core.evaluation.Outcome.NOT_VERIFIED
                    && "ec-signature.native-valid-request-rejected".equals(outcome.reasonCode())))
            throw new IllegalStateException("Native signature evidence incomplete");
        var rawReceipt=Files.readAllBytes(receipts.resolve(run+".json"));
        var originalReceipt=json.readTree(rawReceipt);
        boolean nativeHttp="simplesamlphp-native-http".equals(originalReceipt.path("evidenceAdapter").asText());
        boolean keycloak="keycloak-native-event".equals(originalReceipt.path("evidenceAdapter").asText());
        var mutations=new ArrayList<>(List.of("wrong-run","wrong-request","wrong-event","wrong-metadata","missing-condition"));
        if(nativeHttp || keycloak)mutations.addAll(List.of("wrong-http-status","wrong-http-hash","wrong-http-endpoint","wrong-request-original","wrong-control-response"));
        if(keycloak)mutations.addAll(List.of("wrong-native-hash","wrong-native-issuer","wrong-native-time","indirect-http-response"));
        boolean simpleNativeHttp="simplesamlphp-native-http".equals(originalReceipt.path("evidenceAdapter").asText());
        if(simpleNativeHttp && originalReceipt.has("nativeVerifierSource"))
            mutations.addAll(List.of("wrong-source-hash","wrong-source-path","wrong-source-algorithm",
                    "wrong-image-id","wrong-container-id","wrong-native-observations-hash","wrong-call-path"));
        if(simpleNativeHttp && originalReceipt.has("nativeRuntime"))
            mutations.addAll(List.of("wrong-runtime-inspect-hash","wrong-runtime-source-mount","wrong-runtime-route"));
        var negative=new ArrayList<String>();var temporary=Files.createTempDirectory("native-ec-controls-");
        try {
            for(var mutation:mutations) {
                var changed=(com.fasterxml.jackson.databind.node.ObjectNode)json.readTree(rawReceipt);
                var exchanges=(com.fasterxml.jackson.databind.node.ArrayNode)changed.path("exchanges");
                switch(mutation) {
                    case "wrong-run" -> changed.put("runId","other-run");
                    case "wrong-metadata" -> changed.put("targetMetadataSha256","0".repeat(64));
                    case "missing-condition" -> exchanges.remove(2);
                    case "wrong-request" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path(keycloak?"nativeEvent":nativeHttp?"nativeHttp":"audit")).put("request_id","other-request");
                    case "wrong-event" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path(keycloak?"nativeEvent":nativeHttp?"nativeHttp":"audit")).put(keycloak?"error":nativeHttp?"native_signature_rejection":"event","RuntimeException");
                    case "wrong-http-status" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeHttp")).put("response_status",200);
                    case "wrong-http-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeHttp")).put("request_sha256","0".repeat(64));
                    case "wrong-http-endpoint" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeHttp")).put("response_url","https://example.invalid/");
                    case "wrong-request-original" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2)).put("requestReference",exchanges.get(1).path("requestReference").asText());
                    case "wrong-control-response" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(0)).put("responseReference","other-response");
                    case "wrong-native-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeEvent")).put("request_sha256","0".repeat(64));
                    case "wrong-native-issuer" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeEvent")).put("issuer","other-client");
                    case "wrong-native-time" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeEvent")).put("event_time",0);
                    case "indirect-http-response" -> ((com.fasterxml.jackson.databind.node.ObjectNode)exchanges.get(2).path("nativeHttp")).put("response_url_exact_match",false);
                    case "wrong-source-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource")).put("sha256","0".repeat(64));
                    case "wrong-source-path" -> ((com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource")).put("containerPath","/other/Message.php");
                    case "wrong-source-algorithm" -> {
                        var node=(com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource");
                        var originalSource=new String(Base64.getDecoder().decode(node.path("base64").asText()),java.nio.charset.StandardCharsets.UTF_8);
                        var changedSource=originalSource.replace("new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public'])",
                                "new XMLSecurityKey(XMLSecurityKey::ECDSA_SHA256, ['type' => 'public'])")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        if(java.util.Arrays.equals(changedSource,originalSource.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                            throw new IllegalStateException("Source mutation did not change the verifier");
                        node.put("base64",Base64.getEncoder().encodeToString(changedSource));node.put("sha256",hash(changedSource));
                    }
                    case "wrong-image-id" -> ((com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource"))
                            .put("imageId","sha256:"+"0".repeat(64));
                    case "wrong-container-id" -> ((com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource"))
                            .put("containerId","0".repeat(64));
                    case "wrong-native-observations-hash" -> changed.put("nativeHttpObservationsSha256","0".repeat(64));
                    case "wrong-call-path" -> {
                        var node=(com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeVerifierSource");
                        var originalSource=new String(Base64.getDecoder().decode(node.path("base64").asText()),java.nio.charset.StandardCharsets.UTF_8);
                        var changedSource=originalSource.replace("} elseif (!self::checkSign($srcMetadata, $message)) {",
                                "} elseif (false) {").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        if(java.util.Arrays.equals(changedSource,originalSource.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                            throw new IllegalStateException("Call-path mutation did not change the verifier");
                        node.put("base64",Base64.getEncoder().encodeToString(changedSource));node.put("sha256",hash(changedSource));
                    }
                    case "wrong-runtime-inspect-hash" -> ((com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeRuntime"))
                            .put("startInspectSha256","0".repeat(64));
                    case "wrong-runtime-source-mount" -> {
                        var runtime=(com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeRuntime");
                        var raw=Base64.getDecoder().decode(runtime.path("startInspectBase64").asText());
                        var inspect=(com.fasterxml.jackson.databind.node.ArrayNode)json.readTree(raw);
                        var mounts=((com.fasterxml.jackson.databind.node.ObjectNode)inspect.get(0)).withArray("Mounts");
                        var mount=json.createObjectNode();mount.put("Destination","/var/simplesamlphp/modules/saml/src");mounts.add(mount);
                        var changedRaw=json.writeValueAsBytes(inspect);
                        runtime.put("startInspectBase64",Base64.getEncoder().encodeToString(changedRaw));runtime.put("startInspectSha256",hash(changedRaw));
                    }
                    case "wrong-runtime-route" -> {
                        var runtime=(com.fasterxml.jackson.databind.node.ObjectNode)changed.path("nativeRuntime");
                        com.fasterxml.jackson.databind.node.ObjectNode route=null;
                        for(var source:runtime.withArray("sources")) if("routes".equals(source.path("name").asText()))route=(com.fasterxml.jackson.databind.node.ObjectNode)source;
                        if(route==null)throw new IllegalStateException("Route source unavailable");
                        var originalSource=new String(Base64.getDecoder().decode(route.path("base64").asText()),java.nio.charset.StandardCharsets.UTF_8);
                        var changedSource=originalSource.replace("WebBrowserSingleSignOn::singleSignOnService","Other::handler")
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        if(java.util.Arrays.equals(changedSource,originalSource.getBytes(java.nio.charset.StandardCharsets.UTF_8)))
                            throw new IllegalStateException("Route mutation did not change the source");
                        route.put("base64",Base64.getEncoder().encodeToString(changedSource));route.put("sha256",hash(changedSource));
                    }
                }
                Files.write(temporary.resolve(run+".json"),json.writeValueAsBytes(changed));
                var rejected=new NativeEcSignatureEvidence(temporary,e->originals.get(e.id()),ignored->target).apply(context).orElseThrow();
                if(rejected.outcome()!=com.samlscope.core.evaluation.Outcome.NOT_VERIFIED
                        || !"ec-signature.native-incomplete".equals(rejected.reasonCode()) || !rejected.evidence().isEmpty())
                    throw new IllegalStateException("Negative control not rejected: "+mutation);
                negative.add(mutation);
            }
        } finally {Files.deleteIfExists(temporary.resolve(run+".json"));Files.deleteIfExists(temporary);}
        json.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(),Map.of("run",run,"outcome",outcome,
            "negative_controls_rejected",negative,"receipt_sha256",hash(rawReceipt),
            "transcript_sha256",hash(Files.readAllBytes(folder.resolve("transcript.json"))),"product_verdict_assigned",false));
        System.out.println("Native EC evidence and binding controls verified");
    }
    private static String hash(byte[] bytes)throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
