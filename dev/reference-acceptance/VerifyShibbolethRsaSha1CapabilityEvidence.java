package com.samlscope.runner.cases;

import java.nio.file.*;
import java.time.Clock;
import java.security.MessageDigest;
import java.util.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;

/** Replays the actual production reader on native originals and recomputed-hash mutations. */
public final class VerifyShibbolethRsaSha1CapabilityEvidence {
    static final JsonCodec JSON=new JsonCodec();
    static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static byte[] decode(com.fasterxml.jackson.databind.JsonNode node){return Base64.getDecoder().decode(node.path("base64").asText());}
    static ObjectNode blob(byte[] raw)throws Exception{var node=JSON.mapper().createObjectNode();node.put("base64",Base64.getEncoder().encodeToString(raw));node.put("sha256",sha(raw));return node;}
    static void replace(ObjectNode parent,String key,com.fasterxml.jackson.databind.JsonNode value)throws Exception{parent.set(key,blob(JSON.mapper().writeValueAsBytes(value)));}
    static void mutateObservation(ObjectNode receipt,String field,String control,boolean accepted)throws Exception {
        var raw=new String(decode(receipt.path(field)),java.nio.charset.StandardCharsets.UTF_8).strip().split("\\R");
        var json=(ObjectNode)JSON.mapper().readTree(raw[raw.length-1]);((ObjectNode)json.path(control)).put("accepted",accepted);replace(receipt,field,json);
    }
    static Outcome observe(ObjectNode receipt,byte[] target,String run)throws Exception {
        var root=Files.createTempDirectory("shibboleth-rsa-sha1-replay-");
        try {
            Files.write(root.resolve(run+".json"),JSON.mapper().writeValueAsBytes(receipt));
            var recorder=new TranscriptRecorder(){
                public List<TranscriptEntry> list(String id){return List.of();}
                public TranscriptEntry record(TranscriptInput input){throw new AssertionError();}
                public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}
            };
            var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                    TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
            var test=new MetadataSignatureTestCase(MetadataRsaSha1CapabilityEvidenceFile.CASE_ID,id->id.equals(run)?target:null,root);
            return ((CaseStep.Finish)test.start(context)).outcome().outcome();
        }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("folder immutable-output required");
        var folder=Path.of(args[0]);var output=Path.of(args[1]);if(Files.exists(output))throw new IllegalArgumentException("Output exists");
        var receipt=(ObjectNode)JSON.mapper().readTree(folder.resolve("receipt.json").toFile());
        var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var run=receipt.path("runId").asText();
        // Report the original proof error before the public reader fail-closes it.
        ShibbolethRsaSha1CapabilityProof.verify(receipt,target);
        if(observe(receipt,target,run)!=Outcome.SATISFIED)throw new IllegalStateException("Native originals do not satisfy production reader");
        var checks=new TreeMap<String,String>();checks.put("complete-native-originals","SATISFIED");
        for(var name:List.of("foreign-run","foreign-metadata","unknown-adapter","fake-native-image","restarted-product",
                "shadowed-native-library","fake-native-source","fake-native-class","changed-native-key","missing-original-configuration",
                "positive-rejected","tampered-accepted","wrong-key-accepted","unsigned-accepted","missing-native-control",
                "unrelated-tampered-input","cleared-tampered-signature","signer-wrong-mode","native-nonzero-exit","native-stderr","wrong-operation-count","wrong-certificate")) {
            var changed=receipt.deepCopy();byte[] metadata=target;
            var runtime=(ObjectNode)changed.path("runtime");var configuration=(ObjectNode)changed.path("configuration");
            switch(name) {
                case "foreign-run" -> changed.put("runId","run_00000000000000000000000000");
                case "foreign-metadata" -> changed.put("targetMetadataSha256","0".repeat(64));
                case "unknown-adapter" -> changed.put("evidenceAdapter","suite-native");
                case "fake-native-image","restarted-product","shadowed-native-library" -> {
                    var inspect=(ObjectNode)JSON.mapper().readTree(decode(runtime.path("after")));
                    if(name.equals("fake-native-image"))inspect.put("Image","sha256:"+"0".repeat(64));
                    if(name.equals("restarted-product"))((ObjectNode)inspect.path("State")).put("StartedAt","2099-01-01T00:00:00Z");
                    if(name.equals("shadowed-native-library"))((ArrayNode)inspect.path("Mounts")).addObject().put("Destination","/opt/shibboleth-idp/dist/webapp/WEB-INF/lib");
                    replace(runtime,"after",inspect);
                }
                case "fake-native-source" -> runtime.set("verifierSource",blob("class Arbitrary {}".getBytes()));
                case "fake-native-class" -> ((ObjectNode)runtime.path("nativeClasses").path("org.opensaml.xmlsec.signature.support.SignatureSupport")).set("original",blob("arbitrary class".getBytes()));
                case "changed-native-key" -> {
                    var config=(ObjectNode)JSON.mapper().readTree(decode(configuration.path("after")));config.put("signingKeySha256","0".repeat(64));replace(configuration,"after",config);
                }
                case "missing-original-configuration" -> configuration.remove("before");
                case "positive-rejected" -> mutateObservation(changed,"nativeObservation","positive",false);
                case "tampered-accepted" -> mutateObservation(changed,"nativeObservation","tampered",true);
                case "wrong-key-accepted" -> mutateObservation(changed,"nativeObservation","wrongKey",true);
                case "unsigned-accepted" -> mutateObservation(changed,"nativeObservation","unsigned",true);
                case "missing-native-control","unrelated-tampered-input","cleared-tampered-signature","signer-wrong-mode" -> {
                    String field=name.equals("signer-wrong-mode")?"signerObservation":"nativeObservation";
                    var raw=new String(decode(changed.path(field)),java.nio.charset.StandardCharsets.UTF_8).strip().split("\\R");
                    var json=(ObjectNode)JSON.mapper().readTree(raw[raw.length-1]);
                    if(name.equals("missing-native-control"))json.remove("wrongKey");
                    if(name.equals("unrelated-tampered-input"))json.put("tamperedInputBase64",Base64.getEncoder().encodeToString(decode(changed.path("originalUnsignedMetadata"))));
                    if(name.equals("cleared-tampered-signature")) {
                        var xml=com.samlscope.saml.normal.SecureXml.parse(Base64.getDecoder().decode(json.path("tamperedInputBase64").asText()));
                        xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0).setTextContent("");
                        json.put("tamperedInputBase64",Base64.getEncoder().encodeToString(com.samlscope.saml.normal.SecureXml.serialize(xml)));
                    }
                    if(name.equals("signer-wrong-mode"))json.put("mode","verify");replace(changed,field,json);
                }
                case "native-nonzero-exit" -> changed.put("nativeVerifierExitCode",1);
                case "native-stderr" -> changed.set("nativeVerifierStderr",blob("native error".getBytes()));
                case "wrong-operation-count" -> ((ObjectNode)changed.path("operationCounts")).put("nativeVerificationExecutions",1);
                case "wrong-certificate" -> changed.set("wrongCertificate",blob("not a certificate".getBytes()));
                default -> throw new AssertionError(name);
            }
            var result=observe(changed,metadata,run);if(result!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Mutation accepted: "+name+"="+result);
            checks.put(name,result.name());
        }
        var result=new LinkedHashMap<String,Object>();result.put("schema","samlscope-shibboleth-rsa-sha1-production-replay-v1");
        result.put("run",run);result.put("receiptSha256",sha(Files.readAllBytes(folder.resolve("receipt.json"))));
        result.put("targetMetadataSha256",sha(target));result.put("checks",checks);
        Files.write(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(result));
        System.out.println(checks.size()+" production reader checks passed");
    }
}
