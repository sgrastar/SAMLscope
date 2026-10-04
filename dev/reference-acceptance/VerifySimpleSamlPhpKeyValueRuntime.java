package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Actual production reader replay; mutation originals are isolated in a temporary folder. */
public final class VerifySimpleSamlPhpKeyValueRuntime {
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static final com.fasterxml.jackson.databind.ObjectMapper MAPPER=new JsonCodec().mapper();
    static ObjectNode json(Path file)throws Exception{return (ObjectNode)MAPPER.readTree(Files.readAllBytes(file));}
    static void edit(Path folder,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception {
        Path file=folder.resolve(name);var value=json(file);edit.accept(value);Files.write(file,MAPPER.writeValueAsBytes(value));rehash(folder,name);
    }
    static void rehash(Path folder,String name)throws Exception {
        Path path=folder.resolve("manifest.json");var manifest=json(path);((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(path,MAPPER.writeValueAsBytes(manifest));
    }
    public static void main(String[] args)throws Exception {
        Path source=Path.of(args[0]).toAbsolutePath().normalize(),output=Path.of(args[1]);
        String run=MAPPER.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(MAPPER.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));
        var raw=new HashMap<String,byte[]>();for(var row:MAPPER.readTree(source.resolve("decoded-manifest.json").toFile())){
            byte[] bytes=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!hash(bytes).equals(row.path("sha256").asText()))throw new IllegalArgumentException();raw.put(row.path("id").asText(),bytes);}
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String requested){if(!run.equals(requested))throw new IllegalArgumentException();return entries;}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path directory=Files.createTempDirectory("samlscope-ssp-keyvalue-"),folder=directory.resolve(run);
        Files.createDirectory(folder);var baseline=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(source.resolve("originals"))){for(var path:paths.toList())baseline.put(path.getFileName().toString(),Files.readAllBytes(path));}
        var reader=new SimpleSamlPhpKeyValueRuntimeEvidence(directory,e->raw.get(e.id()));var outcomes=new LinkedHashMap<String,CaseOutcome>();var checks=new LinkedHashMap<String,String>();
        try{
            for(var file:baseline.entrySet())Files.write(folder.resolve(file.getKey()),file.getValue());
            for(var id:SimpleSamlPhpKeyValueRuntimeEvidence.CASES.stream().sorted().toList()){
                var result=reader.evaluate(id,context,target).orElseThrow();System.out.println(id+" "+result.outcome()+" "+result.details());
                if(result.outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Actual native counterexample was not proven: "+result.details());outcomes.put(id,result);
            }
            String request=MAPPER.readTree(folder.resolve(run+".json").toFile()).path("conditions").get(1).path("positive").path("nativeHttp").path("request_id").asText();
            for(String mutation:List.of("wrong-run","wrong-target","wrong-entity","wrong-sp","wrong-campaign","not-restored","restore-different",
                "signature-policy-off","keys-retained","parser-rejected","parser-original-changed","generic-error","wrong-error-entity",
                "request-body-changed","redirected-response","earlier-response","duplicate-http","wrong-http-request","wrong-native-source","missing-original","symlink-original")){
                for(var file:baseline.entrySet()){Files.deleteIfExists(folder.resolve(file.getKey()));Files.write(folder.resolve(file.getKey()),file.getValue());}
                switch(mutation){
                    case "wrong-run" -> edit(folder,"manifest.json",v->v.put("runId","run_00000000000000000000000000"));
                    case "wrong-target" -> edit(folder,"manifest.json",v->v.put("targetMetadataSha256","0".repeat(64)));
                    case "wrong-entity" -> edit(folder,"manifest.json",v->v.put("targetEntityId","other"));
                    case "wrong-sp" -> edit(folder,"manifest.json",v->v.put("spEntityId","other"));
                    case "wrong-campaign" -> edit(folder,"manifest.json",v->v.put("campaignId","other"));
                    case "not-restored" -> edit(folder,"restoration.json",v->v.put("restored",false));
                    case "restore-different" -> {Files.writeString(folder.resolve("final-sp-config.php"),"changed");rehash(folder,"final-sp-config.php");}
                    case "signature-policy-off" -> {for(var phase:List.of("before","after"))edit(folder,"keyvalue-only."+phase+".native.json",v->((ObjectNode)v.path("metadata")).put("validate.authnrequest",false));}
                    case "keys-retained" -> {for(var phase:List.of("before","after"))edit(folder,"keyvalue-only."+phase+".native.json",v->((ObjectNode)v.path("metadata")).set("keys",MAPPER.createArrayNode()));}
                    case "parser-rejected" -> {Path f=folder.resolve("operations.json");var v=MAPPER.readTree(Files.readAllBytes(f));((ObjectNode)v.get(2)).put("nativeParserReturncode",1);Files.write(f,MAPPER.writeValueAsBytes(v));rehash(folder,"operations.json");}
                    case "parser-original-changed" -> {Files.writeString(folder.resolve("keyvalue-only.parser.stdout"),"{}");rehash(folder,"keyvalue-only.parser.stdout");}
                    case "generic-error" -> {Files.writeString(folder.resolve(request+".html"),"UNHANDLEDEXCEPTION");rehash(folder,request+".html");}
                    case "wrong-error-entity" -> {String body=Files.readString(folder.resolve(request+".html"));Files.writeString(folder.resolve(request+".html"),body.replace("http://localhost:18080/p/","http://other/p/"));rehash(folder,request+".html");}
                    case "request-body-changed" -> {Files.writeString(folder.resolve(request+".request.body"),"SAMLRequest=ZmFrZQ%3D%3D");rehash(folder,request+".request.body");}
                    case "redirected-response","earlier-response","wrong-http-request" -> {
                        var receipt=json(folder.resolve(run+".json"));for(var row:receipt.path("conditions"))if("keyvalue-only".equals(row.path("variant").asText())){
                            var http=(ObjectNode)row.path("positive").path("nativeHttp");if(mutation.equals("redirected-response"))http.put("redirect_hops",1);
                            else if(mutation.equals("earlier-response"))http.put("started_at","1970-01-01T00:00:00Z");else http.put("request_id","other");
                        }Files.write(folder.resolve(run+".json"),MAPPER.writeValueAsBytes(receipt));rehash(folder,run+".json");}
                    case "duplicate-http" -> edit(folder,"native-http-observations.json",v->{var a=(com.fasterxml.jackson.databind.node.ArrayNode)v.path("records");a.add(a.get(5).deepCopy());});
                    case "wrong-native-source" -> {Files.writeString(folder.resolve("native-message.php"),"unrelated code");rehash(folder,"native-message.php");}
                    case "missing-original" -> Files.delete(folder.resolve(request+".html"));
                    case "symlink-original" -> {Files.delete(folder.resolve(request+".html"));Files.createSymbolicLink(folder.resolve(request+".html"),source.resolve("originals").resolve(request+".html"));}
                    default -> throw new IllegalStateException();
                }
                for(var id:outcomes.keySet()){var result=reader.evaluate(id,context,target);if(result.isEmpty()||result.get().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid originals accepted: "+id+" "+mutation);}
                checks.put(mutation,"NOT_VERIFIED");
            }
            Files.write(output,MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcomes",outcomes,"negative_controls",checks,
                "manifestSha256",hash(Files.readAllBytes(source.resolve("originals/manifest.json"))),"transcriptSha256",hash(Files.readAllBytes(source.resolve("transcript.json"))),"verdict_adopted",false)),StandardOpenOption.CREATE_NEW);
            System.out.println("Actual production KeyValue counterexample proven; "+checks.size()+" controls rejected for every case; no Run verdict adopted");
        }finally{try(var paths=Files.walk(directory)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}}
    }
}
