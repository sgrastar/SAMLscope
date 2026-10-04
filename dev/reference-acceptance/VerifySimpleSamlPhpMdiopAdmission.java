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
/** Actual production reader replay; altered original controls also repair their declared hashes. */
public final class VerifySimpleSamlPhpMdiopAdmission {
    static final com.fasterxml.jackson.databind.ObjectMapper JSON=new JsonCodec().mapper();
    static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    static void mutate(ObjectNode receipt,Map<String,byte[]> raw,JsonNode ref,java.util.function.Consumer<ObjectNode> change)throws Exception{
        String id=ref.path("reference").asText();var value=(ObjectNode)JSON.readTree(raw.get(id));change.accept(value);byte[] modified=JSON.writeValueAsBytes(value);raw.put(id,modified);((ObjectNode)ref).put("sha256",sha(modified));
    }
    static void encoded(ObjectNode root,String field,byte[] bytes)throws Exception{var value=JSON.createObjectNode();value.put("base64",Base64.getEncoder().encodeToString(bytes));value.put("sha256",sha(bytes));root.set(field,value);}
    public static void main(String[] args)throws Exception{
        Path source=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]);String run=JSON.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var baselineEntries=List.of(JSON.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var baselineRaw=new HashMap<String,byte[]>();
        for(var row:JSON.readTree(source.resolve("decoded-manifest.json").toFile())){byte[] raw=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!sha(raw).equals(row.path("sha256").asText()))throw new IllegalArgumentException();baselineRaw.put(row.path("id").asText(),raw);}
        byte[] receiptRaw=Files.readAllBytes(source.resolve("qualified-receipt.json")),target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path directory=Files.createTempDirectory("ssp-mdiop-reader-"),path=directory.resolve(run+".ssp-mdiop-representation.json");
        var raw=new HashMap<String,byte[]>();var entries=new ArrayList<TranscriptEntry>();var controls=new LinkedHashMap<String,String>();
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException();return List.copyOf(entries);}public TranscriptEntry record(TranscriptInput value){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);var reader=new SimpleSamlPhpMdiopAdmissionEvidence(directory,e->raw.get(e.id()));
        try{
            Files.write(path,receiptRaw);raw.putAll(baselineRaw);entries.addAll(baselineEntries);var outcome=reader.evaluate(context,target);System.out.println(outcome.outcome()+" "+outcome.details());if(outcome.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Full native admission not proven: "+outcome.details());
            for(String control:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","missing-variant","duplicate-variant","keyvalue-fixture-substitution","native-original-foreign-run","native-original-foreign-target","native-original-wrong-variant","parser-failed","parser-input-changed","active-entity-changed","active-endpoint-lost","configuration-different","native-source-changed","native-command-changed","collector-changed","not-restored","restoration-different","native-runtime-changed","missing-parser-control","parser-control-accepted","parser-control-unknown","missing-protocol-control","protocol-unknown-delivery","protocol-generic-500","protocol-request-substitution","protocol-control-after-positive","missing-original","foreign-transcript","duplicate-transcript","symlink-receipt","symlink-directory")){
                raw.clear();raw.putAll(baselineRaw);entries.clear();entries.addAll(baselineEntries);var receipt=(ObjectNode)JSON.readTree(receiptRaw);var member=receipt.path("members").get(0);JsonNode nativeRef=member.path("native");
                switch(control){
                    case "wrong-run"->receipt.put("runId","run_00000000000000000000000000");case "wrong-target"->receipt.put("targetMetadataSha256","0".repeat(64));case "wrong-campaign"->receipt.put("campaignId","other");case "wrong-entity"->receipt.put("targetEntityId","other");
                    case "missing-variant"->((com.fasterxml.jackson.databind.node.ArrayNode)receipt.path("members")).remove(1);case "duplicate-variant"->((ObjectNode)receipt.path("members").get(1)).put("variant",member.path("variant").asText());
                    case "keyvalue-fixture-substitution"->{var m=receipt.path("members");JsonNode key=null;for(var row:m)if(row.path("variant").asText().equals("keyvalue-only"))key=row;((ObjectNode)key).put("preparedReference",member.path("preparedReference").asText());}
                    case "native-original-foreign-run"->mutate(receipt,raw,nativeRef,v->v.put("runId","run_00000000000000000000000000"));case "native-original-foreign-target"->mutate(receipt,raw,nativeRef,v->v.put("targetEntityId","other"));case "native-original-wrong-variant"->mutate(receipt,raw,nativeRef,v->v.put("variant","other"));
                    case "parser-failed"->mutate(receipt,raw,nativeRef,v->((ObjectNode)v.path("parser")).put("returncode",1));
                    case "parser-input-changed"->mutate(receipt,raw,nativeRef,v->{try{encoded((ObjectNode)v.path("parser"),"input","other".getBytes());}catch(Exception e){throw new RuntimeException(e);}});
                    case "active-entity-changed","active-endpoint-lost"->mutate(receipt,raw,nativeRef,v->{try{var readback=(ObjectNode)JSON.readTree(Base64.getDecoder().decode(v.path("readback").path("base64").asText()));if(control.equals("active-entity-changed"))readback.put("entityId","other");else ((ObjectNode)readback.path("metadata")).set("AssertionConsumerService",JSON.createArrayNode());encoded(v,"readback",JSON.writeValueAsBytes(readback));}catch(Exception e){throw new RuntimeException(e);}});
                    case "configuration-different"->mutate(receipt,raw,nativeRef,v->{try{encoded(v,"configuration","other".getBytes());}catch(Exception e){throw new RuntimeException(e);}});
                    case "native-source-changed"->mutate(receipt,raw,receipt.path("baseline"),v->{try{encoded((ObjectNode)v.path("sources"),"parser","other".getBytes());}catch(Exception e){throw new RuntimeException(e);}});
                    case "native-command-changed"->mutate(receipt,raw,receipt.path("baseline"),v->((ObjectNode)v.path("commands")).put("parser","other"));case "collector-changed"->mutate(receipt,raw,receipt.path("baseline"),v->v.put("collectorSha256","0".repeat(64)));
                    case "not-restored"->mutate(receipt,raw,receipt.path("restoration"),v->v.put("restored",false));case "restoration-different"->mutate(receipt,raw,receipt.path("restoration"),v->{try{encoded(v,"configuration","other".getBytes());}catch(Exception e){throw new RuntimeException(e);}});
                    case "native-runtime-changed"->mutate(receipt,raw,receipt.path("restoration"),v->((ObjectNode)v.path("runtime")).put("imageId","other"));
                    case "missing-parser-control"->((com.fasterxml.jackson.databind.node.ArrayNode)receipt.path("parserControls")).remove(0);case "parser-control-accepted"->mutate(receipt,raw,receipt.path("parserControls").get(0).path("native"),v->v.put("returncode",0));case "parser-control-unknown"->((ObjectNode)receipt.path("parserControls").get(0)).put("control","unknown");
                    case "missing-protocol-control"->receipt.remove("baselineProtocolControl");case "protocol-unknown-delivery"->mutate(receipt,raw,receipt.path("baselineProtocolControl"),v->((ObjectNode)v.path("nativeTransport")).put("redirect_hops",1));
                    case "protocol-generic-500"->mutate(receipt,raw,receipt.path("baselineProtocolControl"),v->{try{byte[] error="<html>Internal server error</html>".getBytes();encoded((ObjectNode)v.path("originals"),"html",error);((ObjectNode)v.path("nativeTransport")).put("response_body_sha256",sha(error)).put("persisted_body_sha256",sha(error));}catch(Exception e){throw new RuntimeException(e);}});
                    case "protocol-request-substitution"->mutate(receipt,raw,receipt.path("baselineProtocolControl"),v->{try{encoded((ObjectNode)v.path("originals"),"request.xml","other".getBytes());}catch(Exception e){throw new RuntimeException(e);}});
                    case "protocol-control-after-positive"->mutate(receipt,raw,receipt.path("baselineProtocolControl"),v->((ObjectNode)v.path("nativeTransport")).put("observed_at","2099-01-01T00:00:00Z"));
                    case "missing-original"->raw.remove(nativeRef.path("reference").asText());case "foreign-transcript"->{var original=(ObjectNode)JSON.valueToTree(entries.get(0));original.put("runId","run_00000000000000000000000000");entries.set(0,JSON.treeToValue(original,TranscriptEntry.class));}case "duplicate-transcript"->entries.add(entries.get(0));
                    case "symlink-receipt"->{Files.delete(path);Files.createSymbolicLink(path,source.resolve("qualified-receipt.json"));}
                    case "symlink-directory"->{Files.deleteIfExists(path);Files.delete(directory);Files.createSymbolicLink(directory,source);}
                }
                // Preserve Recorder original lengths when independently replacing semantic originals.
                for(int i=0;i<entries.size();i++){var e=entries.get(i);byte[] changed=raw.get(e.id());if(changed!=null&&changed.length!=e.decodedSamlBytes()){var v=(ObjectNode)JSON.valueToTree(e);v.put("decodedSamlBytes",changed.length);entries.set(i,JSON.treeToValue(v,TranscriptEntry.class));}}
                if(!control.startsWith("symlink"))Files.write(path,JSON.writeValueAsBytes(receipt));var result=reader.evaluate(context,target);if(result.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Altered evidence accepted: "+control);controls.put(control,"NOT_VERIFIED");
                if(Files.isSymbolicLink(directory)){Files.delete(directory);Files.createDirectory(directory);}else if(Files.isSymbolicLink(path))Files.delete(path);
            }
            Files.write(output,JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"caseId",SimpleSamlPhpMdiopAdmissionEvidence.ID,"production_outcome",outcome,"negative_controls",controls,"receiptSha256",sha(receiptRaw),"transcriptSha256",sha(Files.readAllBytes(source.resolve("transcript.json"))),"runtimeKeyInterpretationProven",false)),StandardOpenOption.CREATE_NEW);
        }finally{Files.deleteIfExists(path);Files.deleteIfExists(directory);}
    }
}
