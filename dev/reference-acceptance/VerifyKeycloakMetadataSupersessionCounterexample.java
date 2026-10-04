package com.samlscope.runner.cases;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import java.util.function.BiFunction;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;

/** Actual production replay; private Run keys are loaded only inside the Suite. */
public final class VerifyKeycloakMetadataSupersessionCounterexample {
 private static final JsonCodec JSON=new JsonCodec();
 private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 private static void require(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}
 private static CaseOutcome observe(String caseId,String run,List<TranscriptEntry> entries,Map<String,byte[]> originals,byte[] target,Path temporary,String plan,Path data){
  var normalized=entries.stream().map(e->{var raw=originals.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(run.equals(id),"Foreign context Run");return normalized;}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>summary){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  var store=new FilePlanKeyStore(data,Clock.systemUTC());BiFunction<String,String,Optional<PlanCredentials>> keys=(id,variant)->{try{if(!id.equals(run))return Optional.empty();String alias="poll-"+sha(variant.getBytes(StandardCharsets.UTF_8)).substring(0,16);if(!Files.isRegularFile(data.resolve("keys").resolve(plan).resolve(alias).resolve("signing-key.pk8")))return Optional.empty();return Optional.of(store.getOrCreate(plan,alias));}catch(Exception e){return Optional.empty();}};
  return new KeycloakMetadataSupersessionEvidenceFile(temporary.resolve("metadata-rejection-evidence"),e->originals.get(e.id()),keys).evaluate(caseId,context,target);
 }
 public static void main(String[] args)throws Exception{
  require(args.length==3,"folder data output required");var folder=Path.of(args[0]).toAbsolutePath();var data=Path.of(args[1]);var output=Path.of(args[2]);require(!Files.exists(output),"Immutable replay already exists");
  var created=JSON.mapper().readTree(folder.resolve("created.json").toFile());String run=created.at("/run/id").asText(),plan=created.at("/run/planId").asText();var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
  var byId=new HashMap<String,TranscriptEntry>();for(var e:entries)require(run.equals(e.runId())&&byId.put(e.id(),e)==null,"Foreign/duplicate originals");
  var originals=new HashMap<String,byte[]>();for(var ref:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){var path=folder.resolve(ref.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Decoded path escaped");var raw=Files.readAllBytes(path);var e=byId.get(ref.path("id").asText());require(e!=null&&raw.length==e.decodedSamlBytes()&&sha(raw).equals(ref.path("sha256").asText())&&originals.put(e.id(),raw)==null,"Decoded original changed");}
  var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var receipt=JSON.mapper().readTree(folder.resolve("qualified-receipt.json").toFile());var temporary=Files.createTempDirectory("kc-supersession-reader-");var receiptFile=temporary.resolve("metadata-rejection-evidence").resolve(run+".keycloak-supersession.json");Files.createDirectories(receiptFile.getParent());
  try{
   for(var row:JSON.mapper().readTree(folder.resolve("browser-originals-manifest.json").toFile())){String id=row.path("id").asText();var e=byId.get(id);var raw=Files.readAllBytes(folder.resolve(row.path("file").asText()));require(e!=null&&raw.length==e.bodyBytes()&&sha(raw).equals(row.path("sha256").asText()),"Browser original changed");var path=temporary.resolve(e.bodyRef());require(path.normalize().startsWith(temporary)&&e.bodyRef().equals("transcripts/"+run+"/"+id+".body"),"Body path escaped");Files.createDirectories(path.getParent());Files.write(path,raw);}
   Files.copy(folder.resolve("qualified-receipt.json"),receiptFile);var application=observe(MetadataSupersessionProbeTestCase.APPLICATION,run,entries,originals,target,temporary,plan,data);var base=observe(MetadataSupersessionProbeTestCase.SUPERSESSION,run,entries,originals,target,temporary,plan,data);require(base.outcome()==Outcome.VIOLATED,"Native counterexample not proven: "+base);
   var checks=new TreeMap<String,String>();checks.put("accepted-second-post-acs-counterexample",base.outcome().name());
   for(String name:List.of("foreign-history-run","duplicate-transcript-id","missing-native-http-original","native-response-reference-foreign","native-request-id-foreign","native-request-hash-foreign","native-http-body-hash-foreign","native-http-response-before-request","restore-client-remains","native-extra-local-policy","epoch-order-foreign","native-config-kind-foreign","native-converter-request-not-original","native-replacement-not-converter-output","native-path-source-corrupt","corrupt-positive-response-signature","same-length-unrelated-html","replacement-native-client-differs","replacement-peer-differs","replacement-reused-epoch","accepted-B-fixture-binding-mismatch","accepted-B-positive-key-differs")){
    var changed=new HashMap<>(originals);var altered=receipt.deepCopy();var history=new ArrayList<>(entries);Path changedBody=null;byte[] beforeBody=null;
    JsonNode ref=null;JsonNode source=null;
    if(name.equals("foreign-history-run")){var e=history.getFirst();history.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
    else if(name.equals("duplicate-transcript-id"))history.add(history.getFirst());
    else if(name.equals("missing-native-http-original")){for(var row:altered.path("probes"))if(row.path("fixture").asText().equals("new-key-second-acs"))((ObjectNode)row).remove("nativeHttp");}
    else if(name.equals("corrupt-positive-response-signature")){var probe=receipt.path("probes").get(0);var request=byId.get(probe.path("requestReference").asText());var response=entries.stream().filter(e->("_"+request.correlationId()).equals(e.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();var document=SecureXml.parse(changed.get(response.id()));var node=document.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);var bytes=Base64.getMimeDecoder().decode(node.getTextContent());bytes[0]^=1;node.setTextContent(Base64.getEncoder().encodeToString(bytes));changed.put(response.id(),SecureXml.serialize(document));}
    else if(name.equals("replacement-reused-epoch")){((ObjectNode)altered.path("phases").get(3)).put("preparedReference",altered.path("phases").get(0).path("preparedReference").asText());}
    else if(name.equals("accepted-B-fixture-binding-mismatch")){((ObjectNode)altered.path("phases").get(3)).put("fixtureSha256","0".repeat(64));}
    else if(name.equals("same-length-unrelated-html")){var request=byId.get(receipt.path("probes").get(2).path("requestReference").asText());var response=entries.stream().filter(e->request.correlationId().equals(e.correlationId())&&"BROWSER".equals(e.method())).findFirst().orElseThrow();changedBody=temporary.resolve(response.bodyRef());beforeBody=Files.readAllBytes(changedBody);byte[] unrelated=new byte[beforeBody.length];Arrays.fill(unrelated,(byte)'x');Files.write(changedBody,unrelated);}
    else{
     if(name.startsWith("native-response-")||name.startsWith("native-request-")||name.startsWith("native-http-")){ref=altered.path("probes").get(2).path("nativeHttp");}
     else if(name.equals("restore-client-remains"))ref=altered.path("restoration").path("after");
     else if(name.equals("native-extra-local-policy"))ref=altered.path("probeState").path("before");
     else if(name.equals("native-config-kind-foreign"))ref=altered.path("phases").get(3).path("persisted");
     else if(name.equals("native-converter-request-not-original"))ref=altered.path("phases").get(3).path("converter");
     else if(name.equals("native-replacement-not-converter-output"))ref=altered.path("phases").get(3).path("persisted");
     else if(Set.of("replacement-native-client-differs","replacement-peer-differs").contains(name))ref=altered.path("phases").get(3).path("persisted");
     else if(name.equals("accepted-B-positive-key-differs"))ref=altered.path("probeState").path("before");
     else if(name.equals("native-path-source-corrupt"))ref=altered.path("restoration").path("before");
     else if(name.equals("epoch-order-foreign")){var phases=(ArrayNode)altered.path("phases");var first=phases.get(0).deepCopy();phases.set(0,phases.get(1));phases.set(1,first);}
     if(ref!=null){String reference=ref.path("reference").asText();source=JSON.mapper().readTree(changed.get(reference));var object=(ObjectNode)source;var nativeNode=source.path("native").isObject()?(ObjectNode)source.path("native"):null;
      switch(name){case "native-response-reference-foreign"->object.put("responseReference",entries.getFirst().id());case "native-request-id-foreign"->nativeNode.put("requestId","_foreign");case "native-request-hash-foreign"->nativeNode.put("requestSha256","0".repeat(64));case "native-http-body-hash-foreign"->nativeNode.put("responseBodySha256","0".repeat(64));case "native-http-response-before-request"->nativeNode.put("finishedAt","2026-01-01T00:00:00Z");case "restore-client-remains"->((ArrayNode)source.path("clients")).add("unrestored-client");case "native-extra-local-policy"->((ArrayNode)source.at("/policies/policies/policies")).add("local-constraint");case "native-config-kind-foreign"->object.put("kind","converter");case "native-converter-request-not-original"->nativeNode.put("requestSha256","0".repeat(64));case "native-replacement-not-converter-output"->((ObjectNode)source.path("mutation")).put("requestSha256","0".repeat(64));case "replacement-native-client-differs"->object.put("clientDatabaseId","00000000-0000-0000-0000-000000000000");case "replacement-peer-differs"->object.put("peerEntityId","http://localhost:18080/p/foreign");case "accepted-B-positive-key-differs"->((ObjectNode)source.at("/client/attributes")).put("saml.signing.certificate","broken");case "native-path-source-corrupt"->((ObjectNode)source.path("nativePaths")).put("jarSha256","0".repeat(64));default->throw new IllegalArgumentException(name);}
      var raw=JSON.mapper().writeValueAsBytes(source);changed.put(reference,raw);((ObjectNode)ref).put("sha256",sha(raw));
     }
    }
    Files.write(receiptFile,JSON.mapper().writeValueAsBytes(altered));var result=observe(MetadataSupersessionProbeTestCase.SUPERSESSION,run,history,changed,target,temporary,plan,data);var applicationControl=observe(MetadataSupersessionProbeTestCase.APPLICATION,run,history,changed,target,temporary,plan,data);require(applicationControl.outcome()==Outcome.NOT_VERIFIED,"Application regression accepted altered original: "+name);require(result.outcome()==Outcome.NOT_VERIFIED,"Altered evidence accepted: "+name+" "+result);checks.put(name,result.outcome().name());if(changedBody!=null)Files.write(changedBody,beforeBody);
   }
   var report=new TreeMap<String,Object>();report.put("runId",run);report.put("caseId",MetadataSupersessionProbeTestCase.SUPERSESSION);report.put("applicationRegression",application);report.put("outcome",base.outcome().name());report.put("reasonCode",base.reasonCode());report.put("details",base.details());report.put("evidence",base.evidence());report.put("checks",checks);report.put("privateKeyExported",false);JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),report);
  }finally{try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
