package com.samlscope.runner.cases;
import com.samlscope.core.caseexec.*;
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

/** Actual production native UI reader and recomputed original-proof controls; no target action. */
public final class VerifyKeycloakUiSafetyEvidence {
 private static final JsonCodec JSON=new JsonCodec();
 private static void require(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}
 private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 private static CaseOutcome observe(String run,List<TranscriptEntry> history,Map<String,byte[]> originals,byte[] target,Path directory,String id){return observe(run,history,originals,target,directory,id,false);}
 private static CaseOutcome observe(String run,List<TranscriptEntry> history,Map<String,byte[]> originals,byte[] target,Path directory,String id,boolean offline){
  var normalized=history.stream().map(e->{var raw=originals.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String id){require(run.equals(id),"Foreign context");return normalized;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  return new KeycloakUiSafetyEvidence(directory,e->originals.get(e.id()),offline).evaluate(context,target).orElseGet(()->CaseOutcome.notVerified("native_absent","native_absent"));
 }
 private static JsonNode member(JsonNode receipt,String variant){for(var m:receipt.path("members"))if(variant.equals(m.path("variant").asText()))return m;throw new IllegalArgumentException("Missing member");}
 private static ObjectNode changeOriginal(Map<String,byte[]> originals,JsonNode ref)throws Exception{return (ObjectNode)JSON.mapper().readTree(originals.get(ref.path("reference").asText()));}
 private static void replace(Map<String,byte[]> originals,JsonNode ref,JsonNode record)throws Exception{var raw=JSON.mapper().writeValueAsBytes(record);originals.put(ref.path("reference").asText(),raw);((ObjectNode)ref).put("sha256",sha(raw));}
 public static void main(String[] args)throws Exception{
  require(args.length==3,"folder data output required");var folder=Path.of(args[0]);var output=Path.of(args[2]);require(!Files.exists(output),"Immutable replay already exists");
  String run=JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();var history=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var by=new HashMap<String,TranscriptEntry>();for(var e:history)require(run.equals(e.runId())&&by.put(e.id(),e)==null,"Original history foreign/ambiguous");
  var originals=new HashMap<String,byte[]>();for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){var path=folder.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Decoded escape");var raw=Files.readAllBytes(path);var e=by.get(row.path("id").asText());require(e!=null&&raw.length==e.decodedSamlBytes()&&sha(raw).equals(row.path("sha256").asText()),"Original decoded changed");originals.put(e.id(),raw);}
  var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var receipt=JSON.mapper().readTree(folder.resolve("qualified-receipt.json").toFile());var temporary=Files.createTempDirectory("kc-native-ui-");var directory=temporary.resolve("ui-native-feature-absence");Files.createDirectories(directory);var file=directory.resolve(run+".keycloak-ui-safety.json");var source=directory.resolve(run+".keycloak-ui-safety");Files.createDirectories(source);
  try{
   Files.copy(folder.resolve("qualified-receipt.json"),file);Files.copy(folder.resolve("native-source/before-services.jar"),source.resolve("native-services.jar"));Files.copy(folder.resolve("native-source/before-themes.jar"),source.resolve("native-themes.jar"));
   var outcome=observe(run,history,originals,target,directory,KeycloakUiSafetyEvidence.CASE);require(outcome.outcome()==Outcome.SATISFIED_WITH_NOTE,"Native safety proof incomplete "+outcome);
   var checks=new TreeMap<String,Object>();checks.put("stock-native-image-sink-and-unused-urls",outcome.outcome().name());
   for(String name:List.of("foreign-history-run","duplicate-transcript-id","foreign-receipt-run","foreign-target","foreign-peer","foreign-campaign","missing-fixture-member","duplicate-fixture-member","missing-native-browser-original","missing-native-converter","wrong-converter-fixture","invented-ui-setting","native-local-theme-changed","runtime-epoch-changed","client-left-unrestored","wrong-native-source","wrong-native-theme","preferred-language-unavailable","native-session-context-replaced","same-length-unrelated-public-html","native-ui-dom-unbound","browser-request-id-unbound","browser-request-bytes-unbound","browser-response-not-signed","native-refusal-fabricated","native-validation-not-source-bound","saved-native-ui-substitution","source-policy-supplement-added","overlapping-native-epochs","detector-svg-unexecuted","detector-javascript-unexecuted","detector-safe-sink-executed","second-credential-hidden","native-image-nonexecuting-payload","foreign-decoded-reference")){
    var altered=(ObjectNode)receipt.deepCopy();var changed=new HashMap<>(originals);var changedHistory=new ArrayList<>(history);Path corrupted=null;byte[] old=null;
    if(name.equals("foreign-decoded-reference")){var e=history.stream().filter(t->t.decodedSamlRef()!=null).findFirst().orElseThrow();int index=history.indexOf(e);changedHistory.set(index,new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml",e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
    else if(name.equals("foreign-history-run")){var e=history.getFirst();changedHistory.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
    else if(name.equals("duplicate-transcript-id"))changedHistory.add(history.getFirst());
    else if(name.equals("foreign-receipt-run"))altered.put("runId","run_00000000000000000000000000");
    else if(name.equals("foreign-target"))altered.put("targetMetadataSha256","0".repeat(64));
    else if(name.equals("foreign-peer"))altered.put("peerEntityId","http://localhost:18080/p/plan_00000000000000000000000000");
    else if(name.equals("foreign-campaign"))altered.put("campaignId","foreign");
    else if(name.equals("missing-fixture-member"))((ArrayNode)altered.path("members")).remove(1);
    else if(name.equals("duplicate-fixture-member"))((ArrayNode)altered.path("members")).set(2,altered.path("members").get(1).deepCopy());
    else if(name.equals("missing-native-browser-original"))changed.remove(member(altered,"ui-safety-logo-data").path("browser").path("reference").asText());
    else if(name.equals("missing-native-converter"))changed.remove(member(altered,"ui-safety-logo-data").path("converter").path("reference").asText());
    else if(name.equals("wrong-native-source")||name.equals("wrong-native-theme")){corrupted=source.resolve(name.equals("wrong-native-source")?"native-services.jar":"native-themes.jar");old=Files.readAllBytes(corrupted);var raw=old.clone();raw[100]^=1;Files.write(corrupted,raw);}
    else if(name.equals("browser-response-not-signed")){var ex=changeOriginal(changed,member(altered,"control").path("browser")).path("exchange").path("transcript_ids");for(var ref:ex){var e=by.get(ref.asText());if(e.direction()!=Direction.INBOUND)continue;var doc=SecureXml.parse(changed.get(e.id()));var value=doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);var raw=Base64.getMimeDecoder().decode(value.getTextContent());raw[0]^=1;value.setTextContent(Base64.getEncoder().encodeToString(raw));changed.put(e.id(),SecureXml.serialize(doc));}}
    else{
     JsonNode ref=switch(name){case "native-local-theme-changed","runtime-epoch-changed","source-policy-supplement-added"->altered.path("restoration").path("scopeBefore");case "client-left-unrestored"->altered.path("restoration").path("after");case "wrong-converter-fixture"->member(altered,"ui-safety-logo-data").path("converter");case "invented-ui-setting"->member(altered,"ui-safety-logo-data").path("application");case "native-refusal-fabricated","native-validation-not-source-bound"->member(altered,"ui-safety-privacy-javascript").path("application");case "saved-native-ui-substitution"->member(altered,"ui-safety-information-javascript").path("persisted");default->member(altered,"ui-safety-logo-data").path("browser");};
     var record=changeOriginal(changed,ref);var observation=record.path("observation").isObject()?(ObjectNode)record.path("observation"):null;
     switch(name){
      case "wrong-converter-fixture"->((ObjectNode)record.path("native")).put("requestSha256","0".repeat(64));
      case "invented-ui-setting"->((ObjectNode)record.path("native")).put("requestSha256","0".repeat(64));
      case "native-local-theme-changed"->((ObjectNode)record.path("realm")).put("loginTheme","custom");
      case "runtime-epoch-changed"->((ObjectNode)record.path("runtime")).put("containerId","0".repeat(64));
      case "source-policy-supplement-added"->((ArrayNode)record.at("/clientPolicies/policies/policies")).add("added-ui-policy");
      case "client-left-unrestored"->((ArrayNode)record.path("clients")).add("remaining-client");
      case "preferred-language-unavailable"->observation.put("preferredLanguage","ja-JP");
      case "native-session-context-replaced"->observation.put("contextIndex",2);
      case "browser-request-id-unbound"->((ObjectNode)observation.path("requests").get(0)).put("requestId","_foreign");
      case "browser-request-bytes-unbound"->((ObjectNode)observation.path("requests").get(0)).put("sha256","0".repeat(64));
      case "native-refusal-fabricated"->((ObjectNode)record.path("native")).put("status",201);
      case "native-validation-not-source-bound"->((ObjectNode)record.path("native")).put("url","http://localhost:18180/arbitrary");
      case "saved-native-ui-substitution"->((ObjectNode)record.at("/client/attributes")).put("logoUri","data:image/svg+xml;base64,AA==");
      case "native-ui-dom-unbound"->((ObjectNode)observation.path("consent").path("images").get(0)).put("src","file:///unrelated");
      case "overlapping-native-epochs"->observation.put("startedAt","2026-09-01T00:00:00Z");
      case "detector-svg-unexecuted"->((ArrayNode)observation.at("/detector/activeSvg/dialogs")).removeAll();
      case "detector-javascript-unexecuted"->((ArrayNode)observation.at("/detector/javascriptAnchor/dialogs")).removeAll();
      case "detector-safe-sink-executed"->((ArrayNode)observation.at("/detector/safeImg/dialogs")).add(observation.at("/detector/activeSvg/dialogs/0").deepCopy());
      case "second-credential-hidden"->observation.put("credentialSubmissions",2);
      case "native-image-nonexecuting-payload"->((ObjectNode)observation.at("/consent/images/0")).put("naturalWidth",0);
      case "same-length-unrelated-public-html"->{var raw=Base64.getDecoder().decode(record.path("publicHtmlBase64").asText());String html=new String(raw,java.nio.charset.StandardCharsets.UTF_8);html=html.replace("id=\"kc-oauth\"","id=\"no-oauth\"");raw=html.getBytes(java.nio.charset.StandardCharsets.UTF_8);record.put("publicHtmlBase64",Base64.getEncoder().encodeToString(raw));var c=(ObjectNode)observation.path("consent");c.put("publicHtmlSha256",sha(raw));c.put("publicHtmlBytes",raw.length);}
      default->throw new IllegalArgumentException(name);
     }
     replace(changed,ref,record);
    }
    Files.write(file,JSON.mapper().writeValueAsBytes(altered));var result=observe(run,changedHistory,changed,target,directory,KeycloakUiSafetyEvidence.CASE);require(result.outcome()==Outcome.NOT_VERIFIED,"Invalid original accepted "+name+" "+result);checks.put(name,result.outcome().name());if(corrupted!=null)Files.write(corrupted,old);Files.copy(folder.resolve("qualified-receipt.json"),file,StandardCopyOption.REPLACE_EXISTING);
   }
   var calibrated=(ObjectNode)receipt.deepCopy();calibrated.put("counterfactualCalibrationOnly",true);var ref=calibrated.putObject("isolatedCalibration");var calibration=folder.resolve("calibration-with-native-csp");
   for(var name:List.of("isolated-input.json","isolated-output.json","isolated-renderer.mjs","native-policy-supplement.json"))Files.copy(calibration.resolve(name),source.resolve(name));
   ref.put("inputFile","isolated-input.json").put("outputFile","isolated-output.json").put("rendererFile","isolated-renderer.mjs").put("inputSha256",sha(Files.readAllBytes(source.resolve("isolated-input.json")))).put("outputSha256",sha(Files.readAllBytes(source.resolve("isolated-output.json")))).put("rendererSha256",sha(Files.readAllBytes(source.resolve("isolated-renderer.mjs")))).put("nativePolicySha256",sha(Files.readAllBytes(source.resolve("native-policy-supplement.json"))));
   Files.write(file,JSON.mapper().writeValueAsBytes(calibrated));var offline=observe(run,history,originals,target,directory,KeycloakUiSafetyEvidence.CASE,true);require(offline.outcome()==Outcome.VIOLATED,"Actual isolated unsafe renderer not detected "+offline);checks.put("offline-approved-unsanitized-information-consumer",offline.outcome().name());
   var publicResult=observe(run,history,originals,target,directory,KeycloakUiSafetyEvidence.CASE);require(publicResult.outcome()==Outcome.NOT_VERIFIED,"Production accepted diagnostic renderer");checks.put("production-counterfactual-renderer-forbidden",publicResult.outcome().name());
   for(var name:List.of("calibration-label-only","calibration-source-unbound","calibration-native-policy-substituted")){
    var changed=(ObjectNode)calibrated.deepCopy();Path asset=null;byte[] oldAsset=null;
    if(name.equals("calibration-label-only"))changed.remove("isolatedCalibration");
    else if(name.equals("calibration-source-unbound"))((ObjectNode)changed.path("isolatedCalibration")).put("rendererSha256","0".repeat(64));
    else{asset=source.resolve("native-policy-supplement.json");oldAsset=Files.readAllBytes(asset);var policy=(ObjectNode)JSON.mapper().readTree(oldAsset);((ObjectNode)policy.path("browserSecurityHeaders")).put("contentSecurityPolicy","script-src 'none'");Files.write(asset,JSON.mapper().writeValueAsBytes(policy));((ObjectNode)changed.path("isolatedCalibration")).put("nativePolicySha256",sha(Files.readAllBytes(asset)));}
    Files.write(file,JSON.mapper().writeValueAsBytes(changed));var bad=observe(run,history,originals,target,directory,KeycloakUiSafetyEvidence.CASE,true);require(bad.outcome()==Outcome.NOT_VERIFIED,"Invalid calibration accepted "+name);checks.put(name,bad.outcome().name());if(asset!=null)Files.write(asset,oldAsset);
   }
   Files.copy(folder.resolve("qualified-receipt.json"),file,StandardCopyOption.REPLACE_EXISTING);
   var report=new TreeMap<String,Object>();report.put("runId",run);report.put("cases",Map.of(KeycloakUiSafetyEvidence.CASE,outcome));report.put("checks",checks);report.put("privateKeyExported",false);report.put("productConfigurationWrites",0);report.put("samlRequests",0);JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),report);
  }finally{try(var paths=Files.walk(temporary)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
