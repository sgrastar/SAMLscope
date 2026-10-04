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
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import java.util.function.BiFunction;
import com.fasterxml.jackson.databind.node.*;

/** Production reader replay; private keys and decrypted assertion remain inside Suite memory. */
public final class VerifyKeycloakSelfContainedTrustEvidence {
 private static final JsonCodec JSON=new JsonCodec();
 private static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 private static void require(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}
 private static CaseOutcome observe(String run,List<TranscriptEntry> history,Map<String,byte[]> originals,byte[] target,Path temporary,Path data,int keyMutation){
  var normalized=history.stream().map(e->{var raw=originals.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String id){require(run.equals(id),"Foreign context");return normalized;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  var bridge=new KeycloakNativeRunEvidenceBridge(data);
  BiFunction<String,String,Optional<PlanCredentials>> keys=(r,v)->bridge.key(r,keyMutation==1&&v.equals("no-valid-until")?"control":keyMutation==2&&v.equals("control")?"no-valid-until":v);
  return new KeycloakSelfContainedTrustEvidenceFile(temporary.resolve("metadata-rejection-evidence"),e->originals.get(e.id()),keys).evaluate(context,target);
 }
 public static void main(String[] args)throws Exception{
  require(args.length==3,"folder data output required");var folder=Path.of(args[0]);var data=Path.of(args[1]);var output=Path.of(args[2]);require(!Files.exists(output),"Immutable replay exists");
  String run=JSON.mapper().readTree(folder.resolve("created.json").toFile()).at("/run/id").asText();var history=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));var by=new HashMap<String,TranscriptEntry>();for(var e:history)require(run.equals(e.runId())&&by.put(e.id(),e)==null,"Foreign/duplicate original");
  var originals=new HashMap<String,byte[]>();for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){var p=folder.resolve(row.path("file").asText()).normalize();require(p.getParent().equals(folder.resolve("decoded")),"Decoded escape");var raw=Files.readAllBytes(p);var e=by.get(row.path("id").asText());require(e!=null&&raw.length==e.decodedSamlBytes()&&sha(raw).equals(row.path("sha256").asText()),"Decoded changed");originals.put(e.id(),raw);}
  var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));var nativeReceipt=JSON.mapper().readTree(folder.resolve("qualified-receipt.json").toFile());var trustReceipt=JSON.mapper().readTree(folder.resolve("trust-receipt.json").toFile());var temporary=Files.createTempDirectory("kc-native-trust-");var directory=temporary.resolve("metadata-rejection-evidence");Files.createDirectories(directory);var nativeFile=directory.resolve(run+".keycloak-supersession.json");var trustFile=directory.resolve(run+".native-trust.json");var payload=directory.resolve(run+".native-trust");Files.createDirectory(payload);
  try{
   for(var row:JSON.mapper().readTree(folder.resolve("browser-originals-manifest.json").toFile())){var e=by.get(row.path("id").asText());var raw=Files.readAllBytes(folder.resolve(row.path("file").asText()));require(e!=null&&sha(raw).equals(row.path("sha256").asText())&&raw.length==e.bodyBytes(),"Body changed");var path=temporary.resolve(e.bodyRef());require(path.normalize().startsWith(temporary),"Body escape");Files.createDirectories(path.getParent());Files.write(path,raw);}
   for(var name:List.of("native-services.jar","native-saml-core.jar"))Files.copy(folder.resolve("native-source").resolve(name),payload.resolve(name));
   Files.copy(folder.resolve("qualified-receipt.json"),nativeFile);Files.copy(folder.resolve("trust-receipt.json"),trustFile);
   var base=observe(run,history,originals,target,temporary,data,0);require(base.outcome()==Outcome.SATISFIED,"Native trust not proven: "+base);var checks=new TreeMap<String,String>();checks.put("native-metadata-only-signature-encryption",base.outcome().name());
   for(String name:List.of("foreign-history-run","duplicate-transcript-id","foreign-trust-run","foreign-trust-target","foreign-trust-peer","foreign-trust-campaign","missing-native-receipt","native-source-byte-corrupt","native-locator-byte-corrupt","restore-client-remains","native-extra-local-policy","native-converter-request-not-original","native-replacement-not-converter-output","native-path-source-corrupt","signing-certificate-substitution","encryption-certificate-substitution","external-metadata-loader-enabled","signature-check-disabled","encryption-disabled","corrupt-positive-response-signature","corrupt-negative-request-signature-control","wrong-positive-decryption-key","same-key-negative-decryption-control")){
    var changed=new HashMap<>(originals);var alteredNative=nativeReceipt.deepCopy();var alteredTrust=(ObjectNode)trustReceipt.deepCopy();var changedHistory=new ArrayList<>(history);Path corruptFile=null;byte[] restoreBytes=null;int mutation=0;
    if(name.equals("foreign-history-run")){var e=changedHistory.getFirst();changedHistory.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
    else if(name.equals("duplicate-transcript-id"))changedHistory.add(changedHistory.getFirst());
    else if(name.startsWith("foreign-trust-")){String field=switch(name){case "foreign-trust-run"->"runId";case "foreign-trust-target"->"targetMetadataSha256";case "foreign-trust-peer"->"peerEntityId";default->"campaignId";};alteredTrust.put(field,"foreign");}
    else if(name.equals("missing-native-receipt"))Files.delete(nativeFile);
    else if(name.equals("native-source-byte-corrupt")||name.equals("native-locator-byte-corrupt")){corruptFile=payload.resolve(name.equals("native-source-byte-corrupt")?"native-services.jar":"native-saml-core.jar");restoreBytes=Files.readAllBytes(corruptFile);var corrupt=restoreBytes.clone();corrupt[100]^=1;Files.write(corruptFile,corrupt);}
    else if(name.equals("wrong-positive-decryption-key"))mutation=1;
    else if(name.equals("same-key-negative-decryption-control"))mutation=2;
    else if(name.equals("corrupt-positive-response-signature")){var request=by.get(nativeReceipt.path("probes").get(0).path("requestReference").asText());var response=history.stream().filter(e->("_"+request.correlationId()).equals(e.samlSummary().get("inResponseTo"))).findFirst().orElseThrow();var doc=SecureXml.parse(changed.get(response.id()));var value=doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);var raw=Base64.getMimeDecoder().decode(value.getTextContent());raw[0]^=1;value.setTextContent(Base64.getEncoder().encodeToString(raw));changed.put(response.id(),SecureXml.serialize(doc));}
    else {
     var ref=switch(name){case "restore-client-remains"->alteredNative.path("restoration").path("after");case "native-converter-request-not-original"->alteredNative.path("phases").get(3).path("converter");case "native-replacement-not-converter-output"->alteredNative.path("phases").get(3).path("persisted");case "native-path-source-corrupt"->alteredNative.path("restoration").path("before");case "corrupt-negative-request-signature-control"->alteredNative.path("probes").get(8).path("nativeHttp");default->alteredNative.path("probeState").path("before");};
     String id=ref.path("reference").asText();var record=JSON.mapper().readTree(changed.get(id));
     switch(name){case "restore-client-remains"->((ArrayNode)record.path("clients")).add("unrestored");case "native-extra-local-policy"->((ArrayNode)record.at("/policies/policies/policies")).add("extra");case "native-converter-request-not-original"->((ObjectNode)record.path("native")).put("requestSha256","0".repeat(64));case "native-replacement-not-converter-output"->((ObjectNode)record.path("mutation")).put("requestSha256","0".repeat(64));case "native-path-source-corrupt"->((ObjectNode)record.path("nativePaths")).put("jarSha256","0".repeat(64));case "corrupt-negative-request-signature-control"->((ObjectNode)record.path("native")).put("requestId","_foreign");default->{var attrs=(ObjectNode)record.at("/client/attributes");switch(name){case "signing-certificate-substitution"->attrs.put("saml.signing.certificate","AA==");case "encryption-certificate-substitution"->attrs.put("saml.encryption.certificate","AA==");case "external-metadata-loader-enabled"->attrs.put("saml.useMetadataDescriptorUrl","true");case "signature-check-disabled"->attrs.put("saml.client.signature","false");case "encryption-disabled"->attrs.put("saml.encrypt","false");default->throw new IllegalArgumentException(name);}}}
     var raw=JSON.mapper().writeValueAsBytes(record);changed.put(id,raw);((ObjectNode)ref).put("sha256",sha(raw));
    }
    if(!name.equals("missing-native-receipt")){var raw=JSON.mapper().writeValueAsBytes(alteredNative);Files.write(nativeFile,raw);alteredTrust.put("nativeCampaignReceiptSha256",sha(raw));}Files.write(trustFile,JSON.mapper().writeValueAsBytes(alteredTrust));
    var result=observe(run,changedHistory,changed,target,temporary,data,mutation);require(result.outcome()==Outcome.NOT_VERIFIED,"Altered native trust evidence accepted: "+name+" "+result);checks.put(name,result.outcome().name());
    if(corruptFile!=null)Files.write(corruptFile,restoreBytes);Files.copy(folder.resolve("qualified-receipt.json"),nativeFile,StandardCopyOption.REPLACE_EXISTING);Files.copy(folder.resolve("trust-receipt.json"),trustFile,StandardCopyOption.REPLACE_EXISTING);
   }
   var report=new TreeMap<String,Object>();report.put("runId",run);report.put("caseId",KeycloakSelfContainedTrustEvidenceFile.ID);report.put("outcome",base.outcome().name());report.put("reasonCode",base.reasonCode());report.put("details",base.details());report.put("evidence",base.evidence());report.put("checks",checks);report.put("privateKeyExported",false);report.put("plaintextPersisted",false);JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),report);
  }finally{try(var files=Files.walk(temporary)){for(var p:files.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
