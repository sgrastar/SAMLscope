package com.samlscope.runner.cases;

import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.cert.*;
import java.time.Clock;
import java.util.*;
import org.w3c.dom.Element;

/** Replays the archived production fixture factory; native readbacks prove admission only. */
public final class VerifyKeycloakMdiopRepresentationEvidence {
 private static final JsonCodec JSON=new JsonCodec();
 private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",DS="http://www.w3.org/2000/09/xmldsig#",P="urn:oasis:names:tc:SAML:2.0:protocol";
 private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 private static void require(boolean yes,String why){if(!yes)throw new IllegalArgumentException(why);}
 private static TranscriptEntry replacement(TranscriptEntry e,String url,Direction direction,Map<String,Object> summary){return new TranscriptEntry(e.id(),e.runId(),direction,e.timestamp(),e.correlationId(),e.method(),url,e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),summary);}
 private static CaseOutcome nativeObserve(Path directory,String run,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target){
  var normalized=entries.stream().map(e->{var raw=bodies.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(id.equals(run),"Wrong requested Run");return normalized;}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  return new KeycloakMdiopRepresentationEvidenceFile(directory,e->bodies.get(e.id())).evaluate(context,target);
 }
 public static void main(String[]args)throws Exception{
  if(args.length!=3)throw new IllegalArgumentException("folder data output required");
  var folder=Path.of(args[0]).toAbsolutePath();var output=Path.of(args[2]);require(!Files.exists(output),"Immutable replay already exists");
  var created=JSON.mapper().readTree(folder.resolve("created.json").toFile());var run=created.at("/run/id").asText();var plan=created.at("/run/planId").asText();
  var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
  var originals=new HashMap<String,byte[]>();var byId=new HashMap<String,TranscriptEntry>();
  for(var e:entries)require(e.runId().equals(run)&&byId.put(e.id(),e)==null,"Foreign/duplicate transcript");
  for(var row:JSON.mapper().readTree(folder.resolve("decoded-manifest.json").toFile())){
   var path=folder.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(folder.resolve("decoded")),"Original path escaped");
   var raw=Files.readAllBytes(path);var e=byId.get(row.path("id").asText());require(e!=null&&e.decodedSamlBytes()==raw.length&&sha(raw).equals(row.path("sha256").asText())&&originals.put(e.id(),raw)==null,"Original hash/length differs");
  }
  var temporary=Files.createTempDirectory("keycloak-mdiop-reader-");
  var receipt=JSON.mapper().readTree(folder.resolve("qualified-receipt.json").toFile());
  var target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(id.equals(run),"Foreign Run");return entries;}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  var checks=new TreeMap<String,String>();var observed=new TreeMap<String,Object>();
  try{
   var path=temporary.resolve(run+".mdiop-representation.json");Files.copy(folder.resolve("qualified-receipt.json"),path);
   var base=nativeObserve(temporary,run,entries,originals,target);
   require(base.outcome()==Outcome.SATISFIED,"Native original reader did not satisfy "+base);checks.put("complete-native-admission",base.outcome().name());
   for(var index=0;index<KeycloakMdiopRepresentationEvidenceFile.REQUIRED.size();index++){
    var changed=new HashMap<>(originals);var member=receipt.path("members").get(index);var ref=member.path("converter");var node=JSON.mapper().readTree(originals.get(ref.path("reference").asText()));
    ((com.fasterxml.jackson.databind.node.ObjectNode)node.path("native")).put("status",400);
    var raw=JSON.mapper().writeValueAsBytes(node);changed.put(ref.path("reference").asText(),raw);var altered=receipt.deepCopy();
    ((com.fasterxml.jackson.databind.node.ObjectNode)altered.path("members").get(index).path("converter")).put("sha256",sha(raw));Files.write(path,JSON.mapper().writeValueAsBytes(altered));
    var outcome=nativeObserve(temporary,run,entries,changed,target);require(outcome.outcome()==Outcome.NOT_VERIFIED,"Native representation refusal was ignored");checks.put("native-refused:"+member.path("variant").asText(),outcome.outcome().name());
   }
   for(var name:List.of("missing-member","foreign-run-original","foreign-fixture-hash","foreign-client-identity","converter-request-not-original","restoration-client-remains","baseline-response-signature-corrupt","wrong-adapter","restoration-reference-missing")){
    var altered=receipt.deepCopy();var changed=new HashMap<>(originals);
    if(name.equals("missing-member"))((com.fasterxml.jackson.databind.node.ArrayNode)altered.path("members")).remove(3);
    else if(name.equals("wrong-adapter"))((com.fasterxml.jackson.databind.node.ObjectNode)altered).put("adapter","assertion-only");
    else if(name.equals("restoration-reference-missing"))((com.fasterxml.jackson.databind.node.ObjectNode)altered.path("restoredClients")).put("reference","tx_00000000000000000000000000");
    else if(name.equals("baseline-response-signature-corrupt")){
     var response=entries.stream().filter(e->e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&MetadataProbeCorrelation.matches(e.url(),run,"control")).findFirst().orElseThrow();
     var xml=SecureXml.parse(changed.get(response.id()));var value=xml.getElementsByTagNameNS(DS,"SignatureValue").item(0);var raw=Base64.getMimeDecoder().decode(value.getTextContent());raw[0]^=1;value.setTextContent(Base64.getEncoder().encodeToString(raw));changed.put(response.id(),SecureXml.serialize(xml));
    } else {
     var ref=name.equals("restoration-client-remains")?altered.path("restoredClients"):altered.path("members").get(3).path("converter");var id=ref.path("reference").asText();var nativeNode=JSON.mapper().readTree(changed.get(id));
     if(name.equals("foreign-run-original"))((com.fasterxml.jackson.databind.node.ObjectNode)nativeNode).put("runId","run_00000000000000000000000000");
     if(name.equals("foreign-fixture-hash"))((com.fasterxml.jackson.databind.node.ObjectNode)nativeNode).put("fixtureSha256","0".repeat(64));
     if(name.equals("converter-request-not-original"))((com.fasterxml.jackson.databind.node.ObjectNode)nativeNode.path("native")).put("request_sha256","0".repeat(64));
     if(name.equals("foreign-client-identity")||name.equals("restoration-client-remains")){
      var body=JSON.mapper().readTree(Base64.getDecoder().decode(nativeNode.path("native").path("response_base64").asText()));
      if(name.equals("foreign-client-identity"))((com.fasterxml.jackson.databind.node.ObjectNode)body).put("clientId","https://foreign.example/sp");
      else ((com.fasterxml.jackson.databind.node.ArrayNode)body).add(JSON.mapper().createObjectNode().put("id","remaining"));
      var bytes=JSON.mapper().writeValueAsBytes(body);((com.fasterxml.jackson.databind.node.ObjectNode)nativeNode.path("native")).put("response_base64",Base64.getEncoder().encodeToString(bytes)).put("response_sha256",sha(bytes));
     }
     var raw=JSON.mapper().writeValueAsBytes(nativeNode);changed.put(id,raw);((com.fasterxml.jackson.databind.node.ObjectNode)ref).put("sha256",sha(raw));
    }
    Files.write(path,JSON.mapper().writeValueAsBytes(altered));var outcome=nativeObserve(temporary,run,entries,changed,target);require(outcome.outcome()==Outcome.NOT_VERIFIED,"Altered original was adopted "+name);checks.put(name,outcome.outcome().name());
   }
   observed.put("runId",run);observed.put("caseId",KeycloakMdiopRepresentationEvidenceFile.ID);observed.put("outcome",base.outcome().name());observed.put("reasonCode",base.reasonCode());observed.put("details",base.details());observed.put("evidence",base.evidence());observed.put("checks",checks);observed.put("configurationWrites",0);observed.put("privateKeyExported",false);observed.put("runtimeKeyInterpretationProven",false);
   JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),observed);
  }finally{try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
 }
}
