package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;

/** Archived production Reader replay; private keys and decrypted identifier values stay in Suite memory. */
public final class VerifyShibbolethRequestedSubjectMatch {
 static final JsonCodec JSON=new JsonCodec();
 static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 static void require(boolean b){if(!b)throw new IllegalArgumentException("Subject match replay incomplete");}
 static void copy(Path source,Path folder)throws Exception {if(Files.exists(folder))try(var paths=Files.walk(folder)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}Files.createDirectories(folder);try(var paths=Files.list(source)){for(var p:paths.toList()){require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS));Files.copy(p,folder.resolve(p.getFileName()));}}}
 static void put(Path folder,ObjectNode manifest,String file,byte[] raw)throws Exception{Files.write(folder.resolve(file),raw);((ObjectNode)manifest.path("originals")).put(file,hash(raw));}
 static CaseOutcome evaluate(Path root,ObjectNode manifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,PrivateKey key,boolean complete)throws Exception {
  var receipt=root.resolve(manifest.path("runId").asText()).resolve("manifest.json");if(!JSON.mapper().readTree(Files.readAllBytes(receipt)).equals(manifest))Files.write(receipt,JSON.mapper().writeValueAsBytes(manifest));
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return entries;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Replay sent an action");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("Replay changed originals");}};
  var context=new DefaultCaseContext(manifest.path("runId").asText(),TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
  return new ShibbolethRequestedSubjectMatchEvidence(root,e->bodies.get(e.id()),ignored->target,ignored->Optional.ofNullable(key)).read(context).orElse(CaseOutcome.notVerified("idp.subject.native-unproven","idp.subject.native-unproven"));
 }
 static TranscriptEntry changed(TranscriptEntry old,String run,String correlation,String decoded,Instant at){return new TranscriptEntry(old.id(),run,old.direction(),at,correlation,old.method(),old.url(),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),decoded,old.decodedSamlBytes(),old.contentType(),old.rawQuery(),old.samlSummary());}
 static Map<String,Object> lifecycle(Path root,ObjectNode manifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,PrivateKey key,CaseOutcome actual)throws Exception {
  var run=manifest.path("runId").asText();var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String selected){return entries;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Lifecycle sent an action");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("Lifecycle changed originals");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  var test=new RequestedSubjectMatchTestCase(new IdpExecutableBrowserFixtureScenarioTestCase(ShibbolethRequestedSubjectMatchEvidence.CASE,ignored->null),new ShibbolethRequestedSubjectMatchEvidence(root,e->bodies.get(e.id()),ignored->target,ignored->Optional.of(key)));
  var states=new CaseState("fixture-await",Map.of());var result=new TreeMap<String,Object>();
  require(test.start(context) instanceof CaseStep.Finish finish&&actual.equals(finish.outcome()));result.put("start",actual.outcome().name());
  for(var event:List.of(new CaseEvent.TranscriptReady(),new CaseEvent.Aborted("operator"),new CaseEvent.TimedOut(Duration.ZERO))){var step=test.resume(context,states,event);require(step instanceof CaseStep.Finish finish&&actual.equals(finish.outcome()));result.put(event.getClass().getSimpleName(),actual.outcome().name());}
  require(actual.equals(test.queuedEvidenceOutcome(context)));result.put("queued",actual.outcome().name());
  var previous=CaseOutcome.notVerified("browser_fixture_partial","browser.fixture-partial");require(test.reevaluateRecordedEvidence(context,previous).orElseThrow().outcome()==Outcome.VIOLATED);result.put("recorded-not-verified","VIOLATED");
  require(test.reevaluateRecordedEvidence(context,CaseOutcome.of(Outcome.SATISFIED,"existing",List.of())).isEmpty());result.put("recorded-conclusive",false);require(test.evidenceStatus(context).ready());result.put("status-ready",true);
  var incomplete=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,false);require(test.queuedEvidenceOutcome(incomplete).outcome()==Outcome.NOT_VERIFIED&&test.reevaluateRecordedEvidence(incomplete,previous).isEmpty());result.put("incomplete-history","NOT_VERIFIED");
  return result;
 }
 public static void main(String[]args)throws Exception {
  require(args.length==3);JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
  java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);
  var source=Path.of(args[0]);var browser=Path.of(args[1]);var base=(ObjectNode)JSON.mapper().readTree(source.resolve("manifest.json").toFile());var run=base.path("runId").asText();
  var created=JSON.mapper().readTree(browser.resolve("created.json").toFile());var plan=created.path("run").path("planId").asText();require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
  var entries=List.of(JSON.mapper().readValue(browser.resolve("transcript.json").toFile(),TranscriptEntry[].class));var bodies=new HashMap<String,byte[]>();for(var e:entries)if(e.decodedSamlRef()!=null){require(run.equals(e.runId())&&("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));var b=Files.readAllBytes(Path.of("/data").resolve(e.decodedSamlRef()));require(b.length==e.decodedSamlBytes());bodies.put(e.id(),b);}
  var target=Files.readAllBytes(Path.of("/data/target-metadata/"+run+".xml"));var raw=Files.readAllBytes(Path.of("/data/keys/"+plan+"/signing-key.pk8"));var key=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));Arrays.fill(raw,(byte)0);
  var temporary=Files.createTempDirectory("samlscope-subject-match-");var folder=temporary.resolve(run);var controls=new TreeMap<String,String>();
  try {copy(source,folder);var actual=evaluate(temporary,base.deepCopy(),entries,bodies,target,key,true);require(actual.outcome()==Outcome.VIOLATED);var wrapper=lifecycle(temporary,base,entries,bodies,target,key,actual);
   for(var mutation:List.of("missing-normal-response","wrong-normal-signature","missing-original","wrong-native-source","missing-audit","wrong-audit-principal","wrong-audit-request","wrong-restoration","wrong-readback","late-before-readback","early-after-readback","disabled-transform","different-native-runtime","wrong-fixed-target","wrong-decryption-key","missing-response","wrong-correlation","tampered-request","tampered-response","foreign-run","duplicate-entry","foreign-original-reference","incomplete-history","different-format-policy-exception","equal-id-no-policy")) {
    copy(source,folder);var manifest=base.deepCopy();var selected=new ArrayList<>(entries);var selectedBodies=new HashMap<>(bodies);var selectedTarget=target;PrivateKey selectedKey=key;boolean complete=true;var request=manifest.path("exchanges").get(0).path("requestReference").asText();var response=manifest.path("exchanges").get(0).path("responseReference").asText();
    switch(mutation) {
     case "missing-original" -> Files.delete(folder.resolve("configured-c14n.xml"));
     case "wrong-native-source" -> put(folder,manifest,"native-idp-conf-impl.jar",new byte[]{1,2,3});
     case "missing-audit" -> Files.delete(folder.resolve("native-request-bound-audit.log"));
     case "wrong-audit-principal","wrong-audit-request" -> {var audit=Files.readString(folder.resolve("native-request-bound-audit.log"));audit=mutation.equals("wrong-audit-principal")?audit.replace("samlscope-m0-user","another-user"):audit.replace("_action_","_foreign_action_");put(folder,manifest,"native-request-bound-audit.log",audit.getBytes(StandardCharsets.UTF_8));}
     case "wrong-restoration" -> put(folder,manifest,"final-c14n.xml","<wrong/>".getBytes(StandardCharsets.UTF_8));
     case "wrong-readback" -> put(folder,manifest,"before-protocol-c14n.xml","<wrong/>".getBytes(StandardCharsets.UTF_8));
     case "late-before-readback","early-after-readback" -> {var file=mutation.equals("late-before-readback")?"before-protocol-readback.json":"after-protocol-readback.json";var node=(ObjectNode)JSON.mapper().readTree(folder.resolve(file).toFile());node.put("recordedAt",mutation.equals("late-before-readback")?"2099-01-01T00:00:00Z":"1999-01-01T00:00:00Z");put(folder,manifest,file,JSON.mapper().writeValueAsBytes(node));}
     case "disabled-transform" -> put(folder,manifest,"configured-c14n.xml",Files.readString(folder.resolve("configured-c14n.xml")).replace("c14n/SAML2Transform","c14n/disabled").getBytes(StandardCharsets.UTF_8));
     case "different-native-runtime" -> {var node=(ArrayNode)JSON.mapper().readTree(folder.resolve("target-container-inspect-end.json").toFile());((ObjectNode)node.get(0)).put("Id","another-container");put(folder,manifest,"target-container-inspect-end.json",JSON.mapper().writeValueAsBytes(node));}
     case "wrong-fixed-target" -> selectedTarget="<wrong/>".getBytes(StandardCharsets.UTF_8);
     case "wrong-decryption-key" -> selectedKey=KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
     case "missing-response" -> selected.removeIf(e->e.id().equals(response));
     case "missing-normal-response" -> selected.removeIf(e->e.id().equals(manifest.path("normalControl").path("responseReference").asText()));
     case "wrong-normal-signature" -> {var ref=manifest.path("normalControl").path("responseReference").asText();var xml=SecureXml.parse(selectedBodies.get(ref));xml.getDocumentElement().setAttribute("ID","_tampered");selectedBodies.put(ref,SecureXml.serialize(xml));}
     case "wrong-correlation","foreign-run","foreign-original-reference" -> {var i=0;for(;i<selected.size();i++)if(selected.get(i).id().equals(response))break;var e=selected.get(i);selected.set(i,changed(e,mutation.equals("foreign-run")?"run_00000000000000000000000000":e.runId(),mutation.equals("wrong-correlation")?"_wrong":e.correlationId(),mutation.equals("foreign-original-reference")?"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml":e.decodedSamlRef(),e.timestamp()));}
     case "duplicate-entry" -> selected.add(selected.getFirst());
     case "incomplete-history" -> complete=false;
     case "tampered-request","tampered-response","different-format-policy-exception","equal-id-no-policy" -> {var ref=mutation.equals("tampered-response")?response:request;var xml=SecureXml.parse(selectedBodies.get(ref));var root=xml.getDocumentElement();if(mutation.equals("different-format-policy-exception")){var policy=xml.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol","samlp:NameIDPolicy");policy.setAttribute("Format","urn:oasis:names:tc:SAML:2.0:nameid-format:transient");root.appendChild(policy);}else if(mutation.equals("equal-id-no-policy")){var sp=com.samlscope.saml.normal.SecureXml.parse(Files.readAllBytes(source.resolve("suite-sp-metadata.xml"))).getDocumentElement();var cert=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(sp.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate").item(0).getTextContent())));var targetXml=SecureXml.parse(target).getDocumentElement();var assertion=VerifiedResponseAssertion.read(SecureXml.parse(bodies.get(response)).getDocumentElement(),targetXml.getAttribute("entityID"),MetadataAlgorithmEvidence.signingKeys(targetXml),sp,Optional.of(new com.samlscope.saml.crypto.PlanCredentials(key,cert)),root.getAttribute("ID"),root.getAttribute("AssertionConsumerServiceURL"));var subject=MetadataAlgorithmEvidence.children(root,"urn:oasis:names:tc:SAML:2.0:assertion","Subject").getFirst();var old=MetadataAlgorithmEvidence.children(subject,"urn:oasis:names:tc:SAML:2.0:assertion","NameID").getFirst();var actualName=MetadataAlgorithmEvidence.children(MetadataAlgorithmEvidence.children(assertion,"urn:oasis:names:tc:SAML:2.0:assertion","Subject").getFirst(),"urn:oasis:names:tc:SAML:2.0:assertion","NameID").getFirst();subject.replaceChild(xml.importNode(actualName,true),old);require(!ShibbolethRequestedSubjectMatchEvidence.decisiveMismatch(root,actualName));}else root.setAttribute("ID","_tampered");selectedBodies.put(ref,SecureXml.serialize(xml));}
    }
    var outcome=evaluate(temporary,manifest,selected,selectedBodies,selectedTarget,selectedKey,complete);require(outcome.outcome()==Outcome.NOT_VERIFIED);controls.put(mutation,outcome.outcome().name());
   }
   // Independent semantic checks use in-memory plaintext only, never an unsigned positive product verdict.
   var doc=SecureXml.newDocument();var name=doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion","saml:NameID");name.setAttribute("Format","urn:oasis:names:tc:SAML:2.0:nameid-format:transient");name.setTextContent("same");var equal=(org.w3c.dom.Element)name.cloneNode(true);require(ShibbolethRequestedSubjectMatchEvidence.stronglyMatches(name,equal));
   var attrChecks=new TreeMap<String,Boolean>();for(var attr:List.of("Format","NameQualifier","SPNameQualifier","SPProvidedID")){var other=(org.w3c.dom.Element)equal.cloneNode(true);other.setAttribute(attr,"different");require(!ShibbolethRequestedSubjectMatchEvidence.stronglyMatches(name,other));attrChecks.put(attr,true);}
   JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(),Map.of("runId",run,"outcome",actual,"controls",controls,"allAttributeChecks",attrChecks,"wrapperLifecycle",wrapper,"equalIdentifierStrongMatch",true,"productOperations",0,"privateKeyPersisted",false,"decryptedIdentifierPersisted",false,"originalDecodedSha256",bodies.entrySet().stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,e->{try{return hash(e.getValue());}catch(Exception impossible){throw new IllegalStateException();}}))));
  }finally {try(var paths=Files.walk(temporary)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
