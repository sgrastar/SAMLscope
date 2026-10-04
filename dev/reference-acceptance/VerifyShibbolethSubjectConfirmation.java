package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;

/** Archived production leaf replay. Plan credentials and decrypted assertions exist only in Suite memory. */
public final class VerifyShibbolethSubjectConfirmation {
 static final JsonCodec JSON=new JsonCodec();
 private record UnreachableFallback(String id) implements TestCase,ConfigurationPrompt,AttestationPrompt {
  public TargetRole role(){return TargetRole.IDP;}public String instructionEn(){return "approved CONFIG";}public String promptEn(){return "approved CONFIG";}public List<AttestationOption> options(){return List.of();}
  public CaseStep start(CaseContext c){throw new AssertionError("Owned proof used declaration fallback");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Owned proof used declaration fallback");}
 }
 static Map<String,Object> lifecycle(Path root,ObjectNode m,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,PlanCredentials keys,Map<String,CaseOutcome> outcomes)throws Exception {
  var run=m.path("runId").asText();var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return entries;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Lifecycle sent an action");}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new AssertionError("Lifecycle changed originals");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);var results=new TreeMap<String,Object>();
  for(var row:outcomes.entrySet()) {
   var id=row.getKey();var actual=row.getValue();var empty=new SubjectConfirmationConfigurationTestCase(new UnreachableFallback(id),e->bodies.get(e.id()),r->target,root,r->"browser_sso_idp");
   require(((CaseStep.Finish)empty.start(context)).outcome().outcome()==Outcome.NOT_VERIFIED);var test=empty.withMetadataKeys((r,v)->r.equals(run)&&v.equals("control")?Optional.of(keys):Optional.empty());
   require(((CaseStep.Finish)empty.withMetadataKeys((r,v)->r.equals("run_00000000000000000000000000")?Optional.of(keys):Optional.empty()).start(context)).outcome().outcome()==Outcome.NOT_VERIFIED);
   require(((CaseStep.Finish)empty.withMetadataKeys((r,v)->v.equals("wrong-variant")?Optional.of(keys):Optional.empty()).start(context)).outcome().outcome()==Outcome.NOT_VERIFIED);
   require(test.start(context).equals(new CaseStep.Finish(actual)));for(var event:List.of(new CaseEvent.TranscriptReady(),new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("declared","unsupported declaration"),new CaseEvent.Aborted("cancelled"),new CaseEvent.TimedOut(Duration.ZERO)))require(test.resume(context,CaseState.initial(),event).equals(new CaseStep.Finish(actual)));
   require(test.evidenceStatus(context).ready()&&test.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(actual));require(test.reevaluateRecordedEvidence(context,CaseOutcome.of(Outcome.SATISFIED,"already-conclusive",List.of())).isEmpty());
   require(test.resolvedFromExternalEvidence(new CaseExecution(run,id,1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,actual,Instant.now())));
   var incomplete=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,false);require(((CaseStep.Finish)test.start(incomplete)).outcome().outcome()==Outcome.NOT_VERIFIED&&!test.evidenceStatus(incomplete).ready()&&test.reevaluateRecordedEvidence(incomplete,CaseOutcome.notVerified("pending","pending")).isEmpty());
   results.put(id,Map.of("startResume","SATISFIED_WITH_NOTE","recordedUpdate",true,"existingConclusiveUnchanged",true,"statusReady",true,"protocolProvenance",true,"incompleteHistory","NOT_VERIFIED","emptyKey","NOT_VERIFIED","wrongRunKey","NOT_VERIFIED","wrongVariantKey","NOT_VERIFIED"));
  }
  return results;
 }
 static final String SUFFIX=".shibboleth-subject-confirmation";
 static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 static void require(boolean value){if(!value)throw new IllegalStateException("Native subject confirmation replay incomplete");}
 static void reset(Path folder,Map<String,byte[]> originals)throws Exception{try(var paths=Files.list(folder)){for(var p:paths.toList())Files.delete(p);}for(var row:originals.entrySet())Files.write(folder.resolve(row.getKey()),row.getValue());}
 static void change(Path root,String run,ObjectNode manifest,String file,byte[] raw)throws Exception{Files.write(root.resolve(run+SUFFIX).resolve(file),raw);((ObjectNode)manifest.path("files")).put(file,hash(raw));}
 static void edit(Path root,String run,ObjectNode manifest,String file,java.util.function.Consumer<ObjectNode> apply)throws Exception{var node=(ObjectNode)JSON.mapper().readTree(root.resolve(run+SUFFIX).resolve(file).toFile());apply.accept(node);change(root,run,manifest,file,JSON.mapper().writeValueAsBytes(node));}
 static void manifest(Path root,String run,ObjectNode m)throws Exception{var p=root.resolve(run+SUFFIX+".json");if(!Files.exists(p)||!JSON.mapper().readTree(Files.readAllBytes(p)).equals(m))Files.write(p,JSON.mapper().writeValueAsBytes(m));}
 static TranscriptEntry altered(TranscriptEntry e,String run,String decoded,String correlation){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),correlation,e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),decoded,e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary());}
 static CaseOutcome result(Path root,ObjectNode manifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,PlanCredentials credential,String profile,boolean complete,String id)throws Exception {
  var run=manifest.path("runId").asText();manifest(root,run,manifest);
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){return entries;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Replay sent an action");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Replay altered history");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
  return new ShibbolethSubjectConfirmationEvidence(root,e->bodies.get(e.id()),r->profile,(r,v)->Optional.ofNullable(credential)).evaluate(context,id,target).orElse(CaseOutcome.notVerified("unproven","unproven"));
 }
 public static void main(String[] args)throws Exception {
  require(args.length==3);var original=Path.of(args[0]);var browser=Path.of(args[1]);var output=Path.of(args[2]);
  JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);
  var created=JSON.mapper().readTree(browser.resolve("created.json").toFile()).path("run");var run=created.path("id").asText();var plan=created.path("planId").asText();require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
  var marker=original.getParent().resolve(run+SUFFIX+".json");var markerRaw=Files.readAllBytes(marker);var base=(ObjectNode)JSON.mapper().readTree(markerRaw);
  var entries=List.of(JSON.mapper().readValue(browser.resolve("transcript.json").toFile(),TranscriptEntry[].class));var bodies=new HashMap<String,byte[]>();for(var e:entries)if(e.decodedSamlRef()!=null){require(run.equals(e.runId())&&("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));var raw=Files.readAllBytes(Path.of("/data").resolve(e.decodedSamlRef()));require(raw.length==e.decodedSamlBytes());bodies.put(e.id(),raw);}
  var target=Files.readAllBytes(Path.of("/data/target-metadata/"+run+".xml"));var fixture=SecureXml.parse(Files.readAllBytes(original.resolve("control.fixture.xml"))).getDocumentElement();var descriptor=MetadataAlgorithmEvidence.children(MetadataAlgorithmEvidence.children(fixture,"urn:oasis:names:tc:SAML:2.0:metadata","SPSSODescriptor").getFirst(),"urn:oasis:names:tc:SAML:2.0:metadata","KeyDescriptor").stream().filter(k->"encryption".equals(k.getAttribute("use"))).findFirst().orElseThrow();
  var encoded=Base64.getMimeDecoder().decode(descriptor.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","X509Certificate").item(0).getTextContent());var cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(encoded));PlanCredentials credential=null;
  try(var aliases=Files.list(Path.of("/data/keys/"+plan))){for(var alias:aliases.filter(Files::isDirectory).toList()){var c=Files.readAllBytes(alias.resolve("signing-certificate.der"));if(Arrays.equals(c,cert.getEncoded())){var raw=Files.readAllBytes(alias.resolve("signing-key.pk8"));var privateKey=KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw));Arrays.fill(raw,(byte)0);credential=new PlanCredentials(privateKey,cert);break;}}}require(credential!=null);
  var tmp=Files.createTempDirectory("shib-sc-replay-");var folder=Files.createDirectories(tmp.resolve(run+SUFFIX));var originals=new LinkedHashMap<String,byte[]>();try(var files=Files.list(original)){for(var p:files.toList())originals.put(p.getFileName().toString(),Files.readAllBytes(p));}var outcomes=new TreeMap<String,CaseOutcome>();var controls=new TreeMap<String,String>();
  try {
   reset(folder,originals);Files.write(tmp.resolve(run+SUFFIX+".json"),markerRaw);for(var id:List.of(ShibbolethSubjectConfirmationEvidence.FR,ShibbolethSubjectConfirmationEvidence.GD)){var actual=result(tmp,base,entries,bodies,target,credential,"browser_sso_idp",true,id);require(actual.outcome()==Outcome.SATISFIED_WITH_NOTE);outcomes.put(id,actual);}
   for(var name:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","native-factory-changed","stock-config-changed","unknown-source-override","unknown-classpath","provider-not-restored","restoration-false","native-profile-foreign-attester","native-profile-extra-setting","different-native-runtime","wrong-native-peer","profile-dump-wrong-peer","before-readback-late","after-readback-early","negative-http-unproven","native-signed-control-tampered","semantic-control-swapped","missing-original","symlink-original","wrong-profile","foreign-transcript-entry","duplicate-transcript-id","foreign-content-reference","wrong-response-correlation","tampered-request","tampered-response","wrong-decryption-key","missing-response","incomplete-history")){
    reset(folder,originals);Files.write(tmp.resolve(run+SUFFIX+".json"),markerRaw);var m=base.deepCopy();var selected=new ArrayList<>(entries);var raw=new HashMap<>(bodies);PlanCredentials selectedKey=credential;var profile="browser_sso_idp";boolean complete=true;var request=m.path("positiveRequestReference").asText();var response=m.path("positiveResponseReference").asText();
    switch(name){
     case "wrong-run"->m.put("runId","run_00000000000000000000000000");case "wrong-target"->m.put("targetMetadataSha256","0".repeat(64));case "wrong-campaign"->m.put("campaignId","other");case "wrong-entity"->m.put("targetEntityId","other");
     case "native-factory-changed"->change(tmp,run,m,"native-opensaml-saml-impl.jar",new byte[]{1,2,3});case "stock-config-changed"->change(tmp,run,m,"before-protocol-global.xml","<bean/>".getBytes());case "unknown-source-override"->change(tmp,run,m,"before-protocol-override-source-inventory.json","[\"/opt/reference-idp/system/override.xml\"]".getBytes());case "unknown-classpath"->change(tmp,run,m,"before-protocol-classpath-sha256.json","{}".getBytes());case "provider-not-restored"->change(tmp,run,m,"final-providers.xml","<wrong/>".getBytes());
     case "restoration-false"->edit(tmp,run,m,"restoration.json",n->n.put("restored",false));
     case "native-profile-foreign-attester","native-profile-extra-setting"->edit(tmp,run,m,"before-protocol-native-effective-profile.json",n->((ObjectNode)n.path("ProfileConfiguration")).put("attestingEntity","urn:foreign"));
     case "different-native-runtime"->{var rows=JSON.mapper().readTree(folder.resolve("target-container-inspect-end.json").toFile());((ObjectNode)rows.get(0)).put("Id","other");change(tmp,run,m,"target-container-inspect-end.json",JSON.mapper().writeValueAsBytes(rows));}
     case "wrong-native-peer"->change(tmp,run,m,"native-effective-sp-metadata.xml","<EntityDescriptor/>".getBytes());case "profile-dump-wrong-peer"->edit(tmp,run,m,"before-protocol-native-effective-profile-observed.json",n->n.put("requester","other"));
     case "before-readback-late","after-readback-early"->edit(tmp,run,m,name.startsWith("before")?"before-protocol-observed.json":"after-protocol-observed.json",n->n.put("recordedAt",name.startsWith("before")?"2099-01-01T00:00:00Z":"1970-01-01T00:00:00Z"));
     case "negative-http-unproven"->edit(tmp,run,m,"native-http-observations.json",n->((ObjectNode)n.path("records").get(0)).put("nativeMessageSecurityError",false));
     case "native-signed-control-tampered"->change(tmp,run,m,"foreign-positive.xml",new String(originals.get("foreign-positive.xml")).replace("urn:samlscope:attester-control:one","urn:tampered").getBytes());
     case "semantic-control-swapped"->{change(tmp,run,m,"multiple-positive.xml",originals.get("multiple-packed-identifiers.xml"));edit(tmp,run,m,"producer.json",n->((ObjectNode)n.path("files")).put("multiple-positive",hashUnchecked(originals.get("multiple-packed-identifiers.xml"))));}
     case "missing-original"->Files.delete(folder.resolve("before-protocol-native-effective-profile.json"));case "symlink-original"->{Files.delete(folder.resolve("before-protocol-native-effective-profile.json"));Files.createSymbolicLink(folder.resolve("before-protocol-native-effective-profile.json"),original.resolve("before-protocol-native-effective-profile.json"));}
     case "wrong-profile"->profile="metadata_idp";case "incomplete-history"->complete=false;case "missing-response"->selected.removeIf(e->e.id().equals(response));case "wrong-decryption-key"->selectedKey=new PlanCredentials(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(),cert);
     case "foreign-transcript-entry","foreign-content-reference","wrong-response-correlation"->{int index=0;while(!selected.get(index).id().equals(response))index++;var e=selected.get(index);selected.set(index,altered(e,name.equals("foreign-transcript-entry")?"run_00000000000000000000000000":e.runId(),name.equals("foreign-content-reference")?"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml":e.decodedSamlRef(),name.equals("wrong-response-correlation")?"other":e.correlationId()));}
     case "duplicate-transcript-id"->selected.add(selected.getFirst());case "tampered-request","tampered-response"->{var ref=name.equals("tampered-request")?request:response;var xml=SecureXml.parse(raw.get(ref));xml.getDocumentElement().setAttribute("ID","_changed");raw.put(ref,SecureXml.serialize(xml));}
    }
    for(var id:outcomes.keySet()){var outcome=result(tmp,m,selected,raw,target,selectedKey,profile,complete,id);require(outcome.outcome()==Outcome.NOT_VERIFIED);}controls.put(name,"NOT_VERIFIED");
   }
   reset(folder,originals);Files.write(tmp.resolve(run+SUFFIX+".json"),markerRaw);var wrappers=lifecycle(tmp,base,entries,bodies,target,credential,outcomes);
   JSON.mapper().writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("runId",run,"outcomes",outcomes,"negativeControls",controls,"wrapperLifecycle",wrappers,"nativeSignedSemanticControls",4,"manifestSha256",hash(markerRaw),"originalDecodedSha256",bodies.entrySet().stream().collect(java.util.stream.Collectors.toMap(Map.Entry::getKey,e->hashUnchecked(e.getValue()))),"productOperations",0,"privateKeyPersisted",false,"decryptedIdentifierPersisted",false));
  }finally{try(var paths=Files.walk(tmp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
 static String hashUnchecked(byte[] b){try{return hash(b);}catch(Exception e){throw new IllegalStateException(e);}}
}
