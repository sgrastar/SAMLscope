package com.samlscope.runner.cases;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.sql.*;
import java.util.*;
import java.util.function.*;

/** Public original replay; existing private keys remain in the Suite process and are never exported. */
public final class VerifyShibbolethMetadataApplicationEvidence {
 static final ObjectMapper M=new JsonCodec().mapper();
 static void require(boolean b){if(!b)throw new IllegalArgumentException("Application replay unproven");}
 static void safe(Path root,Path p)throws Exception{require(p.toAbsolutePath().normalize().startsWith(root.toAbsolutePath().normalize()));for(Path x=p;x!=null;x=x.getParent())require(!Files.isSymbolicLink(x));require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS));}
 static PlanCredentials readKey(Path data,String plan,String alias)throws Exception{Path folder=data.resolve("keys").resolve(plan);if(alias!=null)folder=folder.resolve(alias);Path cert=folder.resolve("signing-certificate.der"),key=folder.resolve("signing-key.pk8");safe(data,cert);safe(data,key);byte[] raw=Files.readAllBytes(key);try{return new PlanCredentials(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw)),(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Files.readAllBytes(cert))));}finally{Arrays.fill(raw,(byte)0);}}
 static Map<String,PlanCredentials> keys(Path data,String run,String plan)throws Exception{safe(data,data.resolve("samlscope.db"));try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT plan_id FROM runs WHERE id=?")){q.setString(1,run);try(var r=q.executeQuery()){require(r.next()&&plan.equals(r.getString(1))&&!r.next());}}
  var result=new LinkedHashMap<String,PlanCredentials>();result.put("primary",readKey(data,plan,null));for(String v:List.of("control","no-valid-until","multiple-signing-keys-first","multiple-signing-keys","multiple-signing-keys-unadvertised")){String alias="poll-"+ShibbolethMetadataApplicationEvidence.hash(v.getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0,16);if(v.equals("multiple-signing-keys")||v.equals("multiple-signing-keys-unadvertised")){var first=result.get("multiple-signing-keys-first");alias=(v.equals("multiple-signing-keys")?"roll2-":"roll3-")+ShibbolethMetadataApplicationEvidence.hash(first.certificate().getPublicKey().getEncoded()).substring(0,24);}result.put(v,readKey(data,plan,alias));}return result;}
 static void changed(Path folder,com.fasterxml.jackson.databind.node.ObjectNode manifest,String name,byte[] raw)throws Exception {
  Files.createDirectories(folder.resolve(name).getParent());Files.write(folder.resolve(name),raw);
  ((com.fasterxml.jackson.databind.node.ObjectNode)manifest.path("files")).put(name,ShibbolethMetadataApplicationEvidence.hash(raw));
 }
 static void edit(Path folder,com.fasterxml.jackson.databind.node.ObjectNode manifest,String name,java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> editor)throws Exception {
  var node=(com.fasterxml.jackson.databind.node.ObjectNode)M.readTree(folder.resolve(name).toFile());editor.accept(node);changed(folder,manifest,name,M.writeValueAsBytes(node));
 }
 static CaseOutcome observe(ShibbolethMetadataApplicationEvidence reader,Path folder,com.fasterxml.jackson.databind.node.ObjectNode manifest,CaseContext context,String id)throws Exception {
  if(!Files.exists(folder.resolve("manifest.json"))||!M.readTree(folder.resolve("manifest.json").toFile()).equals(manifest))Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));return reader.evaluate(id,context);
 }
 static void evidence(CaseOutcome outcome,List<TranscriptEntry> entries,String run){for(var e:outcome.evidence())if(e.kind().equals("transcript"))require(entries.stream().filter(t->t.id().equals(e.reference())&&run.equals(t.runId())).count()==1);}
 static Map<String,Object> fullControls(Path source,ShibbolethMetadataApplicationEvidence reader,CaseContext context,List<TranscriptEntry> entries,Map<String,byte[]> decoded,byte[] target,BiFunction<String,String,Optional<PlanCredentials>> provider,SamlDecryptionKeyProvider primary)throws Exception {
  String run=context.runId();Path folder=source.resolve("shibboleth-metadata-application-evidence").resolve(run);var base=(com.fasterxml.jackson.databind.node.ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());
  Map<String,byte[]> originals=new LinkedHashMap<>();try(var paths=Files.walk(folder)){for(var f:paths.filter(Files::isRegularFile).toList())originals.put(folder.relativize(f).toString(),Files.readAllBytes(f));}
  var checks=new TreeMap<String,Object>();var positive=observe(reader,folder,base,context,MetadataSupersessionProbeTestCase.APPLICATION);require(positive.outcome()==Outcome.SATISFIED);evidence(positive,entries,run);
  List<String> names=List.of("wrong-run","wrong-target","wrong-schema","wrong-adapter","missing-epoch","missing-probe","incomplete-history","foreign-run-entry","duplicate-entry","foreign-decoded-reference","request-signature-changed","response-signature-changed","missing-native-paos-cause","foreign-paos-issuer","false-native-prefix","native-cause-outside-window","native-signature-cause-ambiguous","native-refusal-body-unrelated","native-http-request-mismatch","native-http-outside-window","native-effective-role-incomplete","native-policy-source-changed","runtime-identity-changed","rollover-positive-missing","unsupported-binding-proof-missing","selector-class-changed","selector-source-changed","selector-output-mismatch","selector-invocation-mismatch","restoration-byte-changed","restoration-unconfirmed","wrong-polling-decryption-key","wrong-primary-decryption-key");
  for(String name:names){for(var original:originals.entrySet())Files.write(folder.resolve(original.getKey()),original.getValue());var manifest=base.deepCopy();var chosen=new ArrayList<>(entries);var raw=new HashMap<>(decoded);var selectedKeys=provider;var selectedPrimary=primary;boolean complete=true;
   var second=manifest.path("probes").findValues("fixture");
   String request="";for(var probe:manifest.path("probes"))if("new-key-second-acs".equals(probe.path("fixture").asText()))request=probe.path("requestReference").asText();final String requestRef=request;
   String response=chosen.stream().filter(e->e.samlSummary().get("inResponseTo")!=null&&e.samlSummary().get("inResponseTo").equals("_"+chosen.stream().filter(x->x.id().equals(requestRef)).findFirst().orElseThrow().correlationId())&&"Response".equals(e.samlSummary().get("type"))).findFirst().orElseThrow().id();
   switch(name){
    case "wrong-run"->manifest.put("runId","run_00000000000000000000000000");case "wrong-target"->manifest.put("targetMetadataSha256","0".repeat(64));case "wrong-schema"->manifest.put("schema","foreign-schema");case "wrong-adapter"->manifest.put("adapter","mdquery-only");
    case "missing-epoch"->((com.fasterxml.jackson.databind.node.ArrayNode)manifest.path("epochReferences")).remove(0);case "missing-probe"->((com.fasterxml.jackson.databind.node.ArrayNode)manifest.path("probes")).remove(0);case "incomplete-history"->complete=false;
    case "foreign-run-entry","foreign-decoded-reference"->{int i=0;while(!chosen.get(i).id().equals(response))i++;var e=chosen.get(i);chosen.set(i,VerifyNativeRoleKeyConsumption.altered(e,name.equals("foreign-run-entry")?"run_00000000000000000000000000":run,name.equals("foreign-decoded-reference")?"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml":e.decodedSamlRef()));}
    case "duplicate-entry"->chosen.add(chosen.getFirst());
    case "request-signature-changed","response-signature-changed"->{String ref=name.startsWith("request")?request:response;var doc=ShibbolethMetadataApplicationEvidence.xml(raw.get(ref));doc.setAttribute("ID","_changed");raw.put(ref,com.samlscope.saml.normal.SecureXml.serialize(doc.getOwnerDocument()));}
    case "missing-native-paos-cause"->edit(folder,manifest,"native-paos-cause-projection.json",n->n.putArray("publicCandidateLines"));
    case "foreign-paos-issuer"->edit(folder,manifest,"native-paos-cause-projection.json",n->{for(var line:n.path("publicCandidateLines"))if(line.path("kind").asText().equals("native-signature-validation-failure")){var l=(com.fasterxml.jackson.databind.node.ObjectNode)line;String text=l.path("raw").asText().replace(manifest.path("entityId").asText(),"urn:foreign:peer");l.put("raw",text);try{l.put("lineSha256",ShibbolethMetadataApplicationEvidence.hash(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));}catch(Exception e){throw new RuntimeException(e);}}});
    case "false-native-prefix"->edit(folder,manifest,"native-paos-cause-projection.json",n->n.put("sourcePrefixRecheckedSha256","0".repeat(64)));
    case "native-cause-outside-window"->edit(folder,manifest,"native-paos-cause-projection.json",n->{for(var line:n.path("publicCandidateLines"))if(line.path("kind").asText().equals("native-signature-validation-failure"))((com.fasterxml.jackson.databind.node.ObjectNode)line).put("nativeLoggedAt","2000-01-01T00:00:00Z");});
    case "native-signature-cause-ambiguous"->edit(folder,manifest,"native-paos-cause-projection.json",n->{var a=(com.fasterxml.jackson.databind.node.ArrayNode)n.path("publicCandidateLines");for(int i=0;i<a.size();i++)if(a.get(i).path("kind").asText().equals("native-signature-validation-failure")){var l=(com.fasterxml.jackson.databind.node.ObjectNode)a.get(i).deepCopy();l.put("lineNumber",l.path("lineNumber").asInt()+1);a.insert(i+1,l);break;}});
    case "native-refusal-body-unrelated"->{var h=M.readTree(folder.resolve("native-http.json").toFile());for(var row:h)if(row.path("responseStatus").asInt()==400){String file=row.path("responseBodyFile").asText();changed(folder,manifest,file,"<h1>Unrelated error</h1>".getBytes());break;}}
    case "native-http-request-mismatch","native-http-outside-window"->{var h=M.readTree(folder.resolve("native-http.json").toFile());for(var row:h)if(row.path("requestId").asText().equals("_"+chosen.stream().filter(e->e.id().equals(requestRef)).findFirst().orElseThrow().correlationId())){((com.fasterxml.jackson.databind.node.ObjectNode)row).put(name.endsWith("mismatch")?"requestSha256":"startedAt",name.endsWith("mismatch")?"0".repeat(64):"2000-01-01T00:00:00Z");break;}changed(folder,manifest,"native-http.json",M.writeValueAsBytes(h));}
    case "native-effective-role-incomplete"->{var epoch=M.readTree(folder.resolve("native-originals/no-valid-until-before.json").toFile());String q="native/"+epoch.path("queryFile").asText();var doc=ShibbolethMetadataApplicationEvidence.xml(Files.readAllBytes(folder.resolve(q)));var r=ShibbolethMetadataApplicationEvidence.role(doc);r.removeChild(MetadataAlgorithmEvidence.children(r,ShibbolethMetadataApplicationEvidence.MD,"AssertionConsumerService").getFirst());changed(folder,manifest,q,com.samlscope.saml.normal.SecureXml.serialize(doc.getOwnerDocument()));}
    case "native-policy-source-changed"->changed(folder,manifest,"native/trust-control-before-global.xml","<beans/>".getBytes());
    case "runtime-identity-changed"->edit(folder,manifest,"selection-operations.json",n->{((com.fasterxml.jackson.databind.node.ObjectNode)n.path("nativeContainerBefore")).put("id","foreign");((com.fasterxml.jackson.databind.node.ObjectNode)n.path("nativeContainerAfter")).put("id","foreign");});
    case "rollover-positive-missing"->{for(var row:manifest.path("probes"))if(row.path("fixture").asText().equals("fixture-ecp-metadata-rollover-second-paos"))((com.fasterxml.jackson.databind.node.ObjectNode)row).putArray("responseReferences");}
    case "unsupported-binding-proof-missing"->edit(folder,manifest,"native-selection-input.json",n->{var a=(com.fasterxml.jackson.databind.node.ArrayNode)n.path("records");for(int i=0;i<a.size();i++)if(a.get(i).path("label").asText().equals("unsupported-browser-redirect")){a.remove(i);break;}});
    case "selector-class-changed"->edit(folder,manifest,"native-selection-output.json",n->((com.fasterxml.jackson.databind.node.ObjectNode)n.path("selectedNativeClassHashes")).put("org.opensaml.saml.common.binding.impl.DefaultEndpointResolver","0".repeat(64)));
    case "selector-source-changed"->changed(folder,manifest,"native-selection-source.java","class Forged {}".getBytes());
    case "selector-output-mismatch"->edit(folder,manifest,"native-selection-output.json",n->{for(var row:n.path("records"))if(row.path("label").asText().equals("paos"))((com.fasterxml.jackson.databind.node.ObjectNode)row).put("selectedLocation","urn:wrong:acs");});
    case "selector-invocation-mismatch"->edit(folder,manifest,"native-selection-invocation.json",n->n.put("inputSha256","0".repeat(64)));
    case "wrong-polling-decryption-key"->selectedKeys=(r,v)->v.equals("no-valid-until")?Optional.of(new PlanCredentials(provider.apply(r,"control").orElseThrow().privateKey(),provider.apply(r,v).orElseThrow().certificate())):provider.apply(r,v);case "wrong-primary-decryption-key"->selectedPrimary=r->Optional.of(provider.apply(r,"control").orElseThrow().privateKey());
    case "restoration-byte-changed"->changed(folder,manifest,"final-providers.xml","<changed/>".getBytes());case "restoration-unconfirmed"->edit(folder,manifest,"restoration.json",n->n.put("restored",false));
   }
   var selectedReader=new ShibbolethMetadataApplicationEvidence(source.resolve("shibboleth-metadata-application-evidence"),e->raw.get(e.id()),r->target,selectedKeys,selectedPrimary);
   var value=observe(selectedReader,folder,manifest,VerifyNativeRoleKeyConsumption.context(run,chosen,complete),MetadataSupersessionProbeTestCase.APPLICATION);require(value.outcome()==Outcome.NOT_VERIFIED);checks.put(name,Map.of("outcome",value.outcome(),"reasonCode",value.reasonCode()));
  }
  for(var original:originals.entrySet())Files.write(folder.resolve(original.getKey()),original.getValue());
  var calibration=new TreeMap<String,Object>();
  for(String mode:List.of("drop-accepted-b-secondary-acs","retain-conflicting-old-a-acs")) {
   var m=base.deepCopy();var cal=m.putObject("calibration");cal.put("selectedConsumer",mode);
   for(var pair:new TreeMap<>(Map.of("inputFile",mode+".input.json","outputFile",mode+".output.json","invocationFile",mode+".invocation.json","sourceFile","calibration-source.java","operationsFile","operations.json","jarsBeforeFile","native-jars-before.sha256","jarsAfterFile","native-jars-after.sha256")).entrySet()){String f="calibration/"+pair.getValue();cal.put(pair.getKey(),f);changed(folder,m,f,Files.readAllBytes(source.resolve(f)));}
   var offline=new ShibbolethMetadataApplicationEvidence(source.resolve("shibboleth-metadata-application-evidence"),e->decoded.get(e.id()),r->target,provider,primary,true);
   String id=mode.startsWith("drop-")?MetadataSupersessionProbeTestCase.APPLICATION:MetadataSupersessionProbeTestCase.SUPERSESSION;
   var publicValue=observe(reader,folder,m,context,id);require(publicValue.outcome()==Outcome.NOT_VERIFIED);
   var offlineValue=observe(offline,folder,m,context,id);require(offlineValue.outcome()==Outcome.VIOLATED);evidence(offlineValue,entries,run);
   calibration.put(mode,Map.of("publicOutcome",publicValue,"offlineOutcome",offlineValue,"centralVerdict",Evaluator.toVerdict(Rfc2119Level.MUST,offlineValue),"purpose","isolated-native-consumer-calibration-only-not-product-finding"));
   var mismatched=m.deepCopy();((com.fasterxml.jackson.databind.node.ObjectNode)mismatched.path("calibration")).put("selectedConsumer",mode.startsWith("drop-")?"retain-conflicting-old-a-acs":"drop-accepted-b-secondary-acs");require(observe(offline,folder,mismatched,context,id).outcome()==Outcome.NOT_VERIFIED);checks.put(mode+"-label-only-switch",Map.of("outcome",Outcome.NOT_VERIFIED));
  }
  for(var original:originals.entrySet())Files.write(folder.resolve(original.getKey()),original.getValue());
  require(observe(reader,folder,base,context,MetadataSupersessionProbeTestCase.APPLICATION).equals(positive));
  return Map.of("negativeControls",checks,"approvedTriggerCalibrations",calibration,"stockOutcomeUnchangedAfterControls",true,"allTranscriptEvidenceResolvesSameRun",true,"calibrationAssetsInstalled",false,"additionalProductOperations",0,"additionalCredentialPosts",0);
 }
 static Map<String,Object> lifecycle(Path source,CaseContext context,List<TranscriptEntry> entries,Map<String,byte[]> decoded,byte[] target,BiFunction<String,String,Optional<PlanCredentials>> provider,SamlDecryptionKeyProvider primary,Map<String,Object> actual) {
  var result=new TreeMap<String,Object>();
  for(String id:List.of(MetadataSupersessionProbeTestCase.APPLICATION,MetadataSupersessionProbeTestCase.SUPERSESSION)) {
   var fallback=new ConfigurationGateTestCase(new AttestedOutcomeTestCase(id,com.samlscope.core.plan.TargetRole.IDP,"config.evidence",java.time.Duration.ofMinutes(1),List.of(AttestationOption.of("evidence_satisfies",Outcome.SATISFIED,"declaration.satisfies"))),"metadata.config",java.time.Duration.ofMinutes(1),ConfigurationFailureSemantics.TEST_PRECONDITION);
   var wrapper=new MetadataSupersessionProbeTestCase(fallback,r->target,e->decoded.get(e.id()),provider,source.resolve("metadata-supersession-evidence"),primary);
   CaseOutcome expected=(CaseOutcome)actual.get(id);require(((CaseStep.Finish)wrapper.start(context)).outcome().equals(expected));
   require(((CaseStep.Finish)wrapper.resume(context,new CaseState("configuration",Map.of()),new CaseEvent.ConfigConfirmed())).outcome().equals(expected));
   require(wrapper.evidenceStatus(context).ready());var previous=CaseOutcome.notVerified("native_metadata_supersession_originals_unavailable","metadata.supersession.awaiting-native-receipt");
   require(wrapper.reevaluateRecordedEvidence(context,previous).orElseThrow().equals(expected));require(wrapper.reevaluateRecordedEvidence(context,expected).isEmpty());
   require(((CaseStep.Finish)wrapper.start(VerifyNativeRoleKeyConsumption.context(context.runId(),entries,false))).outcome().outcome()==Outcome.NOT_VERIFIED);
   result.put(id,Map.of("start",true,"ConfigConfirmed",true,"statusReady",true,"recordedNotVerified",true,"conclusiveUnchanged",true,"incompleteHistory",Outcome.NOT_VERIFIED,"newOutboundActions",0,"centralVerdict",Evaluator.toVerdict(Rfc2119Level.MUST,expected)));
  }
  return result;
 }
 public static void main(String[]args)throws Exception{require(args.length==3);java.util.logging.LogManager.getLogManager().reset();Path source=Path.of(args[0]).toRealPath(),data=Path.of(args[1]).toRealPath(),report=Path.of(args[2]);require(!Files.exists(report));if(!Files.exists(source.resolve("shibboleth-metadata-application-evidence")))Files.move(source.resolve("evidence"),source.resolve("shibboleth-metadata-application-evidence"));JsonNode manifest=M.readTree(source.resolve("receipt/manifest.json").toFile());String run=manifest.path("runId").asText(),plan=manifest.path("planId").asText();require(ShibbolethMetadataApplicationEvidence.validRun(run)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));var keys=keys(data,run,plan);
  var entries=List.of(M.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var raw=new HashMap<String,byte[]>();for(var row:M.readTree(source.resolve("decoded-manifest.json").toFile())){Path file=source.resolve(row.path("file").asText()).normalize();safe(source,file);byte[] bytes=Files.readAllBytes(file);require(ShibbolethMetadataApplicationEvidence.hash(bytes).equals(row.path("sha256").asText())&&raw.put(row.path("id").asText(),bytes)==null);}
  for(var e:entries)if("BrowserResponseObservation".equals(e.samlSummary().get("type"))){require(e.bodyRef().equals("transcripts/"+run+"/"+e.id()+".body"));Path original=data.resolve(e.bodyRef());safe(data,original);Path copy=source.resolve(e.bodyRef());Files.createDirectories(copy.getParent());Files.copy(original,copy);}
  byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));var context=VerifyNativeRoleKeyConsumption.context(run,entries,true);var provider=(BiFunction<String,String,Optional<PlanCredentials>>)((r,v)->r.equals(run)?Optional.ofNullable(keys.get(v)):Optional.empty());
  var reader=new ShibbolethMetadataApplicationEvidence(source.resolve("shibboleth-metadata-application-evidence"),e->raw.get(e.id()),r->target,provider,r->r.equals(run)?Optional.of(keys.get("primary").privateKey()):Optional.empty());
  var results=new TreeMap<String,Object>();for(String id:List.of(MetadataSupersessionProbeTestCase.APPLICATION,MetadataSupersessionProbeTestCase.SUPERSESSION)){results.put(id,reader.evaluate(id,context));}
  var stages=new TreeMap<String,Object>();var frame=reader.new Frame(MetadataSupersessionProbeTestCase.APPLICATION,context);var names=List.of("load","epochs","restoration","source","baseline","phases","ecp","browser","scope");for(String name:names){try{switch(name){case "load"->frame.load();case "epochs"->frame.epochs();case "restoration"->{frame.restore("");frame.restore("prior-rollover/");}case "source"->frame.source();case "baseline"->frame.baseline();case "phases"->frame.phases();case "ecp"->frame.ecp();case "browser"->frame.browser();case "scope"->frame.scope();}stages.put(name,"verified");}catch(Throwable unproven){var lines=Arrays.stream(unproven.getStackTrace()).limit(4).map(e->e.getClassName()+":"+e.getLineNumber()).toList();stages.put(name,Map.of("unproven",true,"sourceLocations",lines));break;}}
  var controls=fullControls(source,reader,context,entries,raw,target,provider,r->r.equals(run)?Optional.of(keys.get("primary").privateKey()):Optional.empty());
  var lifecycle=lifecycle(source,context,entries,raw,target,provider,r->r.equals(run)?Optional.of(keys.get("primary").privateKey()):Optional.empty(),results);
  M.writerWithDefaultPrettyPrinter().writeValue(report.toFile(),Map.of("wrapperLifecycle",lifecycle,"controls",controls,"runId",run,"outcomes",results,"diagnosticStages",stages,"additionalProductOperations",0,"credentialsPersisted",false));
 }
}
