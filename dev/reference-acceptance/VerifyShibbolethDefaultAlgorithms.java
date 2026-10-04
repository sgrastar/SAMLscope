package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.function.*;

/** Archived production-reader replay. Native SDK detector originals are explicitly offline-only. */
public final class VerifyShibbolethDefaultAlgorithms {
 static final JsonCodec J=new JsonCodec();static final String CASE=DefaultAlgorithmComparison.CASE;
 static void require(boolean value,String why){if(!value)throw new IllegalArgumentException(why);}
 static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 static ObjectNode json(byte[] raw)throws Exception{return (ObjectNode)J.mapper().readTree(raw);}
 static DefaultCaseContext context(String run,List<TranscriptEntry> entries,boolean complete){var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return r.equals(run)?entries:List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Replay wrote Recorder");}public TranscriptEntry updateSamlAnalysis(String id,String corr,Map<String,Object>summary){throw new AssertionError("Replay changed original");}};return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,45,"reference"),new TestPlan.Interaction(true,false),Reachability.CONFIRMED,recorder,complete);}
 static TranscriptEntry alter(TranscriptEntry e,String run,String decoded,int length){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),decoded,length,e.contentType(),e.rawQuery(),e.samlSummary());}
 static TranscriptEntry added(String id,String run,byte[] bytes,Instant at,String type,String corr,String url){return new TranscriptEntry(id,run,Direction.INBOUND,at,corr,"POST",url,200,Map.of(),"offline-diagnostic",bytes.length,"transcripts/"+run+"/"+id+".saml.xml",bytes.length,"application/saml+xml",null,Map.of("type",type));}
 static String id(String name)throws Exception{return "tx_"+hash(name.getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0,26).toUpperCase(Locale.ROOT);}
 static void reset(Path folder,Map<String,byte[]> files)throws Exception{try(var list=Files.list(folder)){for(var p:list.toList())Files.delete(p);}for(var f:files.entrySet())Files.write(folder.resolve(f.getKey()),f.getValue());}
 static void put(Path folder,ObjectNode manifest,String name,byte[] bytes)throws Exception{Files.write(folder.resolve(name),bytes);((ObjectNode)manifest.path("files")).put(name,hash(bytes));}
 static CaseOutcome result(Path root,String run,ObjectNode m,byte[] actualManifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,Function<String,Optional<PlanCredentials>> keys,boolean complete,boolean offline)throws Exception{
  Files.write(root.resolve(run).resolve("manifest.json"),actualManifest==null?J.mapper().writeValueAsBytes(m):actualManifest);
  var content=(TranscriptContentReader)(e->bodies.get(e.id()));var reader=new DefaultAlgorithmPreventionEvidence(root,content,r->target,keys,r->"browser_sso_idp",offline,new ShibbolethDefaultAlgorithmNativeAdapter(content,offline));
  return reader.evaluate(context(run,entries,complete)).orElseGet(()->DefaultAlgorithmComparison.missing("reader_unproven",List.of()));
 }
 static void nativeEdit(ObjectNode m,List<TranscriptEntry> entries,Map<String,byte[]> bodies,String prefix,Consumer<ObjectNode> change)throws Exception{
  String ref=m.path(prefix+"Reference").asText();var raw=json(bodies.get(ref));change.accept(raw);byte[] bytes=J.mapper().writeValueAsBytes(raw);bodies.put(ref,bytes);m.put(prefix+"Sha256",hash(bytes));for(int i=0;i<entries.size();i++)if(entries.get(i).id().equals(ref)){var e=entries.get(i);entries.set(i,alter(e,e.runId(),e.decodedSamlRef(),bytes.length));return;}throw new IllegalArgumentException("Original reference absent");
 }
 static Map<String,Object> lifecycle(Path root,String run,List<TranscriptEntry>entries,Map<String,byte[]>bodies,byte[]target,Function<String,Optional<PlanCredentials>>keys,boolean offline,CaseOutcome actual)throws Exception{
  var content=(TranscriptContentReader)(e->bodies.get(e.id()));var reader=new DefaultAlgorithmPreventionEvidence(root,content,r->target,keys,r->"browser_sso_idp",offline,new ShibbolethDefaultAlgorithmNativeAdapter(content,offline));
  var fallback=new AttestedOutcomeTestCase(CASE,TargetRole.IDP,"algorithm.default",Duration.ofMinutes(1),List.of(AttestationOption.of("evidence_satisfies",Outcome.SATISFIED,"manual.satisfied")));
  var wrapper=new DefaultAlgorithmPreventionProbeTestCase(fallback,content,r->target,keys,r->"browser_sso_idp",reader);var c=context(run,entries,true);var result=new TreeMap<String,Object>();
  result.put("start",((CaseStep.Finish)wrapper.start(c)).outcome().equals(actual));var state=new CaseState("await-default-algorithm-preparation",Map.of("case_id",CASE));
  for(var event:List.of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),new CaseEvent.Aborted("completed"),new CaseEvent.TimedOut(Duration.ofMinutes(1))))result.put(event.getClass().getSimpleName(),((CaseStep.Finish)wrapper.resume(c,state,event)).outcome().equals(actual));
  result.put("status-ready",wrapper.evidenceStatus(c).ready());result.put("recorded-NV",wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("before","before")).orElseThrow().equals(actual));result.put("recorded-conclusive-unchanged",wrapper.reevaluateRecordedEvidence(c,actual).isEmpty());
  result.put("external-provenance-boundary",wrapper.resolvedFromExternalEvidence(new CaseExecution(run,CASE,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,actual,Instant.now()))==!offline);return result;
 }
 public static void main(String[] args)throws Exception{
  require(args.length==2||args.length==3,"Input/output paths required");J.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
  var input=Path.of(args[0]);var receipt=input.resolve("receipt");var created=J.mapper().readTree(input.resolve("created.json").toFile()).path("run");String run=created.path("id").asText();byte[] manifestRaw=Files.readAllBytes(receipt.resolve("manifest.json")),target=Files.readAllBytes(input.resolve("target-metadata.xml"));var base=json(manifestRaw);require(run.equals(base.path("runId").asText())&&!base.path("counterfactualCalibrationOnly").asBoolean(true),"Stock same Run required");
  var snapshot=input.resolve("finalized-originals");var entries=List.of(J.mapper().readValue(snapshot.resolve("transcript.json").toFile(),TranscriptEntry[].class));var bodies=new HashMap<String,byte[]>();for(var row:J.mapper().readTree(snapshot.resolve("decoded-manifest.json").toFile())){byte[] raw=Files.readAllBytes(snapshot.resolve(row.path("file").asText()));require(hash(raw).equals(row.path("sha256").asText())&&bodies.put(row.path("id").asText(),raw)==null,"Decoded original changed/duplicate");}
  var bridge=new KeycloakNativeRunEvidenceBridge(Path.of("/data"));Function<String,Optional<PlanCredentials>> keys=r->bridge.key(r,"control");require(keys.apply(run).isPresent(),"Existing control key unavailable");
  var files=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(receipt)){for(var file:paths.toList())if(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS))files.put(file.getFileName().toString(),Files.readAllBytes(file));}
  var temp=Files.createTempDirectory("default-algorithm-replay-");var root=temp.toRealPath();var folder=Files.createDirectories(root.resolve(run));
  try{
   reset(folder,files);var actual=result(root,run,base,manifestRaw,entries,bodies,target,keys,true,false);require(actual.outcome()==Outcome.SATISFIED||actual.outcome()==Outcome.VIOLATED,"Actual full native case not conclusive: "+actual.details());
   if(args.length==3){J.mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),Map.of("runId",run,"outcome",actual,"diagnosticOnly",false));return;}
   var negatives=new TreeMap<String,String>();
   for(String name:List.of("foreign-run","foreign-case","wrong-campaign","wrong-profile","wrong-target","unknown-adapter","missing-control","missing-negative","duplicate-entry","foreign-entry","foreign-decoded","tampered-request","tampered-response","missing-native-use","fake-native-policy","changed-runtime","restoration-missing","restoration-failed","wrong-registration","missing-cipher-math","cipher-native-math-tampered","cipher-invocation-tampered","wrong-crypto-key","incomplete-history","counterfactual-production","cause-wrong-thread","cause-algorithm-prefix","audit-capture-missing","audit-capture-wrong-request","audit-capture-nonempty","audit-capture-too-late","decoder-misbound-thread","decoder-algorithm-prefix","decoder-missing-event","unmarshaller-output-missing","unmarshaller-foreign-run","unmarshaller-wrong-request","unmarshaller-input-tampered","unmarshaller-class-tampered","unmarshaller-invocation-tampered","rsa15-cause-wrong-thread","rsa15-cause-algorithm-prefix","rsa15-cause-incomplete","rsa15-cause-out-of-order","rsa15-audit-contradictory","rsa15-code-provider-tampered")){
    reset(folder,files);var m=base.deepCopy();var selected=new ArrayList<>(entries);var raw=new HashMap<>(bodies);Function<String,Optional<PlanCredentials>> selectedKeys=keys;boolean complete=true;var normal=(ObjectNode)m.path("observations").get(0);var weak=(ObjectNode)m.path("observations").get(2);var early=(ObjectNode)m.path("observations").get(3);var cipher=(ObjectNode)m.path("observations").get(4);
    switch(name){
     case "foreign-run"->m.put("runId","run_00000000000000000000000000");case "foreign-case"->m.put("caseId","IIP-ALG08-a-idp-01");case "wrong-campaign"->m.put("campaignId","other");case "wrong-profile"->m.put("profile","ecp_idp");case "wrong-target"->m.put("targetMetadataSha256","0".repeat(64));case "unknown-adapter"->m.put("adapter","parser-only");
     case "missing-control"->((ArrayNode)m.path("observations")).remove(0);case "missing-negative"->((ArrayNode)m.path("observations")).remove(1);case "duplicate-entry"->selected.add(selected.getFirst());
     case "foreign-entry","foreign-decoded"->{String ref=normal.path("responseReference").asText();for(int i=0;i<selected.size();i++)if(selected.get(i).id().equals(ref)){var e=selected.get(i);selected.set(i,alter(e,name.equals("foreign-entry")?"run_00000000000000000000000000":run,name.equals("foreign-decoded")?"transcripts/run_00000000000000000000000000/"+ref+".saml.xml":e.decodedSamlRef(),e.decodedSamlBytes()));}}
     case "tampered-request","tampered-response"->{String ref=normal.path(name.equals("tampered-request")?"requestReference":"responseReference").asText();var x=SecureXml.parse(raw.get(ref));x.getDocumentElement().setAttribute("ID","_tampered");raw.put(ref,SecureXml.serialize(x));}
     case "missing-native-use"->weak.put("nativeUseReference","tx_00000000000000000000000000");
     case "fake-native-policy"->nativeEdit(m,selected,raw,"beforeScope",n->n.put("algorithmProcessOverridePresent",true));
     case "changed-runtime"->nativeEdit(m,selected,raw,"afterScope",n->((ObjectNode)n.path("runtime")).put("containerId","0".repeat(64)));
     case "restoration-missing"->m.put("restorationFile","absent.json");case "restoration-failed"->{String f=m.path("restorationFile").asText();var n=json(files.get(f));n.put("restored",false);put(folder,m,f,J.mapper().writeValueAsBytes(n));}
     case "wrong-registration"->put(folder,m,m.path("registeredSuiteMetadataFile").asText(),"<not-metadata/>".getBytes());
     case "missing-cipher-math","cipher-native-math-tampered","cipher-invocation-tampered"->{var use=json(raw.get(cipher.path("nativeUseReference").asText()));if(name.equals("missing-cipher-math"))use.remove("cipherInputReference");else if(name.equals("cipher-native-math-tampered"))use.put("cipherInputSha256","0".repeat(64));else{String f=use.path("cipherInvocationFile").asText();var call=json(files.get(f));call.put("exitCode",1);put(folder,m,f,J.mapper().writeValueAsBytes(call));}final ObjectNode value=use;nativeEdit(cipher,selected,raw,"nativeUse",n->{n.removeAll();n.setAll(value);});}
     case "wrong-crypto-key"->{var key=keys.apply(run).orElseThrow();var bad=new PlanCredentials(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate(),key.certificate());selectedKeys=r->Optional.of(bad);}case "incomplete-history"->complete=false;case "counterfactual-production"->m.put("counterfactualCalibrationOnly",true);
     case "cause-wrong-thread","cause-algorithm-prefix"->{var use=json(raw.get(weak.path("nativeUseReference").asText()));String f=use.path("processLogFile").asText();String log=new String(files.get(f),java.nio.charset.StandardCharsets.UTF_8);if(name.equals("cause-wrong-thread"))log=log.replaceAll("( - (?:WARN|ERROR|INFO|DEBUG) )\\[[^]]+]","$1[foreign-thread]");else log=log.replace("http://www.w3.org/2001/04/xmldsig-more#md5","http://www.w3.org/2001/04/xmldsig-more#md5-other");byte[] altered=log.getBytes(java.nio.charset.StandardCharsets.UTF_8);require(!Arrays.equals(altered,files.get(f)),"Cause control failed to change its native source");put(folder,m,f,altered);((ObjectNode)use.path("processLogRange")).put("afterOffset",use.path("processLogRange").path("beforeOffset").asLong()+altered.length);final ObjectNode replacement=use;nativeEdit(weak,selected,raw,"nativeUse",n->{n.removeAll();n.setAll(replacement);});}
     case "rsa15-cause-wrong-thread","rsa15-cause-algorithm-prefix","rsa15-cause-incomplete","rsa15-cause-out-of-order","rsa15-audit-contradictory","rsa15-code-provider-tampered"->{
      var use=json(raw.get(cipher.path("nativeUseReference").asText()));
      if(name.equals("rsa15-code-provider-tampered")){String f="default-native-opensaml-xmlsec-api.jar";byte[] altered=files.get(f).clone();altered[altered.length-1]^=1;put(folder,m,f,altered);}
      else if(name.equals("rsa15-audit-contradictory")){String f=use.path("auditFile").asText();String[] fields=new String(files.get(f),java.nio.charset.StandardCharsets.UTF_8).strip().split("\\|",-1);require(fields.length==14,"RSA15 audit source changed");fields[3]="MessageAuthenticationError";put(folder,m,f,(String.join("|",fields)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));}
      else {
       String f=use.path("processLogFile").asText();String log=new String(files.get(f),java.nio.charset.StandardCharsets.UTF_8);
       if(name.equals("rsa15-cause-wrong-thread"))log=log.replaceAll("( - (?:WARN|ERROR|INFO|DEBUG) )\\[[^]]+]","$1[foreign-thread]");
       else if(name.equals("rsa15-cause-algorithm-prefix"))log=log.replace("http://www.w3.org/2001/04/xmlenc#rsa-1_5","http://www.w3.org/2001/04/xmlenc#rsa-1_5-other");
       else if(name.equals("rsa15-cause-incomplete"))log=log.replaceAll("(?m)^.*\\[org\\.opensaml\\.saml\\.saml2\\.profile\\.impl\\.DecryptNameIDs:[^\\r\\n]*\\r?\\n?","");
       else {var lines=new ArrayList<>(log.lines().toList());int first=-1,second=-1;for(int index=0;index<lines.size();index++){if(lines.get(index).contains("Algorithm failed exclude list validation: http://www.w3.org/2001/04/xmlenc#rsa-1_5"))first=index;if(lines.get(index).endsWith("Failed to decrypt EncryptedKey, valid decryption key could not be resolved"))second=index;}require(first>=0&&second>first,"RSA15 chain order source missing");Collections.swap(lines,first,second);log=String.join("\n",lines)+"\n";}
       byte[] altered=log.getBytes(java.nio.charset.StandardCharsets.UTF_8);require(!Arrays.equals(altered,files.get(f)),"RSA15 cause control did not change its source");put(folder,m,f,altered);((ObjectNode)use.path("processLogRange")).put("afterOffset",use.path("processLogRange").path("beforeOffset").asLong()+altered.length);final ObjectNode replacement=use;nativeEdit(cipher,selected,raw,"nativeUse",n->{n.removeAll();n.setAll(replacement);});
      }
     }
     case "audit-capture-missing","audit-capture-wrong-request","audit-capture-nonempty","audit-capture-too-late","decoder-misbound-thread","decoder-algorithm-prefix","decoder-missing-event","unmarshaller-output-missing","unmarshaller-foreign-run","unmarshaller-wrong-request","unmarshaller-input-tampered","unmarshaller-class-tampered","unmarshaller-invocation-tampered"->{
      var use=json(raw.get(early.path("nativeUseReference").asText()));require("pre-audit-decoder-rejection".equals(use.path("auditMode").asText()),"Actual expected decoder branch missing");
      if(name.equals("audit-capture-missing"))use.remove("auditCaptureFile");
      else if(name.startsWith("audit-capture-")){
       String f=use.path("auditCaptureFile").asText();var capture=json(files.get(f));
       if(name.equals("audit-capture-wrong-request"))capture.put("requestId","_foreign_request");
       else if(name.equals("audit-capture-nonempty")){capture.put("deltaBytes",1).put("afterOffset",capture.path("beforeOffset").asLong()+1).put("deltaSha256",hash(new byte[]{10}));}
       else {var http=json(files.get(use.path("httpFile").asText()));capture.put("beforeCapturedAt",Instant.parse(http.path("startedAt").asText()).plusSeconds(1).toString());}
       put(folder,m,f,J.mapper().writeValueAsBytes(capture));
      }else if(name.startsWith("decoder-")){
       String f=use.path("processLogFile").asText();String log=new String(files.get(f),java.nio.charset.StandardCharsets.UTF_8);
       if(name.equals("decoder-misbound-thread"))log=log.replaceAll("(?m)^(.* - ERROR )\\[[^]]+]( \\[org\\.opensaml\\.profile\\.action\\.impl\\.DecodeMessage:)","$1[foreign-thread]$2");
       else if(name.equals("decoder-algorithm-prefix"))log=log.replace("http://www.w3.org/2001/04/xmldsig-more#rsa-md5","http://www.w3.org/2001/04/xmldsig-more#rsa-md5-other");
       else log=log.replaceAll("(?m)^.*\\[org\\.opensaml\\.profile\\.action\\.impl\\.LogEvent:[^\\r\\n]*\\r?\\n?","");
       byte[] altered=log.getBytes(java.nio.charset.StandardCharsets.UTF_8);require(!Arrays.equals(altered,files.get(f)),"Decoder control did not change native cause");put(folder,m,f,altered);((ObjectNode)use.path("processLogRange")).put("afterOffset",use.path("processLogRange").path("beforeOffset").asLong()+altered.length);
      }else if(name.equals("unmarshaller-output-missing"))use.remove("unmarshallerOutputReference");
      else if(name.equals("unmarshaller-foreign-run")||name.equals("unmarshaller-wrong-request"))nativeEdit(use,selected,raw,"unmarshallerOutput",n->{if(name.equals("unmarshaller-foreign-run"))n.put("runId","run_00000000000000000000000000");else ((ObjectNode)n.path("records").get(1)).put("requestId","_foreign_request");});
      else {String f=use.path("unmarshallerInvocationFile").asText();var call=json(files.get(f));
       if(name.equals("unmarshaller-input-tampered")){String inputFile=call.path("inputFile").asText();var inputJson=json(files.get(inputFile));((ObjectNode)inputJson.path("records").get(1)).put("requestId","_foreign_request");put(folder,m,inputFile,J.mapper().writeValueAsBytes(inputJson));}
       else if(name.equals("unmarshaller-class-tampered")){String file=call.path("classOriginals").path("org.apache.xml.security.algorithms.SignatureAlgorithm").path("classFile").asText();byte[] type=files.get(file).clone();type[type.length-1]^=1;put(folder,m,file,type);}
       else {((ArrayNode)call.path("command")).set(4,TextNode.valueOf("UnboundUnmarshaller"));put(folder,m,f,J.mapper().writeValueAsBytes(call));}
      }
      final ObjectNode replacement=use;nativeEdit(early,selected,raw,"nativeUse",n->{n.removeAll();n.setAll(replacement);});
     }
    }
    require(result(root,run,m,null,selected,raw,target,selectedKeys,complete,false).outcome()==Outcome.NOT_VERIFIED,"Negative control did not remain NV: "+name);negatives.put(name,"NOT_VERIFIED");
   }
   reset(folder,files);Files.write(folder.resolve("manifest.json"),manifestRaw);var life=lifecycle(root,run,entries,bodies,target,keys,false,actual);for(var e:life.entrySet())require(Boolean.TRUE.equals(e.getValue()),"Actual lifecycle changed: "+e);
   var calibration=input.resolve("calibration");require(Files.exists(calibration.resolve("originals.json")),"Required approved detector calibration missing");var diag=J.mapper().readTree(calibration.resolve("originals.json").toFile());require(diag.path("diagnosticOnly").asBoolean(false)&&!diag.path("controlsAdopted").asBoolean(true)&&run.equals(diag.path("runId").asText()),"Calibration not isolated");
   var m=base.deepCopy();m.put("counterfactualCalibrationOnly",true);var calEntries=new ArrayList<>(entries);var calBodies=new HashMap<>(bodies);reset(folder,files);
   for(var fields=diag.path("files").fields();fields.hasNext();){var f=fields.next();byte[] raw=Files.readAllBytes(calibration.resolve(f.getKey()));require(hash(raw).equals(f.getValue().asText()),"Calibration original hash changed");if(raw.length>0)put(folder,m,f.getKey(),raw);}
   byte[] producer=Files.readAllBytes(calibration.resolve("developer-missing-default-prevention.stdout.json"));String outputId=id(run+"-native-policy-diagnostic");calEntries.add(added(outputId,run,producer,Instant.now(),"NativeDiagnostic",null,"urn:samlscope:offline-diagnostic"));calBodies.put(outputId,producer);var diagnostic=json(producer);
   var obs=(ArrayNode)m.path("observations");while(obs.size()>4)obs.remove(obs.size()-1);
   for(var row:obs){var r=(ObjectNode)row;String fixture=r.path("fixtureId").asText();JsonNode produced=null;for(var value:diagnostic.path("records"))if(fixture.equals(value.path("fixtureId").asText()))produced=value;require(produced!=null,"Diagnostic fixture missing");var request=entries.stream().filter(e->e.id().equals(r.path("requestReference").asText())).findFirst().orElseThrow();
    if(produced.has("responseBase64")){byte[] reply=Base64.getDecoder().decode(produced.path("responseBase64").asText());var x=SecureXml.parse(reply).getDocumentElement();String responseId=id(run+fixture+"-response");calEntries.add(added(responseId,run,reply,request.timestamp().plusNanos(1),"Response",x.getAttribute("InResponseTo"),x.getAttribute("Destination")));calBodies.put(responseId,reply);r.put("responseReference",responseId).put("responseSha256",hash(reply));}else{r.remove("responseReference");r.remove("responseSha256");}
    var use=json(calBodies.get(r.path("nativeUseReference").asText()));use.put("counterfactualCalibrationOnly",true).put("diagnosticOnly",true).put("calibrationOutputReference",outputId).put("calibrationOutputSha256",hash(producer)).put("calibrationInvocationFile","developer-missing-default-prevention.invocation.json").put("stockCalibrationOutputFile","stock-policy.stdout.json").put("stockCalibrationOutputSha256",hash(Files.readAllBytes(calibration.resolve("stock-policy.stdout.json")))).put("stockCalibrationInvocationFile","stock-policy.invocation.json");final ObjectNode selected=use;nativeEdit(r,calEntries,calBodies,"nativeUse",n->{n.removeAll();n.setAll(selected);});
   }
   var mutant=result(root,run,m,null,calEntries,calBodies,target,keys,true,true);require(mutant.outcome()==Outcome.VIOLATED,"Approved missing-default-prevention mutant undetected: "+mutant.details());var calLife=lifecycle(root,run,calEntries,calBodies,target,keys,true,mutant);for(var e:calLife.entrySet())require(Boolean.TRUE.equals(e.getValue()),"Offline full-wrapper lifecycle changed: "+e);
   require(result(root,run,m,null,calEntries,calBodies,target,keys,true,false).outcome()==Outcome.NOT_VERIFIED,"Production adopted diagnostic");
   var relabeled=m.deepCopy();relabeled.put("counterfactualCalibrationOnly",false);for(var row:relabeled.path("observations"))nativeEdit((ObjectNode)row,calEntries,calBodies,"nativeUse",n->n.put("counterfactualCalibrationOnly",false).put("diagnosticOnly",false));
   require(result(root,run,relabeled,null,calEntries,calBodies,target,keys,true,false).outcome()==Outcome.NOT_VERIFIED&&result(root,run,relabeled,null,calEntries,calBodies,target,keys,true,true).outcome()==Outcome.NOT_VERIFIED,"Receipt label toggle enabled calibration");
   var report=new TreeMap<String,Object>();report.put("runId",run);report.put("caseId",CASE);report.put("profile","browser_sso_idp");report.put("targetMetadataSha256",hash(target));report.put("manifestSha256",hash(manifestRaw));report.put("outcome",actual);report.put("negativeControls",negatives);report.put("approvedMutant","VIOLATED");report.put("productionDiagnostic","NOT_VERIFIED");report.put("relabeledDiagnosticProductionAndOffline","NOT_VERIFIED");report.put("wrapperLifecycle",life);report.put("offlineCalibrationWrapperLifecycle",calLife);report.put("controlsAdopted",false);report.put("productSettings",0);report.put("protocolSubmissions",0);report.put("credentialPosts",0);report.put("privateCredentialsPersisted",false);J.mapper().writerWithDefaultPrettyPrinter().writeValue(Path.of(args[1]).toFile(),report);
  }finally{try(var all=Files.walk(root)){for(var p:all.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
}
