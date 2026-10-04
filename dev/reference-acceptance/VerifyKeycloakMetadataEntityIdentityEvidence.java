package com.samlscope.runner.cases;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.*;
import java.time.*;
import java.util.*;

/** Read-only actual production replay. Native producer mutants are calibration only. */
public final class VerifyKeycloakMetadataEntityIdentityEvidence {
 private static final ObjectMapper M=new JsonCodec().mapper();private static final String A1="IIP-MD05-a1-idp-01",A2="IIP-MD05-a2-idp-01";
 private static void require(boolean b,String s){if(!b)throw new IllegalArgumentException(s);}
 private static String sha(byte[] b)throws Exception{return KeycloakMetadataEntityIdentityEvidence.hash(b);}
 private static void regular(Path root,Path file){require(file.normalize().startsWith(root),"outside data");for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p),"symbolic key path");require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS),"missing original key");}
 private record Data(byte[] manifestRaw,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> decoded,Map<String,byte[]> targets,Map<String,PrivateKey> keys){}
 private static Data load(Path folder,Path data)throws Exception{
  var m=(ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());var entries=new HashMap<String,List<TranscriptEntry>>();var decoded=new HashMap<String,byte[]>();var targets=new HashMap<String,byte[]>();var keys=new HashMap<String,PrivateKey>();data=data.toAbsolutePath().normalize();Path db=data.resolve("samlscope.sqlite");if(!Files.isRegularFile(db))db=data.resolve("samlscope.db");regular(data,db);
  for(var peer:m.path("peers")){String label=peer.path("label").asText(),run=peer.path("runId").asText(),plan=peer.path("planId").asText();var child=folder.resolve(label);entries.put(run,List.of(M.readValue(child.resolve("transcript.json").toFile(),TranscriptEntry[].class)));targets.put(run,Files.readAllBytes(child.resolve("target-metadata.xml")));for(var e:M.readTree(child.resolve("decoded-manifest.json").toFile())){var file=child.resolve(e.path("file").asText()).normalize();require(file.getParent().equals(child.resolve("decoded")),"decoded escaped");var b=Files.readAllBytes(file);require(sha(b).equals(e.path("sha256").asText())&&decoded.put(e.path("id").asText(),b)==null,"decoded mismatch");}
   try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+db+"?mode=ro");var q=c.prepareStatement("SELECT plan_id FROM runs WHERE id=?")){q.setString(1,run);try(var rows=q.executeQuery()){require(rows.next()&&plan.equals(rows.getString(1))&&!rows.next(),"unknown peer Run/Plan");}}
   var keyfile=data.resolve("keys").resolve(plan).resolve("signing-key.pk8");regular(data,keyfile);var b=Files.readAllBytes(keyfile);try{keys.put(run,KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(b)));}finally{Arrays.fill(b,(byte)0);}
  }return new Data(Files.readAllBytes(folder.resolve("manifest.json")),m,entries,decoded,targets,keys);
 }
 private static TranscriptEntry copy(TranscriptEntry e,String run,int length,String decodedRef){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),decodedRef,length,e.contentType(),e.rawQuery(),e.samlSummary());}
 private static CaseContext context(Data d,boolean complete){String run=d.manifest.path("runId").asText();var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return d.entries.getOrDefault(r,List.of()).stream().map(e->{var raw=d.decoded.get(e.id());return raw==null?e:copy(e,e.runId(),raw.length,e.decodedSamlRef());}).toList();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("no send");}public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object>s){throw new AssertionError("no update");}};return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);}
 private static TestCase fallback(String id){return new Fallback(id);}
 private record Fallback(String id) implements TestCase,ConfigurationPrompt,ProtocolEvidenceCase,EvidenceCampaignCase,RecordedEvidenceReevaluation {
  public TargetRole role(){return TargetRole.IDP;}public String instructionEn(){return "Approved fixture fallback";}
  public String evidenceCampaignId(){return "metadata-consumer";}public String evidenceCampaignTitle(){return "Metadata consumer";}public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind(){return com.samlscope.runner.RunCampaignQuery.ActionKind.CONFIGURATION;}public List<String>evidenceActionKeys(){return List.of();}
  public CaseStep start(CaseContext c){throw new AssertionError("owned proof escaped");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("owned proof escaped");}public EvidenceStatus evidenceStatus(CaseContext c){throw new AssertionError("owned proof escaped");}
  public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return true;}public Optional<CaseOutcome>reevaluateRecordedEvidence(CaseContext c,CaseOutcome p){throw new AssertionError("owned proof escaped");}
 }
 private static Map<String,CaseOutcome> observe(Path directory,Data d,boolean wrapper)throws Exception {
  Files.write(directory.resolve(d.manifest.path("runId").asText()).resolve("manifest.json"),M.readTree(d.manifestRaw).equals(d.manifest)?d.manifestRaw:M.writeValueAsBytes(d.manifest));var c=context(d,true);var reader=new KeycloakMetadataEntityIdentityEvidence(directory,e->d.decoded.get(e.id()),d.targets::get,r->Optional.ofNullable(d.keys.get(r)));var result=new TreeMap<String,CaseOutcome>();
  for(String id:List.of(A1,A2)){var value=reader.evaluate(c,id).orElseThrow();result.put(id,value);if(wrapper){var w=new MetadataEntityIdentityConfigurationTestCase(fallback(id),directory,e->d.decoded.get(e.id()),d.targets::get,r->Optional.ofNullable(d.keys.get(r)));require(w.start(c).equals(new CaseStep.Finish(value)),"start mismatch");require(w.resume(c,CaseState.initial(),new CaseEvent.TranscriptReady()).equals(new CaseStep.Finish(value)),"resume mismatch");if(value.outcome()!=Outcome.NOT_VERIFIED){require(w.evidenceStatus(c).ready()&&w.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(value),"recorded mismatch");}else require(!w.evidenceStatus(c).ready(),"invalid ready");}}
  return result;
 }
 private static void rehash(Path folder,Data d,String name)throws Exception{((ObjectNode)d.manifest.path("files")).put(name,sha(Files.readAllBytes(folder.resolve(name))));}
 private static void originalEdit(Path folder,Data d,String label,java.util.function.Consumer<ObjectNode> edit)throws Exception{
  var ref=(ObjectNode)d.manifest.path("originals").path(label);var n=(ObjectNode)M.readTree(d.decoded.get(ref.path("reference").asText()));edit.accept(n);var b=M.writeValueAsBytes(n);d.decoded.put(ref.path("reference").asText(),b);ref.put("sha256",sha(b));String file="native-originals/"+label+".json";Files.write(folder.resolve(file),b);rehash(folder,d,file);
 }
 private static ObjectNode publicValue(ObjectNode nativeNode)throws Exception{return (ObjectNode)M.readTree(Base64.getDecoder().decode(nativeNode.path("response_base64").asText()));}
 private static void setResponse(ObjectNode nativeNode,JsonNode value)throws Exception{byte[] b=value==null?new byte[0]:M.writeValueAsBytes(value);nativeNode.put("response_base64",Base64.getEncoder().encodeToString(b));nativeNode.put("response_sha256",sha(b));}
 public static void main(String[] args)throws Exception {
  Path source=Path.of(args[0]).toRealPath(),data=Path.of(args[1]).toAbsolutePath().normalize(),output=Path.of(args[2]);boolean wrappers=args.length<4||!"--leaf-only".equals(args[3]);require(!Files.exists(output),"output exists");var temp=Files.createTempDirectory("kc-entity-identity-");String run=M.readTree(source.resolve("manifest.json").toFile()).path("runId").asText();Path directory=temp.resolve("keycloak-metadata-entity-identity-evidence"),folder=directory.resolve(run);Files.createDirectories(folder);
  try{
   try(var paths=Files.walk(source)){for(var p:paths.filter(Files::isRegularFile).toList()){var dest=folder.resolve(source.relativize(p).toString());Files.createDirectories(dest.getParent());Files.copy(p,dest);}}
   var base=load(folder,data);var baseline=observe(directory,base,wrappers);for(var v:baseline.values())require(v.outcome()==Outcome.SATISFIED,"positive not satisfied: "+v);var checks=new TreeMap<String,Object>();
   var originalFiles=new HashMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList())originalFiles.put(folder.relativize(p).toString(),Files.readAllBytes(p));}
   for(String name:List.of("wrong-run","wrong-adapter","wrong-target","wrong-campaign","unknown-secondary","foreign-native-lookup","duplicate-history","foreign-history","foreign-decoded-ref","wrong-native-method","wrong-native-conflict-message","explicit-replacement-not-simultaneous","converter-output-not-posted","missing-normal","wrong-secondary-key","fixture-not-original","native-redaction-removes-keys","readback-before-normal-incomplete","native-policy-change","restore-client-remains","cost-omits-credential","duplicate-identity-overwrite")){
    for(var e:originalFiles.entrySet())Files.write(folder.resolve(e.getKey()),e.getValue());var d=load(folder,data);
    switch(name){
     case "wrong-run"->d.manifest.put("runId","run_00000000000000000000000000");
     case "wrong-adapter"->d.manifest.put("adapter","unknown");case "wrong-target"->d.manifest.put("targetMetadataSha256","0".repeat(64));case "wrong-campaign"->d.manifest.put("campaignId","unrelated");
     case "foreign-native-lookup"->((ObjectNode)d.manifest.path("peers").get(1)).put("lookup","/clients?clientId=unrelated&briefRepresentation=true");
     case "unknown-secondary"->((ObjectNode)d.manifest.path("peers").get(1)).put("runId","run_00000000000000000000000000");
     case "duplicate-history","foreign-history","foreign-decoded-ref"->{String secondary=d.manifest.path("peers").get(1).path("runId").asText();var rows=new ArrayList<>(d.entries.get(secondary));var e=rows.getFirst();if(name.equals("duplicate-history"))rows.add(e);else rows.set(0,copy(e,name.equals("foreign-history")?run:e.runId(),e.decodedSamlBytes(),name.equals("foreign-decoded-ref")?"transcripts/"+run+"/"+e.id()+".saml.xml":e.decodedSamlRef()));d.entries.put(secondary,rows);}
     case "wrong-native-method"->originalEdit(folder,d,"duplicate-create",n->((ObjectNode)n.path("native")).put("method","GET"));
     case "wrong-native-conflict-message"->originalEdit(folder,d,"duplicate-create",n->{try{setResponse((ObjectNode)n.path("native"),M.createObjectNode().put("errorMessage","Unauthenticated"));}catch(Exception e){throw new RuntimeException(e);}});
     case "explicit-replacement-not-simultaneous"->originalEdit(folder,d,"duplicate-create",n->{((ObjectNode)n.path("native")).put("method","PUT");((ObjectNode)n.path("native")).put("url",n.path("native").path("url").asText()+"/"+d.manifest.path("peers").get(0).path("clientId").asText());});
     case "converter-output-not-posted"->originalEdit(folder,d,"duplicate-create",n->((ObjectNode)n.path("native")).put("request_sha256","0".repeat(64)));
     case "missing-normal"->d.decoded.remove(d.manifest.path("peers").get(1).path("normal").path("responseReference").asText());
     case "wrong-secondary-key"->d.keys.put(d.manifest.path("peers").get(1).path("runId").asText(),d.keys.get(run));
     case "fixture-not-original"->originalEdit(folder,d,"primary-conversion",n->n.put("fixtureSha256","0".repeat(64)));
     case "native-redaction-removes-keys"->originalEdit(folder,d,"duplicate-after",n->((ObjectNode)n.path("peers").get(0).path("native")).putArray("redactions").add("$.attributes.saml.signing.certificate"));
     case "readback-before-normal-incomplete"->originalEdit(folder,d,"normal-before",n->((ArrayNode)n.path("peers")).remove(1));
     case "native-policy-change"->originalEdit(folder,d,"duplicate-after",n->((ArrayNode)n.at("/policies/policies/policies")).add("constraint"));
     case "restore-client-remains"->originalEdit(folder,d,"restoration",n->n.put("restored",false));
     case "cost-omits-credential"->{var n=(ObjectNode)M.readTree(folder.resolve("operation-counts.json").toFile());n.put("credentialPosts",0);Files.write(folder.resolve("operation-counts.json"),M.writeValueAsBytes(n));rehash(folder,d,"operation-counts.json");}
     case "duplicate-identity-overwrite"->{var original=M.readTree(d.decoded.get(d.manifest.path("originals").path("duplicate-conversion").path("reference").asText()));var converted=M.readTree(Base64.getDecoder().decode(original.path("native").path("response_base64").asText()));
      originalEdit(folder,d,"duplicate-create",n->{try{((ObjectNode)n.path("native")).put("status",201);setResponse((ObjectNode)n.path("native"),null);}catch(Exception e){throw new RuntimeException(e);}});
      originalEdit(folder,d,"duplicate-after",n->{try{var nativeNode=(ObjectNode)n.path("peers").get(0).path("native");var saved=publicValue(nativeNode);var attrs=(ObjectNode)saved.path("attributes");var fields=converted.path("attributes").fields();while(fields.hasNext()){var f=fields.next();attrs.set(f.getKey(),f.getValue());}saved.set("redirectUris",converted.path("redirectUris"));setResponse(nativeNode,saved);}catch(Exception e){throw new RuntimeException(e);}});
      var cost=(ObjectNode)M.readTree(folder.resolve("operation-counts.json").toFile());cost.put("nativeConfigurationWrites",5);Files.write(folder.resolve("operation-counts.json"),M.writeValueAsBytes(cost));rehash(folder,d,"operation-counts.json");
     }
    }
    if(name.equals("wrong-run"))Files.createDirectories(directory.resolve(d.manifest.path("runId").asText()));
    var outcome=observe(directory,d,wrappers);for(var v:outcome.values())require(v.outcome()==(name.equals("duplicate-identity-overwrite")?Outcome.VIOLATED:Outcome.NOT_VERIFIED),name+" wrongly accepted: "+v);checks.put(name,outcome);
   }
   for(var e:originalFiles.entrySet())Files.write(folder.resolve(e.getKey()),e.getValue());
   M.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("runId",run,"production_outcomes",baseline,"checks",checks,"shared_native_lifecycle",wrappers,"privateMaterialExported",false,"calibrationOnly",true,"additionalProductOperations",0));System.out.println("Native entity identity production replay PASS "+checks.size()+" controls");
  }finally{try(var paths=Files.walk(temp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
}
