package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.SloRegisteredSignerEvidence.*;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;

/** Diagnoses presentation ordering on immutable failed originals. Derivatives never become receipts. */
public final class VerifySloMountOrdering {
 static final ObjectMapper M=new JsonCodec().mapper();
 static final Map<String,byte[]> decoded=new HashMap<>();
 static final List<TranscriptEntry> entries=new ArrayList<>();
 static String run;
 static void pin(ObjectNode m,Path folder,String name)throws Exception {
  ((ObjectNode)m.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));
 }
 static void edit(Path folder,ObjectNode m,String phase,java.util.function.Consumer<ObjectNode> change)throws Exception {
  var ref=(ObjectNode)m.path("originals").path(phase);
  var original=(ObjectNode)M.readTree(decoded.get(text(ref,"reference")));
  String path=text(original,"nativeReadbackFile");var state=(ObjectNode)M.readTree(folder.resolve(path).toFile());change.accept(state);
  byte[] raw=M.writeValueAsBytes(state);Files.write(folder.resolve(path),raw);pin(m,folder,path);original.put("nativeReadbackSha256",hash(raw));
  raw=M.writeValueAsBytes(original);decoded.put(text(ref,"reference"),raw);ref.put("sha256",hash(raw));
  path="native-originals/"+phase+".json";Files.write(folder.resolve(path),raw);pin(m,folder,path);
 }
 static void sort(ObjectNode state){
  var rows=new ArrayList<JsonNode>();state.path("runtime").path("mounts").forEach(rows::add);
  rows.sort(Comparator.comparing(n->text(n,"Destination")));
  var sorted=M.createArrayNode();rows.forEach(sorted::add);((ObjectNode)state.path("runtime")).set("mounts",sorted);
 }
 static boolean ready(Path folder,ObjectNode m)throws Exception {
  var recorder=new TranscriptRecorder(){
   public List<TranscriptEntry>list(String r){require(run.equals(r));return entries.stream().map(e->{byte[] b=decoded.get(e.id());return b==null?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),b.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();}
   public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No native operation");}
   public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object>s){throw new AssertionError("No Run mutation");}
  };
  var c=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  TranscriptContentReader content=e->decoded.get(e.id());var o=new Originals(c,folder,content);o.allFiles(m);
  var a=Arrays.stream(SloRegisteredSignerNativeAdapters.create(content)).filter(x->x.adapter().equals(text(m,"adapter"))).findFirst().orElseThrow();
  try{return !a.open(c,folder,m,o,false).registrationEvidence().isEmpty();}catch(IllegalArgumentException expected){return false;}
 }
 public static void main(String[]args)throws Exception {
  require(args.length==3);java.util.logging.LogManager.getLogManager().reset();Path source=Path.of(args[0]).toRealPath(),data=Path.of(args[1]).toRealPath(),output=Path.of(args[2]);require(!Files.exists(output));
  var original=(ObjectNode)M.readTree(source.resolve("preparation.json").toFile());run=text(original,"runId");require(validRun(run));
  try(var db=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=db.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){
   q.setString(1,run);try(var r=q.executeQuery()){while(r.next()){var e=M.readValue(r.getString(1),TranscriptEntry.class);entries.add(e);if(e.decodedSamlRef()!=null){require(e.decodedSamlRef().equals("transcripts/"+run+"/"+e.id()+".saml.xml"));decoded.put(e.id(),Files.readAllBytes(data.resolve(e.decodedSamlRef())));}}}
  }
  var a=M.readTree(source.resolve("native-readbacks/initial.json").toFile()).path("runtime").path("mounts");var b=M.readTree(source.resolve("native-readbacks/probes-before.json").toFile()).path("runtime").path("mounts");
  require(!a.equals(b));var first=new TreeMap<String,JsonNode>();var second=new TreeMap<String,JsonNode>();
  for(var n:a)require(first.put(text(n,"Destination"),n)==null);for(var n:b)require(second.put(text(n,"Destination"),n)==null);require(first.equals(second));
  require(!ready(source,original));Path local=Files.createTempDirectory("slo-mount-derivative-");
  try {
   try(var paths=Files.walk(source)){for(var p:paths.toList()){require(!Files.isSymbolicLink(p));var dest=local.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(dest);else Files.copy(p,dest);}}
   var m=original.deepCopy();edit(local,m,"initial",VerifySloMountOrdering::sort);edit(local,m,"probes-before",VerifySloMountOrdering::sort);require(ready(local,m));
   edit(local,m,"probes-before",n->((ObjectNode)n.path("runtime").path("mounts").get(0)).put("RW",true));require(!ready(local,m));
   var result=new TreeMap<String,Object>();result.put("schema","samlscope-slo-mount-order-diagnostic-v1");result.put("sourceRunId",run);result.put("sourcePreparationSha256",hash(Files.readAllBytes(source.resolve("preparation.json"))));result.put("mounts",a.size());result.put("allActualAttributesEqual",true);result.put("originalPreloginPredicate",false);result.put("canonicalDerivativePreloginPredicate",true);result.put("changedPermissionDerivativePreloginPredicate",false);result.put("diagnosticOnly",true);result.put("actualProductFinding",false);result.put("additionalProductSettings",0);result.put("additionalSaml",0);result.put("additionalCredentials",0);M.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),result);
  } finally {try(var paths=Files.walk(local)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
