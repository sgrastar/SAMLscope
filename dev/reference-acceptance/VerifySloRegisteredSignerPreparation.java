package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.SloRegisteredSignerEvidence.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.*;
import java.time.*;
import java.util.*;

/** Calls the same native preparation predicates before credentials, and the full session predicate
 * before generating SLO controls. This utility neither adopts outcomes nor mutates Run history. */
public final class VerifySloRegisteredSignerPreparation {
 public static void main(String[]args)throws Exception {
  require(args.length==4&&Set.of("native","prepared").contains(args[3]));
  java.util.logging.LogManager.getLogManager().reset();
  var json=new JsonCodec().mapper();Path folder=Path.of(args[0]).toRealPath(),data=Path.of(args[1]).toRealPath(),report=Path.of(args[2]);require(!Files.exists(report));
  var manifest=json.readTree(folder.resolve("preparation.json").toFile());String run=text(manifest,"runId");require(validRun(run)&&"samlscope-slo-registered-signer-preparation-v1".equals(text(manifest,"schema")));
  var keys=new HashMap<String,PlanCredentials>();var targets=new HashMap<String,byte[]>();var entries=new ArrayList<TranscriptEntry>();
  try(var db=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro")) {
   for(var peer:manifest.path("peers")) {
    String peerRun=text(peer,"runId"),plan=text(peer,"planId");require(validRun(peerRun)&&plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
    try(var q=db.prepareStatement("SELECT plan_id FROM runs WHERE id=?")){q.setString(1,peerRun);try(var r=q.executeQuery()){require(r.next()&&plan.equals(r.getString(1))&&!r.next());}}
    Path key=data.resolve("keys/"+plan+"/signing-key.pk8"),cert=data.resolve("keys/"+plan+"/signing-certificate.der");safe(data,key);safe(data,cert);byte[] raw=Files.readAllBytes(key);
    try {keys.put(peerRun,new PlanCredentials(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw)),(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(cert))));}finally{Arrays.fill(raw,(byte)0);}
    Path target=data.resolve("target-metadata/"+peerRun+".xml");safe(data,target);targets.put(peerRun,Files.readAllBytes(target));
   }
   try(var q=db.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){q.setString(1,run);try(var r=q.executeQuery()){while(r.next())entries.add(json.readValue(r.getString(1),TranscriptEntry.class));}}
  }
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){require(run.equals(r));return List.copyOf(entries);}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No target operation");}public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object>s){throw new AssertionError("No history mutation");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  TranscriptContentReader content=e->{try{require(e.runId().equals(run)&&e.decodedSamlRef().equals("transcripts/"+run+"/"+e.id()+".saml.xml"));Path p=data.resolve(e.decodedSamlRef());safe(data,p);return Files.readAllBytes(p);}catch(Exception bad){throw new IllegalArgumentException("Scoped original unreadable");}};
  var adapters=SloRegisteredSignerNativeAdapters.create(content);var reader=new SloRegisteredSignerEvidence(folder.getParent(),content,targets::get,(r,alias)->"primary".equals(alias)?Optional.ofNullable(keys.get(r)):Optional.empty(),adapters);
  var result=new TreeMap<String,Object>();result.put("schema","samlscope-slo-preparation-qualification-v1");result.put("runId",run);result.put("mode",args[3]);result.put("preparationSha256",hash(Files.readAllBytes(folder.resolve("preparation.json"))));result.put("newProductSettings",0);result.put("newSaml",0);result.put("newCredentialPosts",0);result.put("privateMaterialExported",false);result.put("diagnosticOnly",true);
  boolean ready=false;
  try {
   var originals=new Originals(context,folder,content);originals.allFiles(manifest);
   for(var peer:manifest.path("peers")) {var metadata=com.samlscope.saml.normal.SecureXml.parse(originals.file(manifest,text(peer,"label")+"/fixture.xml")).getDocumentElement();var key=keys.get(text(peer,"runId"));require(key!=null&&signingKeys(metadata).stream().anyMatch(c->Arrays.equals(c.getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded()))&&Arrays.equals(targets.get(text(peer,"runId")),originals.file(manifest,"target-metadata.xml")));}
   var adapter=Arrays.stream(adapters).filter(a->a.adapter().equals(text(manifest,"adapter"))).findFirst().orElseThrow();require(!adapter.open(context,folder,manifest,originals,false).registrationEvidence().isEmpty());result.put("nativePreparationVerified",true);
   // Exercise the exact installed POST/XML fixture factory before spending a login. This
   // synthetic NameID is a construction prerequisite only, never evidence of a session.
   var primary=manifest.path("peers").get(0);var secondary=manifest.path("peers").get(1);
   var target=com.samlscope.saml.normal.SecureXml.parse(targets.get(run)).getDocumentElement();
   var peer=com.samlscope.saml.normal.SecureXml.parse(originals.file(manifest,"primary/fixture.xml")).getDocumentElement();
   var input=new SloRegisteredSignerProbeInputs(run,text(secondary,"runId"),text(primary,"entity"),endpoint(target,"IDPSSODescriptor","SingleLogoutService"),endpoint(peer,"SPSSODescriptor","SingleLogoutService"),
       ("<s:NameID xmlns:s=\"urn:oasis:names:tc:SAML:2.0:assertion\">construction-only</s:NameID>").getBytes(java.nio.charset.StandardCharsets.UTF_8),List.of("construction-only"),hash(Files.readAllBytes(folder.resolve("preparation.json"))));
   var own=keys.get(run);var other=keys.get(text(secondary,"runId"));int constructed=0;
   for(String fixture:SloRegisteredSignerComparison.FIXTURES){var raw=SloRegisteredSignerFixtures.build(fixture,"_construction-only-"+fixture,Instant.now(),input,own,other);var xml=com.samlscope.saml.normal.SecureXml.parse(raw).getDocumentElement();
    boolean ownValid=signed(xml,List.of(own.certificate())),otherValid=signed(xml,List.of(other.certificate()));
    require(ownValid=="local-normal".equals(fixture)&&otherValid=="local-other-signer".equals(fixture));constructed++;}
   require(constructed==3);result.put("preloginFixtureExecutionVerified",constructed);result.put("fixtureConstructionIsSessionEvidence",false);
   if(args[3].equals("native"))ready=true;
   else {
    var method=SloRegisteredSignerEvidence.class.getDeclaredMethod("frame",CaseContext.class,Originals.class,com.fasterxml.jackson.databind.JsonNode.class);method.setAccessible(true);method.invoke(reader,context,originals,manifest);
    require(folder.getFileName().toString().equals(run));ready=reader.probeInputs(context).isPresent();
   }
  }catch(Throwable failed){Throwable cause=failed instanceof java.lang.reflect.InvocationTargetException i?i.getCause():failed;result.put("exceptionClass",cause.getClass().getSimpleName());result.put("sourceLocations",Arrays.stream(cause.getStackTrace()).limit(5).map(e->e.getClassName()+":"+e.getLineNumber()).toList());}
  result.put("ready",ready);json.writerWithDefaultPrettyPrinter().writeValue(report.toFile(),result);if(!ready)System.exit(2);
 }
 static void safe(Path root,Path file){require(file.normalize().startsWith(root)&&Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS));for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p));}
}
