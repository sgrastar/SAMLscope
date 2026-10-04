package com.samlscope.runner.cases;
import com.fasterxml.jackson.databind.*;
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
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.*;
import java.time.*;
import java.util.*;
import org.w3c.dom.Element;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;

/** Actual archived reader first in classpath; synthetic producer controls stay in this private replay scope. */
public final class VerifySimpleSamlPhpRegisteredSignerEvidence {
 private static final ObjectMapper M=new JsonCodec().mapper();private static final String CASE="IIP-SSO01-al-idp-01",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol",DS="http://www.w3.org/2000/09/xmldsig#";
 private static void require(boolean b,String s){if(!b)throw new IllegalArgumentException(s);}
 private static String sha(byte[] b)throws Exception{return SimpleSamlPhpRegisteredSignerEvidence.hash(b);}
 private record Data(byte[] manifestRaw,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> decoded,Map<String,byte[]> targets,Map<String,PlanCredentials> keys){}
 private static void regular(Path root,Path file){require(file.normalize().startsWith(root),"outside data");for(var p=file;p!=null;p=p.getParent())require(!Files.isSymbolicLink(p),"symlink key");require(Files.isRegularFile(file,LinkOption.NOFOLLOW_LINKS),"missing original");}
 private static Data load(Path folder,Path data,Path replayRoot)throws Exception {
  var m=(ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());var entries=new HashMap<String,List<TranscriptEntry>>();var decoded=new HashMap<String,byte[]>();var targets=new HashMap<String,byte[]>();var keys=new HashMap<String,PlanCredentials>();data=data.toAbsolutePath().normalize();var db=data.resolve("samlscope.db");regular(data,db);
  for(var peer:m.path("peers")){String label=peer.path("label").asText(),run=peer.path("runId").asText(),plan=peer.path("planId").asText();var child=folder.resolve(label);entries.put(run,List.of(M.readValue(child.resolve("transcript.json").toFile(),TranscriptEntry[].class)));targets.put(run,Files.readAllBytes(child.resolve("target-metadata.xml")));
   for(var row:M.readTree(child.resolve("decoded-manifest.json").toFile())){var file=child.resolve(row.path("file").asText()).normalize();require(file.getParent().equals(child.resolve("decoded")),"decoded escaped");var b=Files.readAllBytes(file);require(sha(b).equals(row.path("sha256").asText())&&decoded.put(row.path("id").asText(),b)==null,"decoded mismatch");}
   for(var row:M.readTree(child.resolve("browser-originals-manifest.json").toFile())){var file=child.resolve(row.path("file").asText()).normalize();require(file.getParent().equals(child.resolve("browser-originals")),"body escaped");var b=Files.readAllBytes(file);require(sha(b).equals(row.path("sha256").asText()),"body mismatch");var dest=replayRoot.resolve("transcripts/"+run+"/"+row.path("id").asText()+".body");Files.createDirectories(dest.getParent());Files.write(dest,b);}
   try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+db+"?mode=ro");var q=c.prepareStatement("SELECT plan_id FROM runs WHERE id=?")){q.setString(1,run);try(var rows=q.executeQuery()){require(rows.next()&&plan.equals(rows.getString(1))&&!rows.next(),"unknown peer Run/Plan");}}
   var keyfile=data.resolve("keys").resolve(plan).resolve("signing-key.pk8");var certfile=data.resolve("keys").resolve(plan).resolve("signing-certificate.der");regular(data,keyfile);regular(data,certfile);var b=Files.readAllBytes(keyfile);try{keys.put(run,new PlanCredentials(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(b)),(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(Files.newInputStream(certfile))));}finally{Arrays.fill(b,(byte)0);}
  }return new Data(Files.readAllBytes(folder.resolve("manifest.json")),m,entries,decoded,targets,keys);
 }
 private static TranscriptEntry copy(TranscriptEntry e,String run,int length,String ref){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),ref,length,e.contentType(),e.rawQuery(),e.samlSummary());}
 private static CaseContext context(Data d,boolean complete){String run=d.manifest.path("peers").get(0).path("runId").asText();var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return d.entries.getOrDefault(r,List.of()).stream().map(e->{var b=d.decoded.get(e.id());return b==null?e:copy(e,e.runId(),b.length,e.decodedSamlRef());}).toList();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("no send");}public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object>s){throw new AssertionError("no history write");}};return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);}
 private static class Fallback implements TestCase,AttestationPrompt {public String id(){return CASE;}public TargetRole role(){return TargetRole.IDP;}public String promptEn(){return "Approved fallback";}public List<AttestationOption>options(){return List.of();}public CaseStep start(CaseContext c){throw new AssertionError("owned proof escaped");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("owned proof escaped");}}
 private static CaseOutcome observe(Path dir,Data d,boolean wrapper)throws Exception {
  var folder=dir.resolve(d.manifest.path("peers").get(0).path("runId").asText());Files.write(folder.resolve("manifest.json"),M.readTree(d.manifestRaw).equals(d.manifest)?d.manifestRaw:M.writeValueAsBytes(d.manifest));var c=context(d,true);var value=new SimpleSamlPhpRegisteredSignerEvidence(dir,e->d.decoded.get(e.id()),d.targets::get,(r,v)->Optional.ofNullable(d.keys.get(r))).evaluate(c).orElseThrow();
  if(wrapper){var w=new RegisteredSignerObservationTestCase(new Fallback(),dir.resolveSibling("unused-keycloak-native"),e->d.decoded.get(e.id()),d.targets::get,(r,v)->Optional.ofNullable(d.keys.get(r)),new SimpleSamlPhpRegisteredSignerEvidence(dir,e->d.decoded.get(e.id()),d.targets::get,(r,v)->Optional.ofNullable(d.keys.get(r))));require(w.start(c).equals(new CaseStep.Finish(value)),"start mismatch");for(var event:List.<CaseEvent>of(new CaseEvent.TranscriptReady(),new CaseEvent.Attested("satisfied","not used"),new CaseEvent.ConfigConfirmed()))require(w.resume(c,CaseState.initial(),event).equals(new CaseStep.Finish(value)),"resume mismatch");if(value.outcome()!=Outcome.NOT_VERIFIED){require(w.evidenceStatus(c).ready()&&w.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(value),"recorded mismatch");}else require(!w.evidenceStatus(c).ready(),"invalid ready");}
  return value;
 }
 private static void rehash(Path folder,Data d,String name)throws Exception{((ObjectNode)d.manifest.path("files")).put(name,sha(Files.readAllBytes(folder.resolve(name))));}
 private static void originalEdit(Path folder,Data d,String label,java.util.function.Consumer<ObjectNode> edit)throws Exception{
  var ref=(ObjectNode)d.manifest.path("originals").path(label);var n=(ObjectNode)M.readTree(d.decoded.get(ref.path("reference").asText()));edit.accept(n);var b=M.writeValueAsBytes(n);d.decoded.put(ref.path("reference").asText(),b);ref.put("sha256",sha(b));String file="native-originals/"+label+".json";Files.write(folder.resolve(file),b);rehash(folder,d,file);
 }
 private static void readbackEdit(Path folder,Data d,String label,java.util.function.Consumer<ObjectNode> edit)throws Exception {
  String name="native-readbacks/"+label+".json";var n=(ObjectNode)M.readTree(folder.resolve(name).toFile());edit.accept(n);var raw=M.writeValueAsBytes(n);Files.write(folder.resolve(name),raw);rehash(folder,d,name);
  originalEdit(folder,d,label,original->{n.fields().forEachRemaining(e->original.set(e.getKey(),e.getValue()));try{original.put("nativeReadbackSha256",sha(raw));}catch(Exception failure){throw new IllegalArgumentException(failure);}});
 }
 private static void bodyEdit(Path dataRoot,Path folder,Data d,String label,String replacement)throws Exception {
  var row=d.manifest.path("probes").get(2);String run=row.path("runId").asText(),reference=row.path("responseReference").asText();var body=replacement.getBytes(java.nio.charset.StandardCharsets.UTF_8);Files.write(dataRoot.resolve("transcripts/"+run+"/"+reference+".body"),body);
  var entries=new ArrayList<TranscriptEntry>();for(var e:d.entries.get(run)){if(e.id().equals(reference))entries.add(new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),body.length,e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));else entries.add(e);}d.entries.put(run,entries);
  originalEdit(folder,d,label,n->{try{((ObjectNode)n.path("native")).put("responseBodySha256",sha(body)).put("responseBodyBytes",body.length);}catch(Exception failure){throw new IllegalArgumentException(failure);}});
 }
 private static PlanCredentials calibrationKey()throws Exception{Security.addProvider(new BouncyCastleProvider());var g=KeyPairGenerator.getInstance("RSA");g.initialize(2048);var pair=g.generateKeyPair();var subject=new X500Name("CN=Memory-only signer calibration");var now=Instant.now();var cert=new JcaX509v3CertificateBuilder(subject,java.math.BigInteger.ONE,java.util.Date.from(now.minusSeconds(86400)),java.util.Date.from(now.plusSeconds(86400)),subject,pair.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(pair.getPrivate()));return new PlanCredentials(pair.getPrivate(),new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert));}
 private static void strip(Element e){for(var signature:children(e,DS,"Signature"))e.removeChild(signature);}
 private static byte[] signedResponse(Data d,JsonNode peer,String requestId,byte[] actual,PlanCredentials signer)throws Exception {
  var doc=SecureXml.parse(actual);var root=doc.getDocumentElement();strip(root);root.setAttribute("InResponseTo",requestId);var encrypted=children(root,S,"EncryptedAssertion");Element assertion;
  if(encrypted.isEmpty())assertion=children(root,S,"Assertion").getFirst();else assertion=new SamlXmlDecrypter().decrypt(encrypted.getFirst(),d.keys.get(peer.path("runId").asText()).privateKey());strip(assertion);
  var sc=assertion.getElementsByTagNameNS(S,"SubjectConfirmationData");((Element)sc.item(0)).setAttribute("InResponseTo",requestId);new XmlSigner().sign(assertion,signer,children(assertion,S,"Subject").getFirst());
  if(!encrypted.isEmpty()){var enc=new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,assertion,d.keys.get(peer.path("runId").asText()).certificate().getPublicKey(),new SamlEncryptionFixtureFactory.Algorithms(SamlEncryptionFixtureFactory.Content.AES128_GCM,SamlEncryptionFixtureFactory.Transport.RSA_OAEP,SamlEncryptionFixtureFactory.Digest.DEFAULT,SamlEncryptionFixtureFactory.Mgf.DEFAULT));root.replaceChild(doc.importNode(enc,true),encrypted.getFirst());}
  new XmlSigner().sign(root,signer,children(root,P,"Status").getFirst());return SecureXml.serialize(doc);
 }
 private static void producer(Path folder,Data d,boolean invalid)throws Exception {
  var signer=calibrationKey();var targetDoc=SecureXml.parse(d.targets.get(d.manifest.path("runId").asText()));var cert=Base64.getEncoder().encodeToString(signer.certificate().getEncoded());var certs=targetDoc.getElementsByTagNameNS(DS,"X509Certificate");for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(cert);byte[] target=SecureXml.serialize(targetDoc);String digest=sha(target);d.manifest.put("targetMetadataSha256",digest);Files.write(folder.resolve("target-metadata.xml"),target);rehash(folder,d,"target-metadata.xml");
  var prep=(ObjectNode)M.readTree(folder.resolve("preparation.json").toFile());prep.put("targetMetadataSha256",digest);((ObjectNode)prep.path("files")).put("target-metadata.xml",digest);Files.write(folder.resolve("preparation.json"),M.writeValueAsBytes(prep));rehash(folder,d,"preparation.json");
  for(var peer:d.manifest.path("peers")){String run=peer.path("runId").asText(),label=peer.path("label").asText();d.targets.put(run,target);Files.write(folder.resolve(label+"/target-metadata.xml"),target);rehash(folder,d,label+"/target-metadata.xml");}
  var labels=new ArrayList<String>();d.manifest.path("originals").fieldNames().forEachRemaining(labels::add);for(String label:labels)originalEdit(folder,d,label,n->n.put("targetMetadataSha256",digest));
  for(int i=0;i<2;i++){var peer=d.manifest.path("peers").get(i);String run=peer.path("runId").asText();var normal=d.manifest.path("probes").get(i*3);var actual=d.decoded.get(normal.path("responseReference").asText());d.decoded.put(normal.path("responseReference").asText(),signedResponse(d,peer,"_"+normal.path("actionId").asText(),actual,signer));var row=(ObjectNode)d.manifest.path("probes").get(i*3+(invalid?1:2));String responseId=row.path("responseReference").asText(),requestId="_"+row.path("actionId").asText();var xml=signedResponse(d,peer,requestId,actual,signer);d.decoded.put(responseId,xml);var changed=new ArrayList<TranscriptEntry>();for(var e:d.entries.get(run)){if(e.id().equals(responseId))changed.add(new TranscriptEntry(e.id(),run,Direction.INBOUND,e.timestamp(),e.correlationId(),"POST",peer.path("entity").asText()+"/sp/acs/0",200,Map.of(),e.bodyRef(),e.bodyBytes(),"transcripts/"+run+"/"+e.id()+".saml.xml",xml.length,"application/x-www-form-urlencoded",null,Map.of("type","SAMLResponse","inResponseTo",requestId)));else changed.add(e);}d.entries.put(run,changed);String old=row.path("nativeHttpOriginal").asText();row.remove("nativeHttpOriginal");((ObjectNode)d.manifest.path("originals")).remove(old);}
 }
 public static void main(String[] args)throws Exception {
  var source=Path.of(args[0]).toRealPath();var data=Path.of(args[1]);var output=Path.of(args[2]);require(!Files.exists(output),"immutable replay output");var temp=Files.createTempDirectory("ssp-registered-signer-");String run=M.readTree(source.resolve("manifest.json").toFile()).path("runId").asText();var dir=temp.resolve("registered-signer-evidence-simplesamlphp");var folder=dir.resolve(run);Files.createDirectories(folder);
  try {
   try(var paths=Files.walk(source)){for(var p:paths.filter(Files::isRegularFile).toList()){var dest=folder.resolve(source.relativize(p));Files.createDirectories(dest.getParent());Files.copy(p,dest);}}
   var base=load(folder,data,temp);var outcome=observe(dir,base,true);require(outcome.outcome()==Outcome.SATISFIED,"positive not satisfied: "+outcome);var checks=new TreeMap<String,Object>();var backup=new HashMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList())backup.put(folder.relativize(p).toString(),Files.readAllBytes(p));}
   for(String name:List.of("wrong-run","wrong-adapter","wrong-target","wrong-campaign","foreign-plan","missing-normal","foreign-history","duplicate-history","foreign-decoded-ref","foreign-primary-key","unrelated-native-http","native-request-hash-mismatch","native-body-hash-mismatch","native-signature-setting-disabled","native-readback-key-missing","native-runtime-epoch-changed","missing-native-peer","missing-restoration","restoration-configuration-changed","cost-omits-credential","private-native-readback","generic-native-http500","foreign-native-issuer","foreign-selected-entity","wrong-native-error-code","foreign-nameid-policy-same-native500","invalid-signature-accepted","any-trusted-signer-accepted")) {
    for(var b:backup.entrySet())Files.write(folder.resolve(b.getKey()),b.getValue());var d=load(folder,data,temp);var first=d.manifest.path("peers").get(0);var second=d.manifest.path("peers").get(1);String primary=first.path("runId").asText(),http="primary-local-other-signer-http";
    switch(name){
     case "wrong-run"->d.manifest.put("runId","run_00000000000000000000000000");case "wrong-adapter"->d.manifest.put("adapter","unknown");case "wrong-target"->d.manifest.put("targetMetadataSha256","0".repeat(64));case "wrong-campaign"->d.manifest.put("campaignId","unrelated");case "foreign-plan"->((ObjectNode)second).put("planId","plan_00000000000000000000000000");
     case "missing-normal"->{String id=d.manifest.path("probes").get(0).path("responseReference").asText();d.entries.put(primary,d.entries.get(primary).stream().filter(e->!id.equals(e.id())).toList());}
     case "foreign-history"->{var rows=new ArrayList<>(d.entries.get(primary));var e=rows.getFirst();rows.set(0,copy(e,"run_00000000000000000000000000",e.decodedSamlBytes(),e.decodedSamlRef()));d.entries.put(primary,rows);}
     case "duplicate-history"->{var rows=new ArrayList<>(d.entries.get(primary));rows.add(rows.getFirst());d.entries.put(primary,rows);}
     case "foreign-decoded-ref"->{var rows=new ArrayList<>(d.entries.get(primary));int i=0;while(rows.get(i).decodedSamlRef()==null)i++;var e=rows.get(i);rows.set(i,copy(e,e.runId(),e.decodedSamlBytes(),"transcripts/"+second.path("runId").asText()+"/"+e.id()+".saml.xml"));d.entries.put(primary,rows);}
     case "foreign-primary-key"->d.keys.put(primary,d.keys.get(second.path("runId").asText()));
     case "unrelated-native-http"->originalEdit(folder,d,http,n->n.put("actionId","unrelated"));
     case "native-request-hash-mismatch"->originalEdit(folder,d,http,n->((ObjectNode)n.path("native")).put("requestSha256","0".repeat(64)));
     case "native-body-hash-mismatch"->originalEdit(folder,d,http,n->((ObjectNode)n.path("native")).put("responseBodySha256","0".repeat(64)));
     case "native-signature-setting-disabled"->{for(String phase:List.of("probes-before","probes-after"))readbackEdit(folder,d,phase,n->((ObjectNode)n.path("peers").get(0).path("resolvedMetadata")).put("validate.authnrequest",false));}
     case "native-readback-key-missing"->{for(String phase:List.of("probes-before","probes-after"))readbackEdit(folder,d,phase,n->((ArrayNode)n.path("peers").get(0).path("signingKeys")).removeAll());}
     case "native-runtime-epoch-changed"->originalEdit(folder,d,"probes-after",n->((ObjectNode)n.path("runtime")).put("startedAt","changed"));
     case "missing-native-peer"->{for(String phase:List.of("probes-before","probes-after"))readbackEdit(folder,d,phase,n->((ArrayNode)n.path("peers")).remove(1));}
     case "missing-restoration"->((ObjectNode)d.manifest.path("originals")).remove("restoration");
     case "restoration-configuration-changed"->{Files.writeString(folder.resolve("final-configuration.php"),"changed");rehash(folder,d,"final-configuration.php");}
     case "cost-omits-credential"->{var file=folder.resolve("operation-counts.json");var n=(ObjectNode)M.readTree(file.toFile());n.put("credentialPosts",0);Files.write(file,M.writeValueAsBytes(n));rehash(folder,d,"operation-counts.json");}
     case "private-native-readback"->readbackEdit(folder,d,"probes-before",n->n.put("password","never-product-data"));
     case "generic-native-http500"->bodyEdit(temp,folder,d,http,"<h1>HTTP500 UNHANDLEDEXCEPTION</h1>");
     case "foreign-native-issuer","foreign-selected-entity","wrong-native-error-code"->{var row=d.manifest.path("probes").get(2);var page=Files.readString(temp.resolve("transcripts/"+primary+"/"+row.path("responseReference").asText()+".body"));String field=name.equals("foreign-native-issuer")?"%ISSUER%":"%ENTITYID%";String old=first.path("entity").asText().replace("/","\\/");if(name.equals("wrong-native-error-code"))page=page.replace("NOTVALIDCERTSIGNATURE","UNHANDLEDEXCEPTION");else page=page.replace(field+"&quot;:&quot;"+old,field+"&quot;:&quot;foreign");require(!page.equals(Files.readString(temp.resolve("transcripts/"+primary+"/"+row.path("responseReference").asText()+".body"))),"native error control did not mutate");bodyEdit(temp,folder,d,http,page);}
     case "foreign-nameid-policy-same-native500"->{var row=d.manifest.path("probes").get(2);String reference=row.path("requestReference").asText();var doc=SecureXml.parse(d.decoded.get(reference));var root=doc.getDocumentElement();strip(root);children(root,P,"NameIDPolicy").getFirst().setAttribute("Format","urn:samlscope:unsupported:policy");new XmlSigner().sign(root,d.keys.get(second.path("runId").asText()),children(root,P,"NameIDPolicy").getFirst());var changed=SecureXml.serialize(doc);d.decoded.put(reference,changed);originalEdit(folder,d,http,n->{try{((ObjectNode)n.path("native")).put("requestSha256",sha(changed));}catch(Exception failure){throw new IllegalArgumentException(failure);}});}
     case "invalid-signature-accepted"->producer(folder,d,true);case "any-trusted-signer-accepted"->producer(folder,d,false);
    }
    var value=observe(dir,d,true);require(value.outcome()==(name.equals("any-trusted-signer-accepted")?Outcome.VIOLATED:Outcome.NOT_VERIFIED),"control failed "+name+": "+value);checks.put(name,Map.of("outcome",value.outcome(),"reasonCode",value.reasonCode(),"centralVerdict",Evaluator.toVerdict(Rfc2119Level.SHOULD,value),"purpose","oracle-calibration-only-not-original-product-output"));
   }
   Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("production_outcome",outcome,"checks",checks,"shared_native_lifecycle",true,"privateMaterialExported",false,"additionalProductOperations",0,"calibrationPurpose","oracle-detection-only-no-native-product-sends","calibrationKeys","ephemeral-in-memory-only")));
  }finally{try(var paths=Files.walk(temp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
 }
}
