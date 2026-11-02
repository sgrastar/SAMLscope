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
import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Element;

/** Standalone offline tests with ephemeral in-memory signing credentials. */
public final class SspMetadataEntityIdentityOfflineTest {
    private static final ObjectMapper JSON=new JsonCodec().mapper();
    private static final String RUN="run_00000000000000000000000001",SECOND="run_00000000000000000000000002";
    private static final String PLAN="plan_00000000000000000000000001",PLAN2="plan_00000000000000000000000002";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion",P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String TARGET=SimpleSamlPhpMetadataEntityIdentityEvidence.TARGET,SSO="http://localhost:18380/sso";
    private static final Instant START=Instant.parse("2026-11-02T00:00:00Z");
    private final Path root,folder,data;
    private final Map<String,List<TranscriptEntry>> entries=new HashMap<>();
    private final Map<String,byte[]> decoded=new HashMap<>();
    private final Map<String,byte[]> targets=new HashMap<>();
    private final Map<String,Object> refs=new LinkedHashMap<>();
    private ObjectNode manifest;
    private int tx=0,checks=0;
    private SspMetadataEntityIdentityOfflineTest(Path root)throws Exception {
        this.root=root;folder=Files.createDirectories(root.resolve("ssp-metadata-entity-identity-evidence").resolve(RUN));data=Files.createDirectories(root.resolve("data"));
        entries.put(RUN,new ArrayList<>());entries.put(SECOND,new ArrayList<>());
    }
    private void check(boolean b,String name){checks++;if(!b)throw new AssertionError(name);}
    private static String sha(byte[] b)throws Exception{return SimpleSamlPhpMetadataEntityIdentityEvidence.hash(b);}
    private static PlanCredentials key(int number)throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();
        var name=new X500Name("CN=offline-"+number);var builder=new JcaX509v3CertificateBuilder(name,BigInteger.valueOf(number),Date.from(START.minusSeconds(60)),Date.from(START.plusSeconds(3600)),name,pair.getPublic());
        var cert=new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
        return new PlanCredentials(pair.getPrivate(),cert);
    }
    private static String cert(PlanCredentials key)throws Exception{return Base64.getEncoder().encodeToString(key.certificate().getEncoded());}
    private static byte[] signed(String xml,PlanCredentials key)throws Exception {
        var doc=SecureXml.parse(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));new XmlSigner().sign(doc.getDocumentElement(),key,null);return SecureXml.serialize(doc);
    }
    private static byte[] metadata(String entity,String role,String acs,PlanCredentials key,String id)throws Exception {
        String service=role.equals("SPSSODescriptor")?"<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' index='0' Location='"+acs+"'/>":"<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' Location='"+SSO+"'/>";
        return signed("<md:EntityDescriptor xmlns:md='"+MD+"' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' ID='"+id+"' entityID='"+entity+"'><md:"+role+" protocolSupportEnumeration='"+P+"'><md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"+cert(key)+"</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"+service+"</md:"+role+"></md:EntityDescriptor>",key);
    }
    private static JsonNode project(String entity,String acs,PlanCredentials key)throws Exception {
        return JSON.valueToTree(Map.of("entityId",entity,"keys",List.of(sha(key.certificate().getEncoded())),"endpoints",List.of(acs)));
    }
    private void write(String name,byte[] bytes)throws Exception{var p=folder.resolve(name);Files.createDirectories(p.getParent());Files.write(p,bytes);}
    private void json(String name,Object value)throws Exception{write(name,JSON.writeValueAsBytes(value));}
    private TranscriptEntry tx(String run,int second,Direction dir,String method,String url,int status,String type,byte[] bytes,Map<String,Object> summary) {
        String id="tx_"+String.format("%026d",++tx);decoded.put(id,bytes);
        var e=new TranscriptEntry(id,run,dir,START.plusSeconds(second),null,method,url,status,Map.of(),null,0,
            "transcripts/"+run+"/"+id+".saml.xml",bytes.length,type,null,summary);entries.get(run).add(e);return e;
    }
    private void original(String name,int second,ObjectNode value)throws Exception {
        value.put("schema",SimpleSamlPhpMetadataEntityIdentityEvidence.ORIGINAL).put("kind",name).put("runId",RUN)
            .put("campaignId",SimpleSamlPhpMetadataEntityIdentityEvidence.CAMPAIGN).put("targetMetadataSha256",sha(targets.get(RUN)))
            .put("recordedAt",START.plusSeconds(second).toString());
        if(!name.equals("restoration")) value.put("observedStartedAt",START.plusSeconds(second).toString()).put("observedFinishedAt",START.plusSeconds(second).toString());
        byte[] bytes=JSON.writeValueAsBytes(value);write("native-originals/"+name+".json",bytes);
        var entry=tx(RUN,second+1,Direction.INBOUND,"POST","http://localhost:18080/p/"+PLAN+"/sp/paos?run="+RUN,204,"application/json",bytes,Map.of());
        refs.put(name,Map.of("reference",entry.id(),"sha256",sha(bytes)));
    }
    private Map<String,String> normal(String run,String plan,String acs,PlanCredentials peer,PlanCredentials idp,int second)throws Exception {
        String entity="http://localhost:18080/p/"+plan,id="_request"+second;
        byte[] rq=signed("<p:AuthnRequest xmlns:p='"+P+"' xmlns:s='"+S+"' ID='"+id+"' AssertionConsumerServiceURL='"+acs+"' Destination='"+SSO+"'><s:Issuer>"+entity+"</s:Issuer></p:AuthnRequest>",peer);
        var response=SecureXml.parse(("<p:Response xmlns:p='"+P+"' xmlns:s='"+S+"' ID='_response"+second+"' InResponseTo='"+id+"' Destination='"+acs+"'><s:Issuer>"+TARGET+"</s:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status><s:Assertion ID='_assertion"+second+"'><s:Issuer>"+TARGET+"</s:Issuer><s:Subject><s:NameID>offline-user</s:NameID><s:SubjectConfirmation><s:SubjectConfirmationData InResponseTo='"+id+"' Recipient='"+acs+"'/></s:SubjectConfirmation></s:Subject><s:Conditions><s:AudienceRestriction><s:Audience>"+entity+"</s:Audience></s:AudienceRestriction></s:Conditions><s:AuthnStatement/></s:Assertion></p:Response>").getBytes());
        new XmlSigner().sign((Element)response.getElementsByTagNameNS(S,"Assertion").item(0),idp,null);
        var request=tx(run,second,Direction.OUTBOUND,"POST",SSO,200,"text/xml",rq,Map.of("type","AuthnRequest","id",id));
        var reply=tx(run,second+1,Direction.INBOUND,"POST",acs,200,"text/xml",SecureXml.serialize(response),Map.of("type","Response","inResponseTo",id));
        return Map.of("requestReference",request.id(),"responseReference",reply.id());
    }
    private void fixture()throws Exception {
        var a=key(1);var b=key(2);var d=key(3);var idp=key(4);
        String entity="http://localhost:18080/p/"+PLAN,secondary="http://localhost:18080/p/"+PLAN2;
        String acs=entity+"/sp/acs",acs2=secondary+"/sp/acs",dupAcs=entity+"/sp/duplicate-acs";
        byte[] target=metadata(TARGET,"IDPSSODescriptor","",idp,"_target");targets.put(RUN,target);targets.put(SECOND,target);write("target-metadata.xml",target);
        Files.createDirectories(data.resolve("target-metadata"));Files.write(data.resolve("target-metadata/"+RUN+".xml"),target);Files.write(data.resolve("target-metadata/"+SECOND+".xml"),target);
        byte[] primary=metadata(entity,"SPSSODescriptor",acs,a,"_primary"),second=metadata(secondary,"SPSSODescriptor",acs2,b,"_secondary"),duplicate=metadata(entity,"SPSSODescriptor",dupAcs,d,"_duplicate");
        write("primary/fixture.xml",primary);write("secondary/fixture.xml",second);write("duplicate-fixture.xml",duplicate);
        var fetch=tx(RUN,1,Direction.INBOUND,"GET",entity+"/metadata/live",200,"application/xml",duplicate,Map.of("type","MetadataFetch"));
        tx(RUN,2,Direction.OUTBOUND,"GET",entity+"/metadata/live",200,"application/xml",duplicate,Map.of("type","MetadataPrepared","variant","multiple-signing-keys","fetchTranscriptId",fetch.id(),"metadataSha256",sha(duplicate)));
        var runtime=JSON.valueToTree(Map.of("running",true,"image","sha256:"+"1".repeat(64),"id","offline-container","startedAt",START.toString()));
        var sources=JSON.readTree("[{\"type\":\"flatfile\"},{\"type\":\"flatfile\",\"directory\":\"/tmp/samlscope-md05-"+RUN+"/a\"},{\"type\":\"flatfile\",\"directory\":\"/tmp/samlscope-md05-"+RUN+"/b\"}]");
        var hashes=new TreeMap<String,String>();for(String name:List.of("handler.php","source.php","flatfile.php","parser.php","configuration.php")){byte[] bytes=("offline-native-"+name).getBytes();write("native-runtime/"+name,bytes);hashes.put(name,sha(bytes));}
        var nativeState=JSON.createObjectNode().put("version","2.5.0").put("configurationSha256","2".repeat(64));
        nativeState.set("sources",sources);nativeState.set("sourceHashes",JSON.valueToTree(hashes));
        nativeState.set("sourceA",JSON.valueToTree(List.of(project(entity,acs,a),project(secondary,acs2,b))));
        nativeState.set("sourceB",JSON.valueToTree(List.of(project(entity,dupAcs,d))));
        nativeState.set("effective",nativeState.path("sourceA").deepCopy());
        var observation=JSON.createObjectNode().put("originalSha256","3".repeat(64));observation.set("native",nativeState);observation.set("runtime",runtime);
        original("before",3,observation.deepCopy());
        var normal1=normal(RUN,PLAN,acs,a,idp,5);var normal2=normal(SECOND,PLAN2,acs2,b,idp,7);
        original("after",9,observation.deepCopy());
        var restore=JSON.createObjectNode().put("restored",true).put("originalSha256","3".repeat(64)).put("finalSha256","3".repeat(64)).put("temporarySourcesRemoved",true).put("ownedPeersAbsent",true);
        restore.set("sources",JSON.readTree("[{\"type\":\"flatfile\"}]"));restore.set("runtime",runtime);original("restoration",11,restore);json("restoration.json",restore);
        var counts=new TreeMap<String,Object>();counts.put("configurationApplyWrites",1);counts.put("restorationWrites",1);counts.put("configurationWriteAttempts",2);counts.put("successfulHostWrites",2);counts.put("nativeApplications",1);counts.put("fixtureFileWrites",2);counts.put("fixtureRemovalOperations",1);counts.put("normalFlowsAttempted",2);counts.put("protocolSubmissions",2);counts.put("nativeParserInvocations",3);counts.put("humanOperations",0);counts.put("productRestarts",0);counts.put("restored",true);counts.put("nativeCommandAttempts",1);json("operation-counts.json",counts);
        json("native-commands.json",List.of(Map.of("arguments",List.of("cat","public-fixture"),"exitCode",0,"startedAt",START.toString(),"finishedAt",START.toString())));
        var peers=List.of(Map.of("label","primary","runId",RUN,"planId",PLAN,"entity",entity,"normal",normal1),Map.of("label","secondary","runId",SECOND,"planId",PLAN2,"entity",secondary,"normal",normal2));
        for(var peer:peers) {
            String label=(String)peer.get("label"),run=(String)peer.get("runId"),plan=(String)peer.get("planId");
            json(label+"/created.json",Map.of("run",Map.of("id",run,"planId",plan)));json(label+"/plan.json",Map.of("plan",Map.of("plan",Map.of("id",plan,"profile","metadata_idp"))));json(label+"/case-inventory.json",SimpleSamlPhpMetadataEntityIdentityEvidence.CASES);write(label+"/target-metadata.xml",target);
            json(label+"/transcript.json",entries.get(run));var index=new ArrayList<Object>();
            for(var e:entries.get(run)){String name="decoded/"+e.id()+".xml";write(label+"/"+name,decoded.get(e.id()));index.add(Map.of("id",e.id(),"file",name,"sha256",sha(decoded.get(e.id()))));}json(label+"/decoded-manifest.json",index);
        }
        manifest=JSON.createObjectNode().put("schema",SimpleSamlPhpMetadataEntityIdentityEvidence.SCHEMA).put("adapter",SimpleSamlPhpMetadataEntityIdentityEvidence.ADAPTER)
            .put("campaignId",SimpleSamlPhpMetadataEntityIdentityEvidence.CAMPAIGN).put("profile","metadata_idp").put("runId",RUN).put("planId",PLAN).put("targetEntityId",TARGET).put("targetMetadataSha256",sha(target)).put("operation","simultaneous-sources");
        manifest.set("caseDigests",JSON.valueToTree(SimpleSamlPhpMetadataEntityIdentityEvidence.CASES));manifest.set("peers",JSON.valueToTree(peers));manifest.set("originals",JSON.valueToTree(refs));manifest.set("sources",sources);manifest.set("sourceHashes",JSON.valueToTree(hashes));rehash();
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.createStatement()) {
            q.execute("CREATE TABLE plans(id TEXT,document_json TEXT)");q.execute("CREATE TABLE runs(id TEXT,plan_id TEXT)");q.execute("CREATE TABLE outbox_actions(run_id TEXT,case_id TEXT)");q.execute("CREATE TABLE transcript_entries(run_id TEXT,id TEXT,timestamp TEXT,document_json TEXT)");q.execute("CREATE TABLE case_executions(run_id TEXT,case_id TEXT,revision INTEGER,document_json TEXT)");
            try(var insert=c.prepareStatement("INSERT INTO transcript_entries VALUES(?,?,?,?)")) {
                for(var list:entries.values())for(var entry:list) {
                    insert.setString(1,entry.runId());insert.setString(2,entry.id());insert.setString(3,entry.timestamp().toString());insert.setString(4,JSON.writeValueAsString(entry));insert.executeUpdate();
                    var original=data.resolve("transcripts/"+entry.runId()+"/"+entry.id()+".saml.xml");Files.createDirectories(original.getParent());Files.write(original,decoded.get(entry.id()));
                }
            }
            for(var peer:peers){String run=(String)peer.get("runId"),plan=(String)peer.get("planId");q.execute("INSERT INTO plans VALUES('"+plan+"','{\"profile\":\"metadata_idp\",\"target\":{\"kind\":\"IDP\",\"entityId\":\"http://localhost:18380/idp\"}}')");q.execute("INSERT INTO runs VALUES('"+run+"','"+plan+"')");for(var id:SimpleSamlPhpMetadataEntityIdentityEvidence.CASES.keySet())q.execute("INSERT INTO case_executions(run_id,case_id) VALUES('"+run+"','"+id+"')");}
        }
    }
    private void rehash()throws Exception{var files=new TreeMap<String,String>();try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList())if(!p.equals(folder.resolve("manifest.json")))files.put(folder.relativize(p).toString(),sha(Files.readAllBytes(p)));}manifest.set("files",JSON.valueToTree(files));json("manifest.json",manifest);}
    private CaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String run){return entries.getOrDefault(run,List.of());}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("no sending");}public TranscriptEntry updateSamlAnalysis(String r,String i,Map<String,Object> s){throw new AssertionError("no updates");}},complete);}
    private SimpleSamlPhpMetadataEntityIdentityEvidence reader(){return new SimpleSamlPhpMetadataEntityIdentityEvidence(folder.getParent(),e->decoded.get(e.id()),targets::get,r->Optional.empty());}
    private CaseOutcome outcome(){return reader().evaluate(context(true),"IIP-MD05-a1-idp-01").orElseThrow();}
    private void run()throws Exception {
        check(reader().evaluate(context(true),"unrelated").isEmpty(),"unrelated case");check(!reader().exists("../"+RUN)&&!reader().exists(null),"safe ownership");
        fixture();var baseline=outcome();check(baseline.outcome()==Outcome.NOT_VERIFIED&&"duplicate-conflict-unqualified".equals(baseline.notVerifiedReason()),"complete source-shadow receipt reaches qualification boundary: "+baseline);
        check(reader().evaluate(context(false),"IIP-MD05-a1-idp-01").orElseThrow().outcome()==Outcome.NOT_VERIFIED,"incomplete history");
        byte[] original=Files.readAllBytes(folder.resolve("duplicate-fixture.xml"));Files.writeString(folder.resolve("duplicate-fixture.xml"),"tamper");check(outcome().outcome()==Outcome.NOT_VERIFIED,"tampered fixture");Files.write(folder.resolve("duplicate-fixture.xml"),original);
        var saved=manifest.deepCopy();manifest.put("operation","explicit-replacement");json("manifest.json",manifest);check(outcome().outcome()==Outcome.NOT_VERIFIED,"replacement is not simultaneous");manifest=saved;json("manifest.json",manifest);
        var replay=root.resolve("replay.json");VerifySspMetadataEntityIdentityEvidence.main(new String[]{folder.toString(),data.toString(),replay.toString()});var replayNode=JSON.readTree(Files.readAllBytes(replay));
        check(replayNode.path("checks").size()==15,"all actual reader calibrations executed");
        for(var check:replayNode.path("checks"))for(var row:check)check(row.path("outcome").isTextual(),"calibration has outcome");
        var sourceEntry=entries.get(SECOND).getFirst();
        var actualOriginal=data.resolve("transcripts/"+SECOND+"/"+sourceEntry.id()+".saml.xml");var actualBytes=Files.readAllBytes(actualOriginal);
        Files.writeString(actualOriginal,"foreign original");boolean rejected=false;
        try{VerifySspMetadataEntityIdentityEvidence.main(new String[]{folder.toString(),data.toString(),root.resolve("foreign-original-replay.json").toString()});}catch(Exception expected){rejected=true;}
        check(rejected,"actual source Run original must match the receipt");Files.write(actualOriginal,actualBytes);
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.prepareStatement("UPDATE transcript_entries SET document_json=? WHERE run_id=? AND id=?")) {
            q.setString(1,JSON.writeValueAsString(entries.get(RUN).getFirst()));q.setString(2,SECOND);q.setString(3,sourceEntry.id());q.executeUpdate();
        }
        rejected=false;try{VerifySspMetadataEntityIdentityEvidence.main(new String[]{folder.toString(),data.toString(),root.resolve("foreign-history-replay.json").toString()});}catch(Exception expected){rejected=true;}
        check(rejected,"actual source Run history cannot be relabeled");
        storedRoundTrip(baseline);
        var fallback=new VerifyFallback("IIP-MD05-a1-idp-01");var wrapper=new SimpleSamlPhpMetadataEntityIdentityConfigurationTestCase(fallback,folder.getParent(),e->decoded.get(e.id()),targets::get,r->Optional.empty());
        check(((CaseStep.Finish)wrapper.resume(context(true),CaseState.initial(),new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"unavailable"))).outcome().outcome()==Outcome.NOT_VERIFIED,"owned unavailable never escapes");
        var conflict=Files.createDirectories(root.resolve("keycloak-metadata-entity-identity-evidence").resolve(RUN));check(((CaseStep.Finish)wrapper.start(context(true))).outcome().outcome()==Outcome.NOT_VERIFIED,"conflicting owners");Files.delete(conflict);
        var execution=new CaseExecution(RUN,fallback.id(),1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,baseline,START);
        check(wrapper.evidenceClass(execution)==RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED&&!wrapper.resolvedFromExternalEvidence(execution),"recorded pending provenance");
        var mutant=JSON.treeToValue(replayNode.path("checks").path("mut-iip-md05-a1-idp").path(fallback.id()),CaseOutcome.class);
        check(wrapper.resolvedFromExternalEvidence(new CaseExecution(RUN,fallback.id(),1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,mutant,START)),"recorded merged provenance");
        check(!wrapper.supportsRecordedEvidenceReevaluation(CaseOutcome.of(Outcome.SATISFIED,"old",List.of())),"do not rewrite conclusive outcomes");
        var absent=new SimpleSamlPhpMetadataEntityIdentityConfigurationTestCase(fallback,root.resolve("absent"),e->null,r->null,r->Optional.empty());check(((CaseStep.Finish)absent.start(context(true))).outcome().outcome()==Outcome.SATISFIED,"absent retains legacy path");
        System.out.println("Java offline checks passed: "+checks+"; actual replay: 15 controls x 2 cases");
    }
    private void storedRoundTrip(CaseOutcome baseline)throws Exception {
        String id="IIP-MD05-a1-idp-01";
        var execution=new CaseExecution(RUN,id,1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,baseline,START);
        try(var c=DriverManager.getConnection("jdbc:sqlite:"+data.resolve("samlscope.db"));var q=c.prepareStatement("UPDATE case_executions SET revision=1,document_json=? WHERE run_id=? AND case_id=?")) {
            q.setString(1,JSON.writeValueAsString(execution));q.setString(2,RUN);q.setString(3,id);q.executeUpdate();
        }
        var saved=System.out;var buffer=new java.io.ByteArrayOutputStream();
        try {System.setOut(new java.io.PrintStream(buffer));ReadSspMetadataEntityIdentityStoredConclusions.main(new String[]{"capture",data.toString(),RUN,id});}finally{System.setOut(saved);}
        byte[] bytes=buffer.toByteArray();var path=root.resolve("stored.json");Files.write(path,bytes);var value=JSON.readTree(bytes);
        check(value.path("cases").path(id).path("outboxCount").asInt(-1)==0,"stored capture is read-only");
        buffer.reset();try {System.setOut(new java.io.PrintStream(buffer));ReadSspMetadataEntityIdentityStoredConclusions.main(new String[]{"offline",path.toString()});}finally{System.setOut(saved);}
        check(value.equals(JSON.readTree(buffer.toByteArray())),"archived central Evaluator stored round trip");
    }
    private record VerifyFallback(String id) implements TestCase,ConfigurationPrompt,ProtocolEvidenceCase,EvidenceCampaignCase,RecordedEvidenceReevaluation {
        public TargetRole role(){return TargetRole.IDP;}public String instructionEn(){return "Fallback";}public String evidenceCampaignId(){return "metadata";}public String evidenceCampaignTitle(){return "Metadata";}public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.CONFIGURATION;}public List<String>evidenceActionKeys(){return List.of();}public CaseStep start(CaseContext c){return new CaseStep.Finish(CaseOutcome.of(Outcome.SATISFIED,"legacy",List.of()));}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return start(c);}public EvidenceStatus evidenceStatus(CaseContext c){return new EvidenceStatus(false,List.of(),List.of(),Map.of());}public boolean supportsRecordedEvidenceReevaluation(CaseOutcome p){return true;}public Optional<CaseOutcome>reevaluateRecordedEvidence(CaseContext c,CaseOutcome p){return Optional.empty();}
    }
    public static void main(String[] args)throws Exception {
        var root=Files.createTempDirectory("ssp-md05-tests-").toRealPath();try{new SspMetadataEntityIdentityOfflineTest(root).run();}finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
