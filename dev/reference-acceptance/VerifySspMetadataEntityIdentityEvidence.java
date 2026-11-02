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
import java.sql.DriverManager;
import java.time.*;
import java.util.*;

/** Replay the archived production reader without a sender, product action, or private key. */
public final class VerifySspMetadataEntityIdentityEvidence {
    private static final ObjectMapper JSON=new JsonCodec().mapper();
    static final List<String> CHECKS=List.of("wrong-run","wrong-adapter","wrong-target","wrong-campaign","unknown-secondary",
        "duplicate-history","foreign-history","foreign-decoded-ref","missing-normal","tampered-file","missing-restoration",
        "explicit-replacement-not-simultaneous","positive-control-failed","mut-iip-md05-a1-idp","mut-iip-md05-a2-idp");
    private record Data(ObjectNode manifest,String run,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> decoded,Map<String,byte[]> targets) {}
    private static void require(boolean yes,String message) {if(!yes)throw new IllegalArgumentException(message);}
    private static String hash(byte[] raw)throws Exception{return SimpleSamlPhpMetadataEntityIdentityEvidence.hash(raw);}
    private static byte[] safe(Path root,String name)throws Exception {
        var p=root.resolve(name).normalize();require(p.startsWith(root)&&!p.equals(root),"escaped receipt");
        for(var at=p;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at),"symbolic receipt");
        require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS),"missing receipt original");return Files.readAllBytes(p);
    }
    private static Data load(Path folder,Path data)throws Exception {
        var m=(ObjectNode)SimpleSamlPhpMetadataEntityIdentityEvidence.json(safe(folder,"manifest.json"));
        var entries=new HashMap<String,List<TranscriptEntry>>();var decoded=new HashMap<String,byte[]>();var targets=new HashMap<String,byte[]>();
        String run=m.path("runId").asText(); require(SimpleSamlPhpMetadataEntityIdentityEvidence.validRun(run),"unsafe Run");
        for(var peer:m.path("peers")) {
            String label=peer.path("label").asText(),r=peer.path("runId").asText(),plan=peer.path("planId").asText();
            require(Set.of("primary","secondary").contains(label)&&SimpleSamlPhpMetadataEntityIdentityEvidence.validRun(r),"unknown peer");
            require(entries.put(r,new ArrayList<>(List.of(JSON.readValue(safe(folder,label+"/transcript.json"),TranscriptEntry[].class))))==null,"duplicate peer Run");
            var target=safe(data,"target-metadata/"+r+".xml");require(Arrays.equals(target,safe(folder,label+"/target-metadata.xml")),"source Run target differs");targets.put(r,target);
            try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
                var q=c.prepareStatement("SELECT r.plan_id,p.document_json FROM runs r JOIN plans p ON p.id=r.plan_id WHERE r.id=?")) {
                q.setString(1,r);try(var rows=q.executeQuery()) {
                    require(rows.next()&&plan.equals(rows.getString(1)),"unknown peer Run/Plan");
                    var saved=JSON.readTree(rows.getString(2));require("metadata_idp".equals(saved.path("profile").asText())
                        &&SimpleSamlPhpMetadataEntityIdentityEvidence.TARGET.equals(saved.at("/target/entityId").asText())
                        &&"IDP".equals(saved.at("/target/kind").asText())&&!rows.next(),"wrong Run profile or target");
                }
                var actualHistory=new ArrayList<TranscriptEntry>();
                try(var original=c.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")) {
                    original.setString(1,r);try(var rows=original.executeQuery()){while(rows.next())actualHistory.add(JSON.readValue(rows.getString(1),TranscriptEntry.class));}
                }
                require(actualHistory.equals(entries.get(r)),"archived history is not the actual source Run history");
                try(var selected=c.prepareStatement("SELECT COUNT(*) FROM case_executions WHERE run_id=? AND case_id=?")) {
                    for(String id:SimpleSamlPhpMetadataEntityIdentityEvidence.CASES.keySet()) {selected.setString(1,r);selected.setString(2,id);try(var row=selected.executeQuery()){require(row.next()&&row.getInt(1)==1,"approved case absent from saved Run");}}
                }
            }
            var ids=new HashSet<String>();
            for(var original:JSON.readTree(safe(folder,label+"/decoded-manifest.json"))) {
                String id=original.path("id").asText();require(ids.add(id)&&id.matches("tx_[0-9A-HJKMNP-TV-Z]{26}"),"duplicate decoded original");
                String name=original.path("file").asText();require(name.equals("decoded/"+id+".xml"),"foreign decoded original");
                byte[] bytes=safe(folder,label+"/"+name);
                require(Arrays.equals(bytes,safe(data,"transcripts/"+r+"/"+id+".saml.xml")),"source Run original bytes differ");
                require(hash(bytes).equals(original.path("sha256").asText())&&decoded.put(id,bytes)==null,"decoded original changed");
            }
        }
        return new Data(m,run,entries,decoded,targets);
    }
    private static CaseContext context(Data d) {
        var recorder=new TranscriptRecorder(){
            public List<TranscriptEntry>list(String r){return d.entries.getOrDefault(r,List.of());}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("replay cannot send");}
            public TranscriptEntry updateSamlAnalysis(String r,String id,Map<String,Object> values){throw new AssertionError("replay cannot edit history");}
        };
        return new DefaultCaseContext(d.run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
    }
    private record Fallback(String id) implements TestCase,ConfigurationPrompt,ProtocolEvidenceCase,EvidenceCampaignCase,RecordedEvidenceReevaluation {
        public TargetRole role(){return TargetRole.IDP;}public String instructionEn(){return "Approved fixture fallback";}
        public String evidenceCampaignId(){return "metadata-consumer";}public String evidenceCampaignTitle(){return "Metadata consumer";}
        public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.CONFIGURATION;}
        public List<String>evidenceActionKeys(){return List.of();}
        public CaseStep start(CaseContext c){throw new AssertionError("owned receipt escaped");}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("owned receipt escaped");}
        public EvidenceStatus evidenceStatus(CaseContext c){throw new AssertionError("owned receipt escaped");}
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return true;}
        public Optional<CaseOutcome>reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){throw new AssertionError("owned receipt escaped");}
    }
    private static Map<String,CaseOutcome> observe(Path directory,Data d)throws Exception {
        var folder=directory.resolve(d.run);
        if(!JSON.readTree(Files.readAllBytes(folder.resolve("manifest.json"))).equals(d.manifest)) Files.write(folder.resolve("manifest.json"),JSON.writeValueAsBytes(d.manifest));
        var c=context(d);var reader=new SimpleSamlPhpMetadataEntityIdentityEvidence(directory,e->d.decoded.get(e.id()),d.targets::get,r->Optional.empty());
        var result=new TreeMap<String,CaseOutcome>();
        for(var id:SimpleSamlPhpMetadataEntityIdentityEvidence.CASES.keySet()) {
            var value=reader.evaluate(c,id).orElseThrow();result.put(id,value);
            var wrapper=new SimpleSamlPhpMetadataEntityIdentityConfigurationTestCase(new Fallback(id),directory,e->d.decoded.get(e.id()),d.targets::get,r->Optional.empty());
            require(new CaseStep.Finish(value).equals(wrapper.start(c)),"wrapper start differs");
            require(new CaseStep.Finish(value).equals(wrapper.resume(c,CaseState.initial(),new CaseEvent.TranscriptReady())),"wrapper resume differs");
            require(wrapper.evidenceStatus(c).ready()==(value.outcome()!=Outcome.NOT_VERIFIED),"wrapper readiness differs");
        }
        return result;
    }
    private static TranscriptEntry copy(TranscriptEntry e,String run,String ref,int length) {
        return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),ref,length,e.contentType(),e.rawQuery(),e.samlSummary());
    }
    private static void editOriginal(Path folder,Data d,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception {
        String path="native-originals/"+name+".json";var node=(ObjectNode)JSON.readTree(safe(folder,path));edit.accept(node);var bytes=JSON.writeValueAsBytes(node);
        Files.write(folder.resolve(path),bytes);((ObjectNode)d.manifest.path("files")).put(path,hash(bytes));
        var ref=(ObjectNode)d.manifest.path("originals").path(name);ref.put("sha256",hash(bytes));String id=ref.path("reference").asText();d.decoded.put(id,bytes);
        d.entries.get(d.run).replaceAll(e->id.equals(e.id())?copy(e,e.runId(),e.decodedSamlRef(),bytes.length):e);
    }
    public static void main(String[] args)throws Exception {
        require(args.length==3,"receipt data output required");Path source=Path.of(args[0]).toAbsolutePath().normalize(),data=Path.of(args[1]).toAbsolutePath().normalize(),output=Path.of(args[2]);
        require(!Files.exists(output),"immutable replay output");var temp=Files.createTempDirectory("ssp-entity-replay-").toRealPath();
        try {
            String run=JSON.readTree(safe(source,"manifest.json")).path("runId").asText();require(SimpleSamlPhpMetadataEntityIdentityEvidence.validRun(run),"invalid Run");
            var directory=temp.resolve("ssp-metadata-entity-identity-evidence");var folder=directory.resolve(run);Files.createDirectories(folder);
            var originals=new TreeMap<String,byte[]>();try(var paths=Files.walk(source)){for(var p:paths.filter(Files::isRegularFile).toList())originals.put(source.relativize(p).toString(),safe(source,source.relativize(p).toString()));}
            for(var e:originals.entrySet()){var p=folder.resolve(e.getKey());Files.createDirectories(p.getParent());Files.write(p,e.getValue());}
            var baseline=observe(directory,load(folder,data));
            for(var value:baseline.values())require(value.outcome()==Outcome.VIOLATED||value.outcome()==Outcome.NOT_VERIFIED&&"duplicate-conflict-unqualified".equals(value.notVerifiedReason()),"baseline prerequisites unproven: "+value);
            var checks=new TreeMap<String,Object>();
            for(var name:CHECKS) {
                for(var e:originals.entrySet())Files.write(folder.resolve(e.getKey()),e.getValue());var d=load(folder,data);
                var secondary=d.manifest.path("peers").get(1).path("runId").asText();
                switch(name) {
                    case "wrong-run"->d.manifest.put("runId","run_00000000000000000000000000");
                    case "wrong-adapter"->d.manifest.put("adapter","foreign");
                    case "wrong-target"->d.manifest.put("targetMetadataSha256","0".repeat(64));
                    case "wrong-campaign"->d.manifest.put("campaignId","foreign");
                    case "unknown-secondary"->((ObjectNode)d.manifest.path("peers").get(1)).put("runId","run_00000000000000000000000000");
                    case "duplicate-history"->d.entries.get(secondary).add(d.entries.get(secondary).getFirst());
                    case "foreign-history","foreign-decoded-ref"->{var rows=d.entries.get(secondary);var e=rows.getFirst();rows.set(0,copy(e,name.equals("foreign-history")?d.run:e.runId(),name.equals("foreign-decoded-ref")?"transcripts/"+d.run+"/"+e.id()+".saml.xml":e.decodedSamlRef(),e.decodedSamlBytes()));}
                    case "missing-normal"->d.decoded.remove(d.manifest.path("peers").get(1).path("normal").path("responseReference").asText());
                    case "tampered-file"->Files.writeString(folder.resolve("duplicate-fixture.xml"),"tampered");
                    case "missing-restoration"->editOriginal(folder,d,"restoration",n->n.put("restored",false));
                    case "explicit-replacement-not-simultaneous"->d.manifest.put("operation","explicit-replacement");
                    case "positive-control-failed"->editOriginal(folder,d,"before",n->((ArrayNode)n.at("/native/sourceA")).remove(1));
                    case "mut-iip-md05-a1-idp","mut-iip-md05-a2-idp"->{
                        for(String phase:List.of("before","after"))editOriginal(folder,d,phase,n->{
                            var a=n.at("/native/sourceA/0");var b=n.at("/native/sourceB/0");var merged=(ObjectNode)a.deepCopy();
                            for(String field:List.of("keys","endpoints")){var values=new TreeSet<String>();a.path(field).forEach(v->values.add(v.asText()));b.path(field).forEach(v->values.add(v.asText()));merged.set(field,JSON.valueToTree(values));}
                            ((ArrayNode)n.at("/native/effective")).set(0,merged);
                        });
                    }
                }
                var values=observe(directory,d);for(var value:values.values())require(value.outcome()==(name.startsWith("mut-")?Outcome.VIOLATED:Outcome.NOT_VERIFIED),"calibration missed: "+name+" "+value);checks.put(name,values);
            }
            JSON.writerWithDefaultPrettyPrinter().writeValue(output.toFile(),Map.of("runId",run,"production_outcomes",baseline,"checks",checks,
                "shared_native_lifecycle",true,"privateMaterialExported",false,"additionalProductOperations",0,"calibrationOnly",true));
        } finally {try(var paths=Files.walk(temp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
