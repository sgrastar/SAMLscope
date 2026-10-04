package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataPublisherKeyInventoryEvidence.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Replay only. Source/native detector changes are confined to a temporary tree. */
public final class VerifyNativePublisherUsedSignersEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final Map<String,List<TranscriptEntry>> SOURCES=new HashMap<>();
    private static final Map<String,byte[]> TARGET_OVERRIDES=new HashMap<>();
    private static void check(boolean b,String message){if(!b)throw new IllegalArgumentException(message);}
    private static CaseContext context(String run,List<TranscriptEntry> history,Map<String,byte[]> data,boolean complete){
        var normalized=history.stream().map(e->{byte[] raw=data.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:
            new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){if(run.equals(r))return normalized;var other=SOURCES.get(r);check(other!=null,"Unknown source Run");return other;}
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>v){throw new UnsupportedOperationException();}};
        return new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
    }
    private static void copy(Path src,Path dst)throws Exception{
        try(var walk=Files.walk(src)){for(var p:walk.toList()){check(!Files.isSymbolicLink(p),"Symlink");var d=dst.resolve(src.relativize(p));if(Files.isDirectory(p))Files.createDirectories(d);else Files.copy(p,d,StandardCopyOption.REPLACE_EXISTING);}}
    }
    private static ObjectNode original(ObjectNode m,Map<String,byte[]> d,String label)throws Exception{return (ObjectNode)JSON.mapper().readTree(d.get(m.path("originals").path(label).path("reference").asText()));}
    private static void replace(Path folder,ObjectNode m,Map<String,byte[]>d,String label,ObjectNode n)throws Exception{
        byte[] raw=JSON.mapper().writeValueAsBytes(n);var ref=(ObjectNode)m.path("originals").path(label);String file=ref.path("file").asText();
        Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));ref.put("sha256",hash(raw));d.put(ref.path("reference").asText(),raw);
    }
    private static CaseOutcome observe(Path directory,String id,String run,List<TranscriptEntry>h,Map<String,byte[]>d,byte[]target,boolean offline,boolean complete){
        return new MetadataPublisherKeyInventoryEvidence(directory,e->d.get(e.id()),r->TARGET_OVERRIDES.containsKey(r)?TARGET_OVERRIDES.get(r):run.equals(r)||SOURCES.containsKey(r)?target:null,offline).evaluate(id,context(run,h,d,complete));
    }
    private static final class Fallback implements TestCase,ConfigurationPrompt,AttestationPrompt{
        private final String id;Fallback(String id){this.id=id;}public String id(){return id;}public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Prepare publisher evidence";}public String promptEn(){return "Review original inventory";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){return new CaseStep.AwaitConfig(new CaseState("publisher",Map.of()),List.of(),"publisher.prepare",Duration.ofDays(1));}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return e instanceof CaseEvent.ConfigUnavailable?
            new CaseStep.Finish(CaseOutcome.notVerified("unavailable","configuration.test-precondition")):start(c);}
    }
    public static void main(String[] args)throws Exception{
        check(args.length==2,"campaign output required");Path source=Path.of(args[0]).toAbsolutePath().normalize(),report=Path.of(args[1]);check(!Files.exists(report),"Immutable report exists");
        var stock=(ObjectNode)JSON.mapper().readTree(source.resolve("receipt/manifest.json").toFile());String run=text(stock,"runId");
        check(validRun(run),"Invalid Run");var history=new ArrayList<>(List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class)));
        var by=new HashMap<String,TranscriptEntry>();for(var e:history)check(run.equals(e.runId())&&by.put(e.id(),e)==null,"Foreign/duplicate history");
        var decoded=new HashMap<String,byte[]>();for(var row:JSON.mapper().readTree(source.resolve("decoded-manifest.json").toFile())){
            String id=row.path("id").asText();Path p=source.resolve(row.path("file").asText()).normalize();check(p.getParent().equals(source.resolve("decoded")),"Foreign content");byte[]raw=Files.readAllBytes(p);
            check(by.containsKey(id)&&raw.length==by.get(id).decodedSamlBytes()&&hash(raw).equals(row.path("sha256").asText()),"Decoded original changed");decoded.put(id,raw);
        }
        for(var peer:stock.path("usedSigningPeers")) {
            String sourceRun=text(peer,"runId");if(run.equals(sourceRun))continue;
            Path dir=source.resolve("receipt").resolve(text(peer,"createdFile")).getParent();
            var sourceHistory=List.of(JSON.mapper().readValue(dir.resolve("transcript.json").toFile(),TranscriptEntry[].class));
            check(SOURCES.put(sourceRun,sourceHistory)==null,"Duplicate source Run");
            var ids=new HashSet<String>();for(var e:sourceHistory)check(sourceRun.equals(e.runId())&&ids.add(e.id()),"Foreign source history");
            for(var row:JSON.mapper().readTree(dir.resolve("decoded-manifest.json").toFile())) {
                String id=text(row,"id");Path p=dir.resolve(text(row,"file")).normalize();check(p.getParent().equals(dir.resolve("decoded")),"Foreign source content");
                var entry=sourceHistory.stream().filter(e->e.id().equals(id)).findFirst().orElseThrow();byte[]raw=Files.readAllBytes(p);
                check(raw.length==entry.decodedSamlBytes()&&hash(raw).equals(text(row,"sha256"))&&decoded.put(id,raw)==null,"Source decoded original changed");
            }
        }
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path tmp=Files.createTempDirectory("publisher-replay-").toRealPath(),directory=tmp.resolve("metadata-publisher-key-evidence"),folder=directory.resolve(run);Files.createDirectories(folder);
        try{
            copy(source.resolve("receipt"),folder);
            var pins=JSON.mapper().readTree(source.resolve("runtime-actual/pins.json").toFile());var codeSources=new TreeMap<String,String>();
            for(var type:List.of(MetadataPublisherKeyInventoryEvidence.class,SimpleSamlPhpPublisherInventoryAdapter.class,NativeMetadataPublisherInventoryAdapter.class,MetadataPublisherKeyInventoryConfigurationTestCase.class)) {
                Path code=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
                check(Files.isRegularFile(code)&&hash(Files.readAllBytes(code)).equals(pins.path("runner").asText()),"Class not from pinned archived Runner");codeSources.put(type.getName(),hash(Files.readAllBytes(code)));
            }
            var c1=observe(directory,C1,run,history,decoded,target,false,true);var c3=observe(directory,C3,run,history,decoded,target,false,true);
            check(c1.outcome()==Outcome.VIOLATED&&c3.outcome()==Outcome.VIOLATED,"Stock completeness differs: "+c1+" / "+c3);
            check(c1.evidence().stream().filter(e->e.kind().equals("transcript")).allMatch(e->by.containsKey(e.reference())&&run.equals(by.get(e.reference()).runId())),"Unresolvable transcript reference");
            var checks=new TreeMap<String,String>();
            var sourceHistories=new HashMap<>(SOURCES);
            for(String name:List.of("wrong-run","wrong-plan","wrong-target","wrong-adapter","wrong-campaign","wrong-entity","duplicate-history","foreign-history","foreign-decoded-reference","missing-original","missing-publication","publication-bytes-replaced","native-source-replaced","projection-source-replaced","configuration-epoch-unbound","configuration-restore-mismatch","native-runtime-replaced","native-window-reversed","native-publication-unbound","missing-control-id","duplicate-control-id","swapped-control-id","foreign-case-control-id","control-input-replaced","control-invocation-unbound","control-runtime-unbound","native-readback-credential","incomplete-history","calibration-label-only","missing-signing-peer","foreign-signing-run","duplicate-signing-run","wrong-signing-plan","wrong-signing-request","wrong-signing-response","missing-source-history","foreign-source-history","source-target-mismatch","signer-certificate-replaced","native-signer-use-unbound","material-not-removed")){
                copy(source.resolve("receipt"),folder);var m=stock.deepCopy();var d=new HashMap<>(decoded);var h=new ArrayList<>(history);String before="signers-before";
                switch(name){
                    case "wrong-run"->m.put("runId","run_00000000000000000000000000");case "wrong-plan"->m.put("planId","plan_00000000000000000000000000");
                    case "wrong-target"->m.put("targetMetadataSha256","0".repeat(64));case "wrong-adapter"->m.put("adapter","unqualified");case "wrong-campaign"->m.put("campaignId","unrelated");case "wrong-entity"->m.put("entityId","http://other/idp");
                    case "duplicate-history"->h.add(h.getFirst());case "foreign-history"->{var e=h.getFirst();h.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
                    case "foreign-decoded-reference"->{int i=0;while(h.get(i).decodedSamlRef()==null)i++;var e=h.get(i);h.set(i,new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml",e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
                    case "missing-original"->d.remove(m.path("originals").path(before).path("reference").asText());
                    case "missing-publication","publication-bytes-replaced"->{var f=m.path("epochs").get(0).path("publicationFile").asText();if(name.equals("missing-publication"))Files.delete(folder.resolve(f));else{byte[]b=Files.readAllBytes(folder.resolve(f));b[b.length-10]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}}
                    case "native-source-replaced","projection-source-replaced"->{String f=name.equals("native-source-replaced")?"native-source/native-builder.php":"native-public-readback.php";byte[]b=Files.readAllBytes(folder.resolve(f));b[20]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}
                    case "configuration-epoch-unbound"->{var v=original(m,d,"signers-transition");v.put("afterConfigurationSha256","0".repeat(64));replace(folder,m,d,"signers-transition",v);}
                    case "configuration-restore-mismatch"->{var v=original(m,d,"restoration");((ObjectNode)v.path("configurationHashes").get(0)).put("finalSha256","0".repeat(64));replace(folder,m,d,"restoration",v);}
                    case "native-runtime-replaced"->{var v=original(m,d,before);((ObjectNode)v.path("runtime")).put("startedAt","2020-01-01T00:00:00Z");replace(folder,m,d,before,v);}
                    case "native-window-reversed"->{var v=original(m,d,before);v.put("nativeStartedAt",v.path("nativeFinishedAt").asText());replace(folder,m,d,before,v);}
                    case "native-publication-unbound"->{var v=original(m,d,"signers-publication");v.put("epochId","other");replace(folder,m,d,"signers-publication",v);}
                    case "missing-control-id","duplicate-control-id","swapped-control-id","foreign-case-control-id"->{var v=original(m,d,"controls");var a=(ArrayNode)v.path("negativeControlIds");switch(name){case "missing-control-id"->a.remove(1);case "duplicate-control-id"->a.set(1,a.get(0));case "swapped-control-id"->{var x=a.get(0);a.set(0,a.get(1));a.set(1,x);}default->a.set(1,JSON.mapper().getNodeFactory().textNode("iip-md05-c5-idp-01-negative"));}replace(folder,m,d,"controls",v);}
                    case "control-input-replaced"->{var f=m.path("controls").path("inputFile").asText();byte[]b=Files.readAllBytes(folder.resolve(f));b[30]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}
                    case "control-invocation-unbound","control-runtime-unbound"->{String f=m.path("controls").path("invocationsFile").asText();var v=(ArrayNode)JSON.mapper().readTree(folder.resolve(f).toFile());if(name.equals("control-runtime-unbound"))((ObjectNode)v.get(0).path("runtimeBefore")).put("id","0".repeat(64));else ((ObjectNode)v.get(0)).put("outputSha256","0".repeat(64));byte[]b=JSON.mapper().writeValueAsBytes(v);Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}
                    case "native-readback-credential"->{var v=original(m,d,before);v.put("Authorization","never-export");replace(folder,m,d,before,v);}
                    case "calibration-label-only"->m.put("selectedPath","developer-omitted-transport-key");default->{}
                }
                var secondary=(ObjectNode)m.path("usedSigningPeers").get(1);String sourceRun=stock.path("usedSigningPeers").get(1).path("runId").asText();
                switch(name){
                    case "missing-signing-peer"->((ArrayNode)m.path("usedSigningPeers")).remove(1);
                    case "foreign-signing-run"->secondary.put("runId","run_00000000000000000000000000");
                    case "duplicate-signing-run"->secondary.put("runId",run);
                    case "wrong-signing-plan"->secondary.put("planId","plan_00000000000000000000000000");
                    case "wrong-signing-request"->secondary.put("requestReference",m.path("usedSigningPeers").get(0).path("requestReference").asText());
                    case "wrong-signing-response"->secondary.put("responseReference",m.path("usedSigningPeers").get(0).path("responseReference").asText());
                    case "missing-source-history"->SOURCES.put(sourceRun,List.of());
                    case "foreign-source-history"->{var all=new ArrayList<>(SOURCES.get(sourceRun));var e=all.getFirst();all.set(0,new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));SOURCES.put(sourceRun,all);}
                    case "source-target-mismatch"->TARGET_OVERRIDES.put(sourceRun,"foreign target".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                    case "signer-certificate-replaced"->{var state=original(m,d,before);String file=state.path("readbackFile").asText();var readback=(ObjectNode)JSON.mapper().readTree(folder.resolve(file).toFile());for(var peer:readback.path("remotePeers"))if(peer.path("signatureOverridePresent").asBoolean())((ObjectNode)peer).put("signatureOverrideCertificateDerBase64",readback.path("currentCredentials").get(0).path("certificateDerBase64").asText());byte[]raw=JSON.mapper().writeValueAsBytes(readback);Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));state.put("readbackSha256",hash(raw));replace(folder,m,d,before,state);}
                    case "native-signer-use-unbound"->{var v=original(m,d,"secondary-signer-use");v.put("responseCertificateSpkiSha256","0".repeat(64));replace(folder,m,d,"secondary-signer-use",v);}
                    case "material-not-removed"->{var v=original(m,d,"ephemeral-removal");v.put("absent",false);replace(folder,m,d,"ephemeral-removal",v);}
                    default->{}
                }
                Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(m));
                try{for(String id:List.of(C1,C3)){var o=observe(directory,id,run,h,d,target,false,!name.equals("incomplete-history"));check(o.outcome()==Outcome.NOT_VERIFIED,name+" falsely concluded "+id+" "+o);}checks.put(name,Outcome.NOT_VERIFIED.name());}
                finally{SOURCES.clear();SOURCES.putAll(sourceHistories);TARGET_OVERRIDES.clear();}
            }
            copy(source.resolve("receipt"),folder);var cal=stock.deepCopy();cal.put("selectedPath","developer-omitted-transport-key");cal.put("counterfactualCalibrationOnly",true);Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(cal));
            var mutants=new TreeMap<String,Object>();for(String id:List.of(C1,C3)){var pub=observe(directory,id,run,history,decoded,target,false,true);var off=observe(directory,id,run,history,decoded,target,true,true);check(pub.outcome()==Outcome.NOT_VERIFIED&&off.outcome()==Outcome.VIOLATED,"Detector/production permission failed");mutants.put(id,Map.of("production",pub,"offline",off));}
            copy(source.resolve("receipt"),folder);var leaf=new MetadataPublisherKeyInventoryEvidence(directory,e->decoded.get(e.id()),r->run.equals(r)||SOURCES.containsKey(r)?target:null);var wrapper=new MetadataPublisherKeyInventoryConfigurationTestCase(new Fallback(C1),c->leaf.evaluate(C1,c));var context=context(run,history,decoded,true);
            var proof=((CaseStep.Finish)wrapper.start(context)).outcome();var lifecycle=new TreeMap<String,Boolean>();
            lifecycle.put("start-violated",proof.outcome()==Outcome.VIOLATED);lifecycle.put("status-ready",wrapper.evidenceStatus(context).ready());
            lifecycle.put("recorded-nv-reevaluation",wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("missing","case.pending-interaction")).orElseThrow().equals(proof));
            lifecycle.put("conclusive-unchanged",wrapper.reevaluateRecordedEvidence(context,proof).isEmpty());lifecycle.put("config-unavailable-preserved",((CaseStep.Finish)wrapper.resume(context,new CaseState("publisher",Map.of()),new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"unavailable"))).outcome().outcome()==Outcome.NOT_VERIFIED);
            var cw=new MetadataPublisherKeyInventoryConfigurationTestCase(new Fallback(C3),c->leaf.evaluate(C3,c));var c3Proof=((CaseStep.Finish)cw.start(context)).outcome();lifecycle.put("c3-real-key-omission",c3Proof.outcome()==Outcome.VIOLATED&&cw.evidenceStatus(context).ready());
            lifecycle.put("c3-recorded-nv-reevaluation",cw.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("missing","case.pending-interaction")).orElseThrow().equals(c3Proof));
            lifecycle.put("c3-conclusive-unchanged",cw.reevaluateRecordedEvidence(context,c3Proof).isEmpty());
            lifecycle.put("c3-config-unavailable-preserved",((CaseStep.Finish)cw.resume(context,new CaseState("publisher",Map.of()),new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"unavailable"))).outcome().outcome()==Outcome.NOT_VERIFIED);
            check(lifecycle.values().stream().allMatch(Boolean.TRUE::equals),"Shared wrapper lifecycle mismatch");check(Evaluator.toVerdict(Rfc2119Level.MUST,proof)==Verdict.FAIL,"Central verdict mismatch");
            var result=new LinkedHashMap<String,Object>();result.put("runId",run);result.put("targetMetadataSha256",hash(target));result.put("classCodeSourceSha256",codeSources);result.put("caseOutcomes",Map.of(C1,proof,C3,c3Proof));result.put("negativeControls",checks);result.put("approvedMutants",mutants);result.put("wrapperLifecycle",lifecycle);result.put("sourceRunIds",new TreeSet<>(SOURCES.keySet()));result.put("counterfactualAdopted",false);result.put("additionalSettings",0);result.put("additionalSaml",0);result.put("additionalCredentials",0);Files.write(report,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(result));
        }finally{try(var walk=Files.walk(tmp)){for(var p:walk.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
