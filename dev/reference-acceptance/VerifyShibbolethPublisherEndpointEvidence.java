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
public final class VerifyShibbolethPublisherEndpointEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static void check(boolean b,String message){if(!b)throw new IllegalArgumentException(message);}
    private static CaseContext context(String run,List<TranscriptEntry> history,Map<String,byte[]> data,boolean complete){
        var normalized=history.stream().map(e->{byte[] raw=data.get(e.id());return raw==null||raw.length==e.decodedSamlBytes()?e:
            new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),e.rawQuery(),e.samlSummary());}).toList();
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){check(run.equals(r),"Foreign Run");return normalized;}
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
    private static void readback(Path folder,ObjectNode m,Map<String,byte[]>d,String label,java.util.function.Consumer<ObjectNode> change)throws Exception{
        var o=original(m,d,label);String file=o.path("readbackFile").asText();var v=(ObjectNode)JSON.mapper().readTree(folder.resolve(file).toFile());change.accept(v);
        byte[] raw=JSON.mapper().writeValueAsBytes(v);Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));o.put("readbackSha256",hash(raw));replace(folder,m,d,label,o);
    }
    private static CaseOutcome observe(Path directory,String id,String run,List<TranscriptEntry>h,Map<String,byte[]>d,byte[]target,boolean offline,boolean complete){
        return new MetadataPublisherKeyInventoryEvidence(directory,e->d.get(e.id()),r->run.equals(r)?target:null,offline).evaluate(id,context(run,h,d,complete));
    }
    private static final class Fallback implements TestCase,ConfigurationPrompt,AttestationPrompt{
        private final String id;Fallback(String id){this.id=id;}public String id(){return id;}public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Prepare publisher evidence";}public String promptEn(){return "Review original inventory";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){return new CaseStep.AwaitConfig(new CaseState("publisher",Map.of()),List.of(),"publisher.prepare",Duration.ofDays(1));}
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return e instanceof CaseEvent.ConfigUnavailable?
            new CaseStep.Finish(CaseOutcome.notVerified("unavailable","configuration.test-precondition")):start(c);}
    }
    public static void main(String[] args)throws Exception{
        check((args.length==2||args.length==3),"campaign output required");Path source=Path.of(args[0]).toAbsolutePath().normalize(),report=Path.of(args[1]);check(!Files.exists(report),"Immutable report exists");
        var stock=(ObjectNode)JSON.mapper().readTree(source.resolve("receipt/manifest.json").toFile());String run=text(stock,"runId");
        check(validRun(run),"Invalid Run");var history=new ArrayList<>(List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class)));
        var by=new HashMap<String,TranscriptEntry>();for(var e:history)check(run.equals(e.runId())&&by.put(e.id(),e)==null,"Foreign/duplicate history");
        var decoded=new HashMap<String,byte[]>();for(var row:JSON.mapper().readTree(source.resolve("decoded-manifest.json").toFile())){
            String id=row.path("id").asText();Path p=source.resolve(row.path("file").asText()).normalize();check(p.getParent().equals(source.resolve("decoded")),"Foreign content");byte[]raw=Files.readAllBytes(p);
            check(by.containsKey(id)&&raw.length==by.get(id).decodedSamlBytes()&&hash(raw).equals(row.path("sha256").asText()),"Decoded original changed");decoded.put(id,raw);
        }
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path tmp=Files.createTempDirectory("publisher-replay-").toRealPath(),directory=tmp.resolve("metadata-publisher-key-evidence"),folder=directory.resolve(run);Files.createDirectories(folder);
        try{
            copy(source.resolve("receipt"),folder);
            var codeSources=new TreeMap<String,String>();
            if(args.length==2){var pins=JSON.mapper().readTree(source.resolve("runtime-actual/pins.json").toFile());
            for(var type:List.of(MetadataPublisherKeyInventoryEvidence.class,ShibbolethPublisherEndpointInventoryAdapter.class,NativeMetadataPublisherInventoryAdapter.class,MetadataPublisherKeyInventoryConfigurationTestCase.class)){
                Path code=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());check(Files.isRegularFile(code)&&hash(Files.readAllBytes(code)).equals(pins.path("runner").asText()),"Class not from pinned archived Runner");codeSources.put(type.getName(),hash(Files.readAllBytes(code)));}}
            else check("development-only".equals(args[2]),"Unknown replay mode");
            var frame=new Frame(folder,context(run,history,decoded,true),e->decoded.get(e.id()),r->target);var adapter=new ShibbolethPublisherEndpointInventoryAdapter();
            for(var epoch:stock.path("epochs")){adapter.validate(frame,epoch);adapter.validateTransition(frame,epoch,target);}adapter.validateControls(frame,C1);adapter.validateRestoration(frame);
            var c1=observe(directory,C1,run,history,decoded,target,false,true);var c3=observe(directory,C3,run,history,decoded,target,false,true);
            check(c1.outcome()==Outcome.VIOLATED&&c3.outcome()==Outcome.NOT_VERIFIED,"Native endpoint proof differs: "+c1+" / "+c3);
            check(c1.evidence().stream().filter(e->e.kind().equals("transcript")).allMatch(e->by.containsKey(e.reference())&&run.equals(by.get(e.reference()).runId())),"Unresolvable transcript reference");
            var checks=new TreeMap<String,String>();
            for(String name:List.of("wrong-run","wrong-plan","wrong-target","wrong-adapter","wrong-campaign","wrong-entity","duplicate-history","foreign-history","foreign-decoded-reference","missing-original","missing-publication","publication-bytes-replaced","native-source-replaced","projection-source-replaced","configuration-epoch-unbound","configuration-restore-mismatch","native-runtime-replaced","native-window-reversed","native-publication-unbound","missing-control-id","duplicate-control-id","swapped-control-id","foreign-case-control-id","control-input-replaced","control-invocation-unbound","control-runtime-unbound","native-readback-credential","incomplete-history","calibration-label-only","native-endpoint-override","native-source-override","native-selected-peer-missing","baseline-response-missing","baseline-response-signature-invalid","native-profile-not-ecp","native-effective-paos-absent","operation-restoration-unbound","restored-owned-file-present","native-library-replaced","control-origin-shadowed")){
                copy(source.resolve("receipt"),folder);var m=stock.deepCopy();var d=new HashMap<>(decoded);var h=new ArrayList<>(history);String before="before";
                switch(name){
                    case "wrong-run"->m.put("runId","run_00000000000000000000000000");case "wrong-plan"->m.put("planId","plan_00000000000000000000000000");
                    case "wrong-target"->m.put("targetMetadataSha256","0".repeat(64));case "wrong-adapter"->m.put("adapter","unqualified");case "wrong-campaign"->m.put("campaignId","unrelated");case "wrong-entity"->m.put("entityId","http://other/idp");
                    case "duplicate-history"->h.add(h.getFirst());case "foreign-history"->{var e=h.getFirst();h.set(0,new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
                    case "foreign-decoded-reference"->{int i=0;while(h.get(i).decodedSamlRef()==null)i++;var e=h.get(i);h.set(i,new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),"transcripts/run_00000000000000000000000000/"+e.id()+".saml.xml",e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary()));}
                    case "missing-original"->d.remove(m.path("originals").path(before).path("reference").asText());
                    case "missing-publication","publication-bytes-replaced"->{var f=m.path("epochs").get(0).path("publicationFile").asText();if(name.equals("missing-publication"))Files.delete(folder.resolve(f));else{byte[]b=Files.readAllBytes(folder.resolve(f));b[b.length-10]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}}
                    case "native-source-replaced","projection-source-replaced"->{String f=name.equals("native-source-replaced")?"native-source/idp-conf-impl.jar":"controls/ObserveShibbolethPublisherControls.java";byte[]b=Files.readAllBytes(folder.resolve(f));b[20]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}
                    case "configuration-epoch-unbound"->{var v=original(m,d,"transition");v.put("configurationPurpose","unrelated-setting");replace(folder,m,d,"transition",v);}
                    case "configuration-restore-mismatch"->{var v=original(m,d,"restoration");v.put("restored",false);replace(folder,m,d,"restoration",v);}
                    case "native-runtime-replaced"->{var v=original(m,d,before);((ObjectNode)v.path("runtime")).put("startedAt","2020-01-01T00:00:00Z");replace(folder,m,d,before,v);}
                    case "native-window-reversed"->{var v=original(m,d,before);v.put("nativeStartedAt",v.path("nativeFinishedAt").asText());replace(folder,m,d,before,v);}
                    case "native-publication-unbound"->{var v=original(m,d,"publication");v.put("epochId","other");replace(folder,m,d,"publication",v);}
                    case "missing-control-id","duplicate-control-id","swapped-control-id","foreign-case-control-id"->{var v=original(m,d,"controls");var a=(ArrayNode)v.path("negativeControlIds");switch(name){case "missing-control-id"->a.remove(0);case "duplicate-control-id"->a.add(a.get(0));case "swapped-control-id"->{a.set(0,JSON.mapper().getNodeFactory().textNode("iip-md05-c1-idp-01-positive"));}default->a.set(0,JSON.mapper().getNodeFactory().textNode("iip-md05-c5-idp-01-negative"));}replace(folder,m,d,"controls",v);}
                    case "control-input-replaced"->{var f=m.path("controls").path("inputFile").asText();byte[]b=Files.readAllBytes(folder.resolve(f));b[30]^=1;Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));}
                    case "control-invocation-unbound","control-runtime-unbound"->{String f=m.path("controls").path("invocationsFile").asText();var v=(ArrayNode)JSON.mapper().readTree(folder.resolve(f).toFile());if(name.equals("control-runtime-unbound"))((ObjectNode)v.get(0).path("runtimeBefore")).put("containerId","0".repeat(64));else ((ArrayNode)v.get(1).path("command")).set(18,JSON.mapper().getNodeFactory().textNode("/foreign/input.json"));byte[]b=JSON.mapper().writeValueAsBytes(v);Files.write(folder.resolve(f),b);((ObjectNode)m.path("files")).put(f,hash(b));var o=original(m,d,"controls");o.put("invocationsSha256",hash(b));replace(folder,m,d,"controls",o);}
                    case "native-endpoint-override","native-source-override"->{for(String label:List.of("before","after"))readback(folder,m,d,label,v->{if(name.equals("native-endpoint-override"))((ObjectNode)v.path("processScope")).put("endpointOverridePresent",true);else ((ArrayNode)v.path("sourceOverrides")).add("/opt/reference-idp/flows/saml/saml2/sso-ecp-flow.xml");});}
                    case "native-selected-peer-missing"->{for(String label:List.of("before","after"))readback(folder,m,d,label,v->v.putNull("selectedPeer"));}
                    case "baseline-response-missing"->d.remove(m.path("baseline").path("responseReference").asText());
                    case "baseline-response-signature-invalid"->{String id=m.path("baseline").path("responseReference").asText();var root=com.samlscope.saml.normal.SecureXml.parse(d.get(id)).getDocumentElement();root.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0).setTextContent("invalid");d.put(id,com.samlscope.saml.normal.SecureXml.serialize(root.getOwnerDocument()));}
                    case "native-profile-not-ecp","native-effective-paos-absent"->{for(String label:List.of("before","after")){
                        var old=original(m,d,label);String rf=old.path("readbackFile").asText();var state=(ObjectNode)JSON.mapper().readTree(folder.resolve(rf).toFile());var r=(ObjectNode)(name.equals("native-profile-not-ecp")?state.path("selectedProfiles").path("ecp"):state.path("selectedPeer"));String file=r.path("file").asText();byte[] raw;
                        if(name.equals("native-profile-not-ecp")){var p=(ObjectNode)JSON.mapper().readTree(folder.resolve(file).toFile());((ObjectNode)p.path("ProfileConfiguration")).put("id","http://foreign/profile");raw=JSON.mapper().writeValueAsBytes(p);}else raw=Files.readString(folder.resolve(file)).replace("urn:oasis:names:tc:SAML:2.0:bindings:PAOS","urn:foreign:binding").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));String digest=hash(raw);readback(folder,m,d,label,v->((ObjectNode)(name.equals("native-profile-not-ecp")?v.path("selectedProfiles").path("ecp"):v.path("selectedPeer"))).put("sha256",digest));}}
                    case "operation-restoration-unbound"->{var rows=(ArrayNode)JSON.mapper().readTree(folder.resolve("operations.json").toFile());((ObjectNode)rows.get(7)).put("sha256","0".repeat(64));byte[] raw=JSON.mapper().writeValueAsBytes(rows);Files.write(folder.resolve("operations.json"),raw);((ObjectNode)m.path("files")).put("operations.json",hash(raw));var o=original(m,d,"operations");o.put("operationsSha256",hash(raw));replace(folder,m,d,"operations",o);}
                    case "restored-owned-file-present"->readback(folder,m,d,"restored",v->v.put("temporaryPresent",true));
                    case "native-library-replaced"->{String file="native-libraries/opensaml-core-api-5.2.3.jar";byte[] raw=Files.readAllBytes(folder.resolve(file));raw[100]^=1;Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));}
                    case "control-origin-shadowed"->{String file=m.path("controls").path("observationFile").asText();var v=(ObjectNode)JSON.mapper().readTree(folder.resolve(file).toFile());((ObjectNode)v.path("nativeClassOrigins")).put("org.opensaml.core.config.InitializationService","file:/tmp/foreign.jar");byte[] raw=JSON.mapper().writeValueAsBytes(v);Files.write(folder.resolve(file),raw);((ObjectNode)m.path("files")).put(file,hash(raw));var o=original(m,d,"controls");o.put("observationSha256",hash(raw));replace(folder,m,d,"controls",o);}
                    case "native-readback-credential"->{var v=original(m,d,before);v.put("Authorization","never-export");replace(folder,m,d,before,v);}
                    case "calibration-label-only"->m.put("selectedPath","developer-omitted-transport-key");default->{}
                }
                Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(m));var o=observe(directory,C1,run,h,d,target,false,!name.equals("incomplete-history"));check(o.outcome()==Outcome.NOT_VERIFIED,name+" falsely concluded "+o);checks.put(name,o.outcome().name());
            }
            copy(source.resolve("receipt"),folder);var cal=stock.deepCopy();cal.put("selectedPath","developer-omitted-transport-key");cal.put("counterfactualCalibrationOnly",true);Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(cal));
            var mutants=new TreeMap<String,Object>();for(String id:List.of(C1)){var pub=observe(directory,id,run,history,decoded,target,false,true);var off=observe(directory,id,run,history,decoded,target,true,true);check(pub.outcome()==Outcome.NOT_VERIFIED&&off.outcome()==Outcome.VIOLATED,"Detector/production permission failed");mutants.put(id,Map.of("production",pub,"offline",off));}
            copy(source.resolve("receipt"),folder);var leaf=new MetadataPublisherKeyInventoryEvidence(directory,e->decoded.get(e.id()),r->target);var wrapper=new MetadataPublisherKeyInventoryConfigurationTestCase(new Fallback(C1),c->leaf.evaluate(C1,c));var context=context(run,history,decoded,true);
            var proof=((CaseStep.Finish)wrapper.start(context)).outcome();var lifecycle=new TreeMap<String,Boolean>();
            lifecycle.put("start-violated",proof.outcome()==Outcome.VIOLATED);lifecycle.put("status-ready",wrapper.evidenceStatus(context).ready());
            lifecycle.put("recorded-nv-reevaluation",wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("missing","case.pending-interaction")).orElseThrow().equals(proof));
            lifecycle.put("conclusive-unchanged",wrapper.reevaluateRecordedEvidence(context,proof).isEmpty());lifecycle.put("config-unavailable-preserved",((CaseStep.Finish)wrapper.resume(context,new CaseState("publisher",Map.of()),new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT,"unavailable"))).outcome().outcome()==Outcome.NOT_VERIFIED);
            var cw=new MetadataPublisherKeyInventoryConfigurationTestCase(new Fallback(C3),c->leaf.evaluate(C3,c));lifecycle.put("c3-remains-unverified",cw.start(context) instanceof CaseStep.AwaitConfig&&!cw.evidenceStatus(context).ready());
            check(lifecycle.values().stream().allMatch(Boolean.TRUE::equals),"Shared wrapper lifecycle mismatch");check(Evaluator.toVerdict(Rfc2119Level.MUST,proof)==Verdict.FAIL,"Central verdict mismatch");
            var result=new LinkedHashMap<String,Object>();result.put("runId",run);result.put("targetMetadataSha256",hash(target));result.put("classCodeSourceSha256",codeSources);result.put("caseOutcomes",Map.of(C1,proof,C3,c3));result.put("negativeControls",checks);result.put("approvedMutants",mutants);result.put("wrapperLifecycle",lifecycle);result.put("counterfactualAdopted",false);result.put("developmentOnly",args.length==3);result.put("additionalSettings",0);result.put("additionalSaml",0);result.put("additionalCredentials",0);Files.write(report,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(result));
        }finally{try(var walk=Files.walk(tmp)){for(var p:walk.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
