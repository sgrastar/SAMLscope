package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.zip.ZipFile;

/** Immutable actual-JAR replay; diagnostic copies never replace public target originals. */
public final class VerifySloSoapContinuationEvidence {
    private static final JsonCodec JSON = new JsonCodec();
    private static String run;
    private static byte[] target;
    private static KeycloakNativeRunEvidenceBridge bridge;
    private static List<TranscriptEntry> entries;
    private static Map<String,byte[]> raw;
    private static String hash(byte[] bytes)throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static Map<String,Object> classBindings()throws Exception {
        var result=new TreeMap<String,Object>();
        for(var c:List.of(ShibbolethNativeSloContinuationEvidence.class,SoapSloPropagationTestCase.class,LogoutBrowserEvidenceTestCase.class,SloContinuationProof.class,SloContinuationActorEvidence.class,CaseOutcome.class,SecureXml.class,JsonCodec.class)) {
            var jar=Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI());
            require(Files.isRegularFile(jar,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(jar),"Unbound production CodeSource");
            String member=c.getName().replace('.','/')+".class";
            try(var zip=new ZipFile(jar.toFile())) {
                require(zip.stream().filter(e->member.equals(e.getName())).count()==1,"Ambiguous production class original");
                byte[] bytes;try(var stream=zip.getInputStream(zip.getEntry(member))){bytes=stream.readAllBytes();}
                result.put(c.getName(),Map.of("jar",jar.getFileName().toString(),"jarSha256",hash(Files.readAllBytes(jar)),"classSha256",hash(bytes)));
            }
        }
        return result;
    }
    private static CaseOutcome evaluate(Path directory,List<TranscriptEntry> list,Map<String,byte[]> bytes)throws Exception {
        TranscriptRecorder recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String r){return list;}
            public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read-only replay");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Read-only replay");}
        };
        var context = new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),new TestPlan.Interaction(false,false),Reachability.CONFIRMED,recorder,true);
        var original = new ShibbolethNativeSloContinuationEvidence(directory,e->bytes.get(e.id()),r->target,r->bridge.primaryKey(r)).read(context,ShibbolethNativeSloContinuationEvidence.CASE).orElseThrow();
        var manual = new AttestedOutcomeTestCase(ShibbolethNativeSloContinuationEvidence.CASE,TargetRole.IDP,
                "slo.continuation",Duration.ofMinutes(5),List.of(AttestationOption.notVerified("unavailable","slo.unavailable","unavailable")));
        var fallback = new BrowserEvidenceTestCase(manual,java.net.URI.create("http://localhost:18080"),"Collect genuine target continuation originals.",Duration.ofMinutes(5));
        var targetKeys=MetadataAlgorithmEvidence.signingKeys(SecureXml.parse(target).getDocumentElement());
        var observer = new LogoutBrowserEvidenceTestCase(fallback,e->bytes.get(e.id()),
                r->Optional.of(SecureXml.parse(target).getDocumentElement().getAttribute("entityID")),
                r->targetKeys,
                r->bridge.primaryKey(r)).withNativePropagation(directory,r->target);
        var wrapper = new SoapSloPropagationTestCase(observer,
                r->{throw new AssertionError("Owned evidence must not prepare another native campaign");},e->bytes.get(e.id()))
                .withTargetMetadata(r->target);
        require(wrapper.start(context) instanceof CaseStep.Finish f && original.equals(f.outcome()),"Full wrapper start disagrees with archived reader");
        require(wrapper.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()) instanceof CaseStep.Finish f
                &&original.equals(f.outcome()),"Full wrapper resume disagrees with archived reader");
        boolean conclusive=Set.of(Outcome.SATISFIED,Outcome.SATISFIED_WITH_NOTE,Outcome.VIOLATED).contains(original.outcome());
        require(wrapper.evidenceStatus(context).ready()==conclusive,"Full wrapper readiness disagrees with original");
        var replaced=wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("waiting","slo.waiting"));
        require(conclusive?replaced.isPresent()&&original.equals(replaced.get()):replaced.isEmpty(),"Full wrapper reevaluation bypassed native proof");
        return original;
    }
    private static void require(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
    private static void nv(Map<String,Object> controls,String name,Path folder,List<TranscriptEntry> list,Map<String,byte[]> bytes)throws Exception {
        var value = evaluate(folder,list,bytes);require(value.outcome()==Outcome.NOT_VERIFIED,"Control contamination adopted: "+name);controls.put(name,value);
    }
    private static void receiptControl(Map<String,Object> controls,String name,Path source,java.util.function.Consumer<ObjectNode> change)throws Exception {
        var copy=Files.createTempDirectory("soap-continuation-diagnostic-").toRealPath();
        try {
            try(var paths=Files.walk(source)){for(var p:paths.toList()) {require(!Files.isSymbolicLink(p),"Symbolic proof");var destination=copy.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(destination);else Files.copy(p,destination);}}
            var file=copy.resolve(run).resolve("manifest.json");var model=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(file));change.accept(model);Files.write(file,JSON.mapper().writeValueAsBytes(model));nv(controls,name,copy,entries,raw);
        }finally{try(var paths=Files.walk(copy)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
    public static void main(String[]args)throws Exception {
        require(args.length==3,"data root, immutable replay folder and Run required");
        var folder=Path.of(args[1]).toRealPath();run=args[2];require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid Run");
        bridge=new KeycloakNativeRunEvidenceBridge(Path.of(args[0]));entries=JSON.mapper().readValue(Files.readAllBytes(folder.resolve("transcript.json")),new TypeReference<List<TranscriptEntry>>(){});
        var seen=new HashSet<String>();for(var e:entries)require(run.equals(e.runId())&&seen.add(e.id()),"Foreign or duplicate TX");
        raw=new HashMap<>();for(var row:JSON.mapper().readTree(Files.readAllBytes(folder.resolve("decoded-manifest.json")))){
            var file=folder.resolve(row.path("file").asText()).normalize();require(file.startsWith(folder)&&!Files.isSymbolicLink(file),"Unsafe decoded original");var bytes=Files.readAllBytes(file);String id=row.path("id").asText();
            require(hash(bytes).equals(row.path("sha256").asText())&&raw.put(id,bytes)==null,"Decoded hash or duplicate");
            var e=entries.stream().filter(v->v.id().equals(id)).findFirst().orElseThrow();require(bytes.length==e.decodedSamlBytes()&&e.decodedSamlRef().equals("transcripts/"+run+"/"+id+".saml.xml"),"Decoded original binding");
        }
        target=Files.readAllBytes(folder.resolve("target-metadata.xml"));require(Arrays.equals(target,bridge.targetMetadata(run)),"Fixed metadata mismatch");
        var nativeRoot=folder.resolve("slo-soap-continuation-evidence");var original=evaluate(nativeRoot,entries,raw);var controls=new TreeMap<String,Object>();
        var copy=new ArrayList<>(entries);copy.add(entries.getFirst());nv(controls,"duplicate-recorded-entry",nativeRoot,copy,raw);
        var model=JSON.mapper().readTree(Files.readAllBytes(nativeRoot.resolve(run).resolve("manifest.json")));
        for(var t:model.path("trials")) {
            String trial=t.path("trial").asText();var p=t.path("participants").get(2);String ref=p.path("responseReference").asText();
            copy=new ArrayList<>(entries);copy.removeIf(e->e.id().equals(ref));nv(controls,"missing-"+trial+"-remaining-response",nativeRoot,copy,raw);
            var mutated=new HashMap<>(raw);var bytes=mutated.get(ref).clone();bytes[bytes.length/2]^=1;mutated.put(ref,bytes);nv(controls,"tampered-"+trial+"-remaining-response",nativeRoot,entries,mutated);
        }
        receiptControl(controls,"foreign-manifest-run",nativeRoot,m->m.put("runId","run_00000000000000000000000000"));
        receiptControl(controls,"foreign-target-metadata",nativeRoot,m->m.put("targetMetadataSha256","0".repeat(64)));
        receiptControl(controls,"counterfactual-calibration-not-product",nativeRoot,m->m.put("counterfactual",true));
        receiptControl(controls,"missing-all-success-control",nativeRoot,m->{var a=JSON.mapper().createArrayNode();for(var t:m.path("trials"))if(!"all-success".equals(t.path("trial").asText()))a.add(t);m.set("trials",a);});
        var sources=new TreeMap<String,String>();for(var c:List.of(ShibbolethNativeSloContinuationEvidence.class,SoapSloPropagationTestCase.class,LogoutBrowserEvidenceTestCase.class,SloContinuationProof.class,SloContinuationActorEvidence.class,CaseOutcome.class,SecureXml.class,JsonCodec.class))sources.put(c.getName(),Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).getFileName().toString());
        var report=new TreeMap<String,Object>();
        report.putAll(Map.of("schema","samlscope-soap-continuation-replay-v2","runId",run,"caseId",ShibbolethNativeSloContinuationEvidence.CASE,
            "outcome",original,"negativeControls",controls,"codeSources",sources,"readOnly",true,"outboundActions",0,"privateKeyExported",false,"fullWrapperLifecycleChecked",true));
        report.put("targetMetadataSha256",hash(target));report.put("classBindings",classBindings());
        report.put("positiveManifestOriginal",Map.of("file","manifest.json","sha256",hash(Files.readAllBytes(nativeRoot.resolve(run).resolve("manifest.json")))));
        System.out.println(JSON.write(report));
    }
}
