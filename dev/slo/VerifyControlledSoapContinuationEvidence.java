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
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.zip.ZipFile;

/** Read-only access to an isolated control target. The common predicate receives no
 * calibration flag: verified complete attempts, signed replies and terminal originals
 * determine the outcome. These target originals are never stock-product evidence. */
public final class VerifyControlledSoapContinuationEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static String run;
    private static byte[] target;
    private static PrivateKey factoryKey;
    private static List<TranscriptEntry> entries;
    private static Map<String,byte[]> raw;
    private static String hash(byte[] bytes)throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static void require(boolean value,String message) {
        if(!value)throw new IllegalArgumentException(message);
    }
    private static CaseOutcome evaluate(Path root,List<TranscriptEntry> list,Map<String,byte[]> bytes)throws Exception {
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String r){require(run.equals(r),"Foreign recorder Run");return list;}
            public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read-only replay");}
            public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Read-only replay");}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),
                new TestPlan.Interaction(false,false),Reachability.CONFIRMED,recorder,true);
        // Permission admits an independently selected diagnostic source, never an Outcome.
        var reader=new ShibbolethNativeSloContinuationEvidence(root,e->bytes.get(e.id()),r->target,r->Optional.of(factoryKey),true);
        var outcome=reader.read(context,ShibbolethNativeSloContinuationEvidence.CASE).orElseThrow();
        var manual=new AttestedOutcomeTestCase(ShibbolethNativeSloContinuationEvidence.CASE,TargetRole.IDP,"slo.continuation",
                Duration.ofMinutes(5),List.of(AttestationOption.notVerified("unavailable","slo.unavailable","unavailable")));
        var fallback=new BrowserEvidenceTestCase(manual,java.net.URI.create("http://localhost:18080"),"Collect continuation originals.",Duration.ofMinutes(5));
        var targetXml=SecureXml.parse(target).getDocumentElement();
        var targetKeys=MetadataAlgorithmEvidence.signingKeys(targetXml);
        var observer=new LogoutBrowserEvidenceTestCase(fallback,e->bytes.get(e.id()),r->Optional.of(targetXml.getAttribute("entityID")),
                r->targetKeys,r->Optional.of(factoryKey)).withNativePropagation(root,r->target,true);
        var wrapper=new SoapSloPropagationTestCase(observer,r->{throw new AssertionError("Owned proof must not issue preparation");},e->bytes.get(e.id()))
                .withTargetMetadata(r->target);
        require(wrapper.start(context) instanceof CaseStep.Finish f&&outcome.equals(f.outcome()),"Full wrapper start differs");
        require(wrapper.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()) instanceof CaseStep.Finish f&&outcome.equals(f.outcome()),"Full wrapper resume differs");
        boolean conclusive=Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(outcome.outcome());
        require(wrapper.evidenceStatus(context).ready()==conclusive,"Full wrapper readiness differs");
        require(wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("waiting","slo.waiting"))
                .equals(conclusive?Optional.of(outcome):Optional.empty()),"Full wrapper reevaluation differs");
        return outcome;
    }
    private static void copy(Path source,Path destination)throws Exception {
        try(var paths=Files.walk(source)){for(var p:paths.toList()){
            require(!Files.isSymbolicLink(p),"Symbolic control original");var dest=destination.resolve(source.relativize(p));
            if(Files.isDirectory(p))Files.createDirectories(dest);else Files.copy(p,dest);
        }}
    }
    private static void remove(Path root)throws Exception {
        try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
    }
    private static void nv(Map<String,Object> controls,String name,Path root,List<TranscriptEntry> list,Map<String,byte[]> bytes)throws Exception {
        var value=evaluate(root,list,bytes);require(value.outcome()==Outcome.NOT_VERIFIED,"Contaminated control adopted: "+name);controls.put(name,value);
    }
    private static void mutatedReceipt(Map<String,Object> controls,String name,Path source,java.util.function.Consumer<ObjectNode> change)throws Exception {
        Path root=Files.createTempDirectory("controlled-slo-mutation-").toRealPath();
        try{copy(source,root);var manifest=root.resolve(run).resolve("manifest.json");
            var model=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(manifest));change.accept(model);
            Files.write(manifest,JSON.mapper().writeValueAsBytes(model));nv(controls,name,root,entries,raw);
        }finally{remove(root);}
    }
    private static void mutatedOriginal(Map<String,Object> controls,String name,Path source,String file,boolean json)throws Exception {
        Path root=Files.createTempDirectory("controlled-slo-mutation-").toRealPath();
        try{copy(source,root);var manifest=root.resolve(run).resolve("manifest.json");
            var model=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(manifest));var original=root.resolve(run).resolve(file);
            byte[] changed;
            if(json){var content=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(original));content.put("runId","run_11111111111111111111111111");changed=JSON.mapper().writeValueAsBytes(content);}
            else {changed=Files.readAllBytes(original);changed[changed.length/2]^=1;}
            Files.write(original,changed);((ObjectNode)model.path("files")).put(file,hash(changed));
            Files.write(manifest,JSON.mapper().writeValueAsBytes(model));nv(controls,name,root,entries,raw);
        }finally{remove(root);}
    }
    private static Map<String,Object> classBindings()throws Exception {
        var result=new TreeMap<String,Object>();
        for(var c:List.of(ShibbolethNativeSloContinuationEvidence.class,SoapSloPropagationTestCase.class,
                LogoutBrowserEvidenceTestCase.class,SloContinuationProof.class,SloContinuationActorEvidence.class,
                CaseOutcome.class,SecureXml.class,JsonCodec.class)) {
            var jar=Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI());
            require(Files.isRegularFile(jar,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(jar),"Unbound production CodeSource");
            String member=c.getName().replace('.','/')+".class";
            try(var zip=new ZipFile(jar.toFile())) {
                require(zip.stream().filter(e->member.equals(e.getName())).count()==1,"Ambiguous production class");
                byte[] bytes;try(var stream=zip.getInputStream(zip.getEntry(member))){bytes=stream.readAllBytes();}
                result.put(c.getName(),Map.of("jar",jar.getFileName().toString(),"jarSha256",hash(Files.readAllBytes(jar)),"classSha256",hash(bytes)));
            }
        }
        return result;
    }
    public static void main(String[]args)throws Exception {
        require(args.length==1,"Immutable actor original folder required");var folder=Path.of(args[0]).toRealPath();
        var manifest=JSON.mapper().readTree(Files.readAllBytes(folder.resolve("receipt/manifest.json")));run=manifest.path("runId").asText();
        require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid diagnostic Run");
        entries=JSON.mapper().readValue(Files.readAllBytes(folder.resolve("transcript.json")),new TypeReference<List<TranscriptEntry>>(){});
        var seen=new HashSet<String>();for(var e:entries)require(run.equals(e.runId())&&seen.add(e.id()),"Foreign or duplicate original TX");
        raw=new HashMap<>();for(var row:JSON.mapper().readTree(Files.readAllBytes(folder.resolve("decoded-manifest.json")))) {
            var file=folder.resolve(row.path("file").asText()).normalize();require(file.startsWith(folder)&&!Files.isSymbolicLink(file),"Unsafe decoded original");
            var bytes=Files.readAllBytes(file);require(hash(bytes).equals(row.path("sha256").asText())&&raw.put(row.path("id").asText(),bytes)==null,"Decoded original hash or duplicate differs");
        }
        target=Files.readAllBytes(folder.resolve("target-metadata.xml"));
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);factoryKey=generator.generateKeyPair().getPrivate();
        Path root=Files.createTempDirectory("controlled-slo-proof-").toRealPath();
        try {
            copy(folder.resolve("receipt"),root.resolve(run));var value=evaluate(root,entries,raw);var controls=new TreeMap<String,Object>();
            var duplicate=new ArrayList<>(entries);duplicate.add(entries.getFirst());nv(controls,"duplicate-recorded-entry",root,duplicate,raw);
            var failure=manifest.path("trials").get(0);require("failure".equals(failure.path("trial").asText()),"Unknown trial ordering");
            String finalRef=failure.path("originResponseReference").asText();var missing=new ArrayList<>(entries);missing.removeIf(e->e.id().equals(finalRef));
            nv(controls,"missing-signed-origin-final",root,missing,raw);
            var modified=new HashMap<>(raw);var bytes=modified.get(finalRef).clone();bytes[bytes.length/2]^=1;modified.put(finalRef,bytes);
            nv(controls,"tampered-signed-origin-final",root,entries,modified);
            mutatedReceipt(controls,"foreign-manifest-run",root,m->m.put("runId","run_11111111111111111111111111"));
            mutatedReceipt(controls,"foreign-fixed-target",root,m->m.put("targetMetadataSha256","0".repeat(64)));
            mutatedOriginal(controls,"changed-selected-producer-source",root,manifest.path("producerSourceFile").asText(),false);
            mutatedOriginal(controls,"foreign-operation-input",root,failure.path("operationInputFile").asText(),true);
            mutatedOriginal(controls,"foreign-operation-output",root,failure.path("operationOutputFile").asText(),true);
            mutatedOriginal(controls,"tampered-signed-complete-operation",root,failure.path("operationTraceFile").asText(),false);
            var report=new TreeMap<String,Object>();report.put("schema","samlscope-soap-controlled-replay-v1");
            report.put("runId",run);report.put("caseId",ShibbolethNativeSloContinuationEvidence.CASE);report.put("outcome",value);
            report.put("targetMetadataSha256",hash(target));report.put("classBindings",classBindings());report.put("negativeControls",controls);
            report.put("fullWrapperLifecycleChecked",true);report.put("sameProductionPredicate",true);report.put("readOnly",true);
            report.put("outboundActions",0);report.put("ephemeralFactoryKeyPersisted",false);report.put("stockPlacementPermitted",false);
            report.put("manifestOriginal",Map.of("file","receipt/manifest.json","sha256",hash(Files.readAllBytes(folder.resolve("receipt/manifest.json")))));
            System.out.println(JSON.write(report));
        }finally{remove(root);factoryKey=null;}
    }
}
