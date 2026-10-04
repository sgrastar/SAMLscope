package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;

/** Isolated archived-Reader replay. Private decryption keys remain in the Suite process. */
public final class VerifyShibbolethEntityIdUniqueness {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String CASE=ShibbolethEntityIdUniquenessEvidence.CASE;
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static byte[] original(TranscriptEntry entry)throws Exception {
        if(!entry.runId().matches("run_[0-9A-HJKMNP-TV-Z]{26}")||!entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")
            ||!("transcripts/"+entry.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()))throw new IllegalArgumentException("Unsafe original");
        byte[] raw=Files.readAllBytes(Path.of("/data").resolve(entry.decodedSamlRef()));
        if(raw.length!=entry.decodedSamlBytes())throw new IllegalArgumentException("Changed original size");return raw;
    }
    private static void restore(Path source,Path folder)throws Exception {
        if(Files.exists(folder))try(var paths=Files.walk(folder)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
        try(var paths=Files.walk(source)){for(var path:paths.toList()){
            var destination=folder.resolve(source.relativize(path));if(Files.isSymbolicLink(path))throw new IllegalArgumentException("Symlink original");
            if(Files.isDirectory(path))Files.createDirectories(destination);else Files.copy(path,destination);
        }}
    }
    private static void put(Path folder,ObjectNode manifest,String name,byte[] bytes)throws Exception {
        Files.write(folder.resolve(name),bytes);((ObjectNode)manifest.path("originals")).put(name,hash(bytes));
    }
    private static void put(Path folder,ObjectNode manifest,String name,JsonNode node)throws Exception{put(folder,manifest,name,JSON.mapper().writeValueAsBytes(node));}
    private static ObjectNode json(Path folder,String name)throws Exception{return (ObjectNode)JSON.mapper().readTree(folder.resolve(name).toFile());}
    private static CaseOutcome evaluate(Path root,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> bodies,
            Map<String,byte[]> targets,Map<String,PrivateKey> keys,boolean complete,boolean write)throws Exception {
        var run=manifest.path("runId").asText();if(write)Files.write(root.resolve(run).resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
        var recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String selected){return entries.getOrDefault(selected,List.of());}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
        return new ShibbolethEntityIdUniquenessEvidence(root,e->bodies.get(e.id()),targets::get,r->Optional.ofNullable(keys.get(r)))
            .read(context).orElse(new CaseOutcome(Outcome.NOT_VERIFIED,"metadata.entityid.native-unproven","metadata.entityid.native-unproven","metadata.entityid.native-unproven",List.of(),Map.of()));
    }
    private static TranscriptEntry changed(TranscriptEntry old,String run,String id,String decoded,Instant at,Map<String,Object> summary) {
        return new TranscriptEntry(id,run,old.direction(),at,old.correlationId(),old.method(),old.url(),old.status(),old.headers(),old.bodyRef(),old.bodyBytes(),decoded,old.decodedSamlBytes(),old.contentType(),old.rawQuery(),summary);
    }
    private static Map<String,Object> lifecycle(Path root,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> bodies,
            Map<String,byte[]> targets,Map<String,PrivateKey> keys,CaseOutcome actual)throws Exception {
        var run=manifest.path("runId").asText();
        var recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String selected){return entries.getOrDefault(selected,List.of());}
            public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Lifecycle wrote a transcript");}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Lifecycle mutated a transcript");}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        var fallback=new MetadataFixtureObservationTestCase(CASE,TargetRole.IDP,List.of(
            new MetadataFixtureObservationTestCase.Fixture("distinct-entity-ids",MetadataFixtureObservationTestCase.Behavior.ACCEPT,"actual secondary peer"),
            new MetadataFixtureObservationTestCase.Fixture("duplicate-entity-ids",MetadataFixtureObservationTestCase.Behavior.REJECT,"native conflict control")),ConfigurationFailureSemantics.TEST_PRECONDITION);
        var test=new EntityIdUniquenessConfigurationTestCase(fallback,e->bodies.get(e.id()),targets::get,r->Optional.ofNullable(keys.get(r)),root);
        var state=new CaseState("await-metadata-fixture-probe",Map.of());var checks=new TreeMap<String,Object>();
        if(!(test.start(context) instanceof CaseStep.Finish first)||!actual.equals(first.outcome()))throw new IllegalStateException("Wrapper start differs");checks.put("start",actual.outcome().name());
        for(var event:List.<CaseEvent>of(new CaseEvent.ConfigConfirmed(),new CaseEvent.TranscriptReady(),new CaseEvent.Aborted("cancel"),new CaseEvent.TimedOut(Duration.ofMinutes(1)))) {
            if(!(test.resume(context,state,event) instanceof CaseStep.Finish finish)||!actual.equals(finish.outcome()))throw new IllegalStateException("Wrapper resume differs");
            checks.put(event.getClass().getSimpleName(),finish.outcome().outcome().name());
        }
        var previous=CaseOutcome.notVerified("partial","metadata.fixture-probe.incomplete");
        if(!test.reevaluateRecordedEvidence(context,previous).orElseThrow().equals(actual)||test.reevaluateRecordedEvidence(context,actual).isPresent())throw new IllegalStateException("Recorded lifecycle differs");
        checks.put("recorded-not-verified",actual.outcome().name());checks.put("recorded-conclusive",false);
        if(!test.evidenceStatus(context).ready())throw new IllegalStateException("Wrapper status differs");checks.put("status-ready",true);
        var execution=new CaseExecution(run,CASE,1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,actual,Instant.now());
        if(!test.resolvedFromExternalEvidence(execution))throw new IllegalStateException("Native provenance missing");checks.put("external-evidence",true);
        if(test.resolvedFromExternalEvidence(new CaseExecution(run,"IIP-MD05-a2-idp-01",1,CaseExecutionStatus.FINISHED,execution.state(),null,actual,execution.updatedAt()))
            ||test.resolvedFromExternalEvidence(new CaseExecution("run_00000000000000000000000000",CASE,1,CaseExecutionStatus.FINISHED,execution.state(),null,actual,execution.updatedAt())))
            throw new IllegalStateException("Copied provenance accepted");checks.put("copied-provenance",false);
        return checks;
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=3)throw new IllegalArgumentException("receipt-dir primary-transcript-json report-json");
        java.util.logging.Logger.getLogger("org.apache.xml.security.signature.XMLSignature").setLevel(java.util.logging.Level.SEVERE);
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var source=Path.of(args[0]);var base=json(source,"manifest.json");var run=base.path("runId").asText();
        var entries=new HashMap<String,List<TranscriptEntry>>();var bodies=new HashMap<String,byte[]>();var targets=new HashMap<String,byte[]>();var keys=new HashMap<String,PrivateKey>();
        entries.put(run,List.of(JSON.mapper().readValue(Path.of(args[1]).toFile(),TranscriptEntry[].class)));
        var distinct=base.path("distinctRunId").asText();var pair=json(source,"distinct-proof/"+distinct+"/manifest.json");
        for(int index=0;index<2;index++) {
            var peer=pair.path("peers").get(index);var peerRun=peer.path("runId").asText();
            entries.put(peerRun,List.of(JSON.mapper().readValue(source.resolve("distinct-proof/"+distinct+"/"+(index==0?"primary":"secondary")+"-transcript.json").toFile(),TranscriptEntry[].class)));
            var entity=peer.path("entityId").asText();var plan=entity.substring(entity.lastIndexOf('/')+1);
            if(!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe key scope");
            var raw=Files.readAllBytes(Path.of("/data/keys/"+plan+"/signing-key.pk8"));
            keys.put(peerRun,KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(raw)));Arrays.fill(raw,(byte)0);
        }
        for(var entry:entries.entrySet()) {
            var selected=entry.getKey();if(!selected.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe target scope");
            targets.put(selected,Files.readAllBytes(Path.of("/data/target-metadata/"+selected+".xml")));
            for(var item:entry.getValue())if(item.decodedSamlRef()!=null)bodies.put(item.id(),original(item));
        }
        var temp=Files.createTempDirectory("samlscope-entityid-replay-");var folder=temp.resolve(run);var controls=new TreeMap<String,String>();
        try {
            restore(source,folder);var actual=evaluate(temp,base.deepCopy(),entries,bodies,targets,keys,true,false);
            if(actual.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Native original proof not satisfied");
            var lifecycle=lifecycle(temp,base,entries,bodies,targets,keys,actual);
            for(var mutation:List.of("missing-conflict-log","wrong-conflict-run","wrong-conflict-entity","conflict-outside-epoch","conflict-on-normal-control",
                    "wrong-native-class","wrong-native-jar","native-source-changed","wrong-native-image","different-native-image-epoch","wrong-provider-readback",
                    "missing-epoch","late-before-readback","early-after-readback","wrong-restoration","missing-distinct-peer","same-distinct-entity",
                    "wrong-distinct-restoration","missing-distinct-readback","wrong-distinct-request","missing-normal-response","wrong-normal-signature",
                    "foreign-run-entry","duplicate-entry","foreign-decoded-reference","wrong-prepared-hash","prepared-after-native-reload","incomplete-history","wrong-fixed-target")) {
                restore(source,folder);var manifest=base.deepCopy();var alteredEntries=new HashMap<>(entries);var alteredBodies=new HashMap<>(bodies);var alteredTargets=new HashMap<>(targets);boolean complete=true;
                var prefix="distinct-proof/"+distinct+"/";
                switch(mutation) {
                    case "missing-conflict-log" -> Files.delete(folder.resolve("duplicate-entity-ids/native-resolver-warn.log"));
                    case "wrong-conflict-run","wrong-conflict-entity","conflict-outside-epoch","conflict-on-normal-control" -> {
                        var log=Files.readString(folder.resolve("duplicate-entity-ids/native-resolver-warn.log"));
                        log=mutation.equals("wrong-conflict-run")?log.replace(run,"run_00000000000000000000000000"):
                            mutation.equals("wrong-conflict-entity")?log.replace("http://localhost:18080/p/","https://foreign-sp.example/p/"):
                            mutation.equals("conflict-outside-epoch")?log.replace("2026-10-01","1999-01-01"):log;
                        if(mutation.equals("conflict-on-normal-control")) {
                            put(folder,manifest,"control/native-resolver-warn.log",log.getBytes(StandardCharsets.UTF_8));
                            var epoch=(ArrayNode)JSON.mapper().readTree(folder.resolve("native-resolver-epochs.json").toFile());
                            ((ObjectNode)epoch.get(0)).put("nativeLogSha256",hash(log.getBytes(StandardCharsets.UTF_8)));put(folder,manifest,"native-resolver-epochs.json",epoch);
                        } else {
                            put(folder,manifest,"duplicate-entity-ids/native-resolver-warn.log",log.getBytes(StandardCharsets.UTF_8));
                            var epoch=(ArrayNode)JSON.mapper().readTree(folder.resolve("native-resolver-epochs.json").toFile());
                            ((ObjectNode)epoch.get(2)).put("nativeLogSha256",hash(log.getBytes(StandardCharsets.UTF_8)));put(folder,manifest,"native-resolver-epochs.json",epoch);
                        }
                    }
                    case "wrong-native-class","wrong-native-jar" -> put(folder,manifest,mutation.equals("wrong-native-class")?"native-abstract-metadata-resolver.class":"native-opensaml-saml-impl.jar",new byte[]{1,2,3});
                    case "native-source-changed" -> {var node=json(folder,"native-resolver-source.json");node.put("unchanged",false);put(folder,manifest,"native-resolver-source.json",node);}
                    case "wrong-native-image","different-native-image-epoch" -> {
                        var file=mutation.equals("wrong-native-image")?"target-container-inspect-start.json":manifest.path("distinctRuntimeFiles").get(0).asText();
                        var node=(ArrayNode)JSON.mapper().readTree(folder.resolve(file).toFile());((ObjectNode)node.get(0)).put("Image","sha256:"+"0".repeat(64));put(folder,manifest,file,node);
                    }
                    case "wrong-provider-readback" -> put(folder,manifest,"duplicate-entity-ids/flow-before-providers.xml","<wrong/>".getBytes(StandardCharsets.UTF_8));
                    case "missing-epoch","late-before-readback","early-after-readback" -> {
                        var epoch=(ArrayNode)JSON.mapper().readTree(folder.resolve("native-resolver-epochs.json").toFile());
                        if(mutation.equals("missing-epoch"))epoch.remove(0);
                        else ((ObjectNode)epoch.get(2).path(mutation.equals("late-before-readback")?"before":"after")).put("recordedAt",mutation.equals("late-before-readback")?"2099-01-01T00:00:00Z":"1999-01-01T00:00:00Z");
                        put(folder,manifest,"native-resolver-epochs.json",epoch);
                    }
                    case "wrong-restoration" -> {
                        var raw="<different/>".getBytes(StandardCharsets.UTF_8);put(folder,manifest,"final-providers.xml",raw);
                        var restoration=json(folder,"restoration.json");restoration.put("final_sha256",hash(raw));put(folder,manifest,"restoration.json",restoration);
                    }
                    case "missing-distinct-peer","same-distinct-entity","wrong-distinct-restoration","missing-distinct-readback","wrong-distinct-request" -> {
                        var changed=json(folder,prefix+"manifest.json");
                        if(mutation.equals("missing-distinct-peer"))((ArrayNode)changed.path("peers")).remove(1);
                        else if(mutation.equals("same-distinct-entity"))((ObjectNode)changed.path("peers").get(1)).put("entityId",changed.path("peers").get(0).path("entityId").asText());
                        else if(mutation.equals("wrong-distinct-request"))((ObjectNode)changed.path("peers").get(1).path("exchanges").get(0)).put("requestReference",changed.path("peers").get(0).path("exchanges").get(0).path("requestReference").asText());
                        else {
                            var row=(ObjectNode)changed.path("configurationFiles").get(0);
                            if(mutation.equals("missing-distinct-readback"))((ArrayNode)row.path("readBacks")).remove(0);
                            else {var name=row.path("finalFile").asText();var raw="<different/>".getBytes(StandardCharsets.UTF_8);put(folder,manifest,prefix+name,raw);row.put("finalSha256",hash(raw));}
                        }
                        put(folder,manifest,prefix+"manifest.json",changed);
                    }
                    case "missing-normal-response" -> alteredEntries.put(run,entries.get(run).stream().filter(e->!(e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&e.url().contains("mdv=control&"))).toList());
                    case "wrong-normal-signature" -> {
                        var entry=entries.get(run).stream().filter(e->e.direction()==Direction.INBOUND&&"Response".equals(e.samlSummary().get("type"))&&e.url().contains("mdv=control&")).findFirst().orElseThrow();
                        var text=new String(bodies.get(entry.id()),StandardCharsets.UTF_8);
                        var pattern=java.util.regex.Pattern.compile("(<(?:[A-Za-z0-9_]+:)?SignatureValue[^>]*>\\s*)([A-Za-z0-9+/])");
                        var matcher=pattern.matcher(text);if(!matcher.find())throw new IllegalStateException("Missing native signature value");
                        var position=matcher.start(2);var old=text.charAt(position);text=text.substring(0,position)+(old=='A'?'B':'A')+text.substring(position+1);
                        var raw=text.getBytes(StandardCharsets.UTF_8);if(raw.length!=entry.decodedSamlBytes())throw new IllegalStateException("Signature mutant size changed");alteredBodies.put(entry.id(),raw);
                    }
                    case "foreign-run-entry","duplicate-entry","foreign-decoded-reference","wrong-prepared-hash","prepared-after-native-reload" -> {
                        var list=new ArrayList<>(entries.get(run));int selected=1;
                        if(mutation.equals("prepared-after-native-reload"))for(int i=0;i<list.size();i++)
                            if("MetadataPrepared".equals(list.get(i).samlSummary().get("type"))&&"duplicate-entity-ids".equals(list.get(i).samlSummary().get("variant")))selected=i;
                        var old=list.get(selected);var summary=new HashMap<>(old.samlSummary());
                        if(mutation.equals("wrong-prepared-hash"))summary.put("metadataSha256","0".repeat(64));
                        if(mutation.equals("duplicate-entry"))list.add(old);
                        else {
                            var epoch=JSON.mapper().readTree(folder.resolve("native-resolver-epochs.json").toFile());
                            var time=mutation.equals("prepared-after-native-reload")?Instant.parse(epoch.get(2).path("startedAt").asText()).plusMillis(1):old.timestamp();
                            list.set(selected,changed(old,mutation.equals("foreign-run-entry")?distinct:run,old.id(),mutation.equals("foreign-decoded-reference")?"transcripts/"+distinct+"/"+old.id()+".saml.xml":old.decodedSamlRef(),time,summary));
                        }
                        alteredEntries.put(run,List.copyOf(list));
                    }
                    case "incomplete-history" -> complete=false;
                    case "wrong-fixed-target" -> manifest.put("targetMetadataSha256","0".repeat(64));
                }
                var observed=evaluate(temp,manifest,alteredEntries,alteredBodies,alteredTargets,keys,complete,true);
                if(observed.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid proof accepted "+mutation);
                controls.put(mutation,observed.outcome().name());
            }
            var report=new TreeMap<String,Object>();report.put("schema","samlscope-shibboleth-entityid-uniqueness-replay-v1");report.put("runId",run);report.put("caseId",CASE);
            var hashes=new TreeMap<String,String>();for(var entry:bodies.entrySet())hashes.put(entry.getKey(),hash(entry.getValue()));report.put("originalDecodedSha256",hashes);
            report.put("outcome",actual);report.put("controls",controls);report.put("wrapperLifecycle",lifecycle);report.put("productOperations",0);report.put("privateCredentialsUsed",true);report.put("privateCredentialsPersisted",false);
            Files.write(Path.of(args[2]),JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
        }finally{try(var paths=Files.walk(temp)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
}
