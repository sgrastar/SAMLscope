package com.samlscope.runner.cases;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
/** Read-only complete originals, installed profile membership and production reader replay. */
public final class VerifyKeycloakForceAuthnMechanism {
    private static final ObjectMapper M=new JsonCodec().mapper();
    static void require(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    static String hash(byte[] raw)throws Exception{return KeycloakAuthenticationIdentityEvidence.hash(raw);}
    static void rehash(Path f,String name)throws Exception{var m=(ObjectNode)M.readTree(f.resolve("manifest.json").toFile());((ObjectNode)m.path("files")).put(name,hash(Files.readAllBytes(f.resolve(name))));Files.write(f.resolve("manifest.json"),M.writeValueAsBytes(m));}
    static void edit(Path f,String name,java.util.function.Consumer<JsonNode> mutation)throws Exception{var value=M.readTree(f.resolve(name).toFile());mutation.accept(value);Files.write(f.resolve(name),M.writeValueAsBytes(value));if(!name.equals("manifest.json"))rehash(f,name);}
    static void nativeRecord(Path f,String field,JsonNode body)throws Exception{edit(f,"native-scope-before.json",m->{try{byte[] raw=M.writeValueAsBytes(body);var record=(ObjectNode)m.path(field);record.put("response_base64",Base64.getEncoder().encodeToString(raw));record.put("response_sha256",hash(raw));}catch(Exception failure){throw new IllegalArgumentException(failure);}});}
    public static void main(String[] args)throws Exception {
        if(args[0].equals("offline")) {var state=(ObjectNode)M.readTree(Path.of(args[1]).toFile());require(state.path("schema").asText().equals("samlscope-keycloak-forceauthn-stored-v1"),"Unsafe stored schema");
            var c=(ObjectNode)state.path("case");require(state.path("runId").asText().matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&KeycloakForceAuthnMechanismEvidence.CASE.equals(c.path("caseId").asText())&&c.path("runId").equals(state.path("runId")),"Foreign central stored case");
            if(!c.path("outcome").isNull())c.put("verdict",Evaluator.toVerdict(Rfc2119Level.MUST,M.treeToValue(c.path("outcome"),CaseOutcome.class)).name());else c.putNull("verdict");Files.write(Path.of(args[2]),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(state));return;}
        String mode=args[0],run=args[2];Path data=Path.of(args[1]),source=Path.of(args[3]),output=Path.of(args[4]);
        var store=new DefaultAlgorithmSourceRunStore(data,KeycloakForceAuthnMechanismEvidence.CASE,KeycloakForceAuthnMechanismEvidence.DIGEST);
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var binding=store.execution(run);var entries=entries(data,run);
        if(mode.equals("state")) {
            var state=new TreeMap<String,Object>();state.put("schema","samlscope-keycloak-forceauthn-stored-v1");state.put("runId",run);state.put("caseId",KeycloakForceAuthnMechanismEvidence.CASE);
            state.put("sourceStore",KeycloakForceAuthnMechanismEvidence.stableSnapshot(binding.snapshot()));state.put("sourceHistory",store.history(run,entries,bridge::content));
            var executions=new TreeMap<String,String>();
            try(var c=java.sql.DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT case_id,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")) {
                q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()) {String id=rows.getString(1),raw=rows.getString(2);var execution=M.readValue(raw,CaseExecution.class);
                    require(run.equals(execution.runId())&&id.equals(execution.caseId())&&executions.put(id,hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)))==null,"Foreign stored execution");
                    if(id.equals(KeycloakForceAuthnMechanismEvidence.CASE)) {var projected=new TreeMap<String,Object>();projected.put("runId",run);projected.put("caseId",id);projected.put("status",execution.status().name());projected.put("revision",execution.revision());projected.put("updatedAt",execution.updatedAt().toString());
                        projected.put("stateSha256",hash(M.writeValueAsBytes(execution.state())));projected.put("waitSha256",hash(M.writeValueAsBytes(execution.waitCondition())));projected.put("documentSha256",hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));projected.put("outcome",execution.outcome());
                        projected.put("verdict",execution.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,execution.outcome()));state.put("case",projected);}
                }}
            }
            require(state.containsKey("case"),"Missing approved native case");state.put("executions",executions);Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(state));return;
        }
        if(mode.equals("snapshot")){
            Files.write(source.resolve("source-store-snapshot.json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(KeycloakForceAuthnMechanismEvidence.stableSnapshot(binding.snapshot())));
            Files.write(source.resolve("source-history.json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(store.history(run,entries,bridge::content)));
            Files.write(output,M.writeValueAsBytes(Map.of("approvedMembershipVerified",true,"runId",run,"caseId",KeycloakForceAuthnMechanismEvidence.CASE,"entries",entries.size())));return;
        }
        Path root=Files.createTempDirectory("kc-mechanism-reader-controls-");Path folder=root.resolve(run+".keycloak-forceauthn-mechanism");
        try{
            try(var paths=Files.walk(source)){for(var from:paths.toList()){Path to=folder.resolve(source.relativize(from));if(Files.isDirectory(from))Files.createDirectories(to);else Files.copy(from,to);}}
            var context=binding.context(Clock.systemUTC(),entries);var reader=new KeycloakForceAuthnMechanismEvidence(root,bridge::content,bridge::targetMetadata,store);
            var original=reader.read(context).orElseThrow();require(original.outcome()==Outcome.SATISFIED,"Current production reader did not qualify: "+original);
            if(mode.equals("forgery")) {
                trace(folder,2,"mechanismRawNotePresent",true);
                Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("schema","samlscope-keycloak-forceauthn-forged-native-trace-v1",
                    "runId",run,"caseId",KeycloakForceAuthnMechanismEvidence.CASE,"originalOutcome",original.outcome().name(),
                    "forgedOutcome",reader.read(context).orElseThrow().outcome().name(),"manifestHashesCoherent",true,"sourceOriginalsChanged",false)));
                return;
            }
            var baseline=new KeycloakAuthenticationIdentityEvidence(folder.resolve("source"),bridge::content,bridge::targetMetadata,r->Optional.empty(),KeycloakForceAuthnMechanismEvidence.COLLECTOR,KeycloakForceAuthnMechanismEvidence.CLASSPATH).evaluate(context).orElseThrow();
            require(baseline.outcome()==Outcome.SATISFIED,"Current original native baseline did not qualify");
            var originals=new HashMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList())originals.put(folder.relativize(p).toString(),Files.readAllBytes(p));}
            var controls=new LinkedHashMap<String,String>();
            for(String name:List.of("wrong-run","wrong-case","wrong-case-digest","wrong-plan","foreign-store-context","foreign-history","source-original-changed","helper-changed","runtime-subset","native-jar-changed","true-live-claim","seeded-flag","mock-session","mock-result","native-flow-not-executed","form-entry-not-executed","different-session","wrong-flow","wrong-mechanism","wrong-input","wrong-request","lost-positive-indicator","positive-control-as-mutant","missing-negative-control","mutant-lacks-detection","misbinding-undetected","origin-sha-changed","missing-original","symlink-original","realm-model-changed","scope-collector-changed","scope-foreign-run","scope-foreign-plan","scope-foreign-target","scope-foreign-source","scope-foreign-store","scope-foreign-history","scope-foreign-runtime","scope-foreign-classpath","scope-restored-client-present","scope-restored-flow-changed","scope-native-write","scope-before-after-process","scope-after-before-process","scope-realm-epoch-changed","forged-coherent-native-trace")){
                for(var row:originals.entrySet()){Path p=folder.resolve(row.getKey());if(!Files.exists(p,LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(p)||!Arrays.equals(Files.readAllBytes(p),row.getValue())){Files.deleteIfExists(p);Files.write(p,row.getValue());}}
                switch(name){
                    case "wrong-run"->edit(folder,"manifest.json",m->((ObjectNode)m).put("runId","other"));
                    case "wrong-case"->edit(folder,"manifest.json",m->((ObjectNode)m).put("caseId","IIP-IDP06-a-idp-01"));
                    case "wrong-case-digest"->edit(folder,"manifest.json",m->((ObjectNode)m).put("caseDigest","sha256:"+"0".repeat(64)));
                    case "wrong-plan"->edit(folder,"manifest.json",m->((ObjectNode)m).put("planId","other"));
                    case "foreign-store-context"->edit(folder,"source-store-snapshot.json",m->((ObjectNode)m).put("planDocumentSha256","0".repeat(64)));
                    case "foreign-history"->edit(folder,"source-history.json",m->((ObjectNode)m.get(0)).put("entrySha256","0".repeat(64)));
                    case "source-original-changed"->Files.writeString(folder.resolve("source/"+run+"/originals/native-client-before.json"),"other");
                    case "helper-changed"->{Files.writeString(folder.resolve("native-helper.java"),"other");rehash(folder,"native-helper.java");}
                    case "runtime-subset"->{Files.writeString(folder.resolve("native-classpath.txt"),"subset");rehash(folder,"native-classpath.txt");}
                    case "native-jar-changed"->Files.writeString(folder.resolve("native-complete/lib/main/org.keycloak.keycloak-services-26.7.2.jar"),"other");
                    case "true-live-claim"->edit(folder,"native-trace.json",m->((ObjectNode)m).put("trueLivePasswordUiExecutionClaimed",true));
                    case "seeded-flag"->trace(folder,1,"positiveFlagSeededByHarness",true);
                    case "mock-session"->trace(folder,1,"nativeSessionClass","synthetic-interface");
                    case "mock-result"->trace(folder,1,"nativeResultClass","synthetic-result");
                    case "native-flow-not-executed"->trace(folder,1,"nativeSelectedFlowExecuted",false);
                    case "form-entry-not-executed"->trace(folder,1,"mechanismEntryExecuted",false);
                    case "different-session"->trace(folder,1,"sameNativeSessionObject",false);
                    case "wrong-flow"->trace(folder,1,"nativeResolvedFlowId","other");
                    case "wrong-mechanism"->trace(folder,1,"mechanismClass","other");
                    case "wrong-input"->trace(folder,1,"inputSha256","0".repeat(64));
                    case "wrong-request"->trace(folder,1,"mechanismRequestId","other");
                    case "lost-positive-indicator"->trace(folder,1,"mechanismNativeIndicator",false);
                    case "positive-control-as-mutant"->trace(folder,1,"mutation","drop-indicator");
                    case "missing-negative-control"->edit(folder,"native-trace.json",m->((com.fasterxml.jackson.databind.node.ArrayNode)m.path("traces")).remove(2));
                    case "mutant-lacks-detection"->trace(folder,2,"mechanismNativeIndicator",true);
                    case "misbinding-undetected"->edit(folder,"native-trace.json",m->((ObjectNode)m.path("traces").get(4)).put("mechanismRequestId",m.path("traces").get(4).path("requestId").asText()));
                    case "origin-sha-changed"->edit(folder,"native-trace.json",m->((ObjectNode)m.path("classes").get(0)).put("classSha256","0".repeat(64)));
                    case "missing-original"->Files.delete(folder.resolve("native-trace.json"));
                    case "symlink-original"->{Files.delete(folder.resolve("native-trace.json"));Files.createSymbolicLink(folder.resolve("native-trace.json"),source.resolve("native-trace.json"));}
                    case "realm-model-changed"->{Files.writeString(folder.resolve("native-realm-before.json"),"{}");rehash(folder,"native-realm-before.json");}
                    case "scope-collector-changed"->{Files.writeString(folder.resolve("native-scope-collector.py"),"other");rehash(folder,"native-scope-collector.py");}
                    case "scope-foreign-run"->scope(folder,"before","runId","other");
                    case "scope-foreign-plan"->scope(folder,"before","planId","other");
                    case "scope-foreign-target"->scope(folder,"before","targetEntityId","urn:other");
                    case "scope-foreign-source"->scope(folder,"before","sourceManifestSha256","0".repeat(64));
                    case "scope-foreign-store"->scope(folder,"before","sourceStoreSnapshotSha256","0".repeat(64));
                    case "scope-foreign-history"->scope(folder,"before","sourceHistorySha256","0".repeat(64));
                    case "scope-foreign-runtime"->edit(folder,"native-scope-before.json",m->((ObjectNode)m).set("runtime",M.createObjectNode()));
                    case "scope-foreign-classpath"->scope(folder,"before","nativeClasspathSha256","0".repeat(64));
                    case "scope-restored-client-present"->nativeRecord(folder,"restoredClientAbsenceRecord",M.createArrayNode().add(M.createObjectNode()));
                    case "scope-restored-flow-changed"->nativeRecord(folder,"restoredFlowInventoryRecord",M.createArrayNode());
                    case "scope-native-write"->scope(folder,"before","productSettingWrites",1);
                    case "scope-before-after-process"->edit(folder,"native-scope-before.json",m->((ObjectNode)m.path("realmRecord")).put("recordedAt","2099-01-01T00:00:00Z"));
                    case "scope-after-before-process"->edit(folder,"native-scope-after.json",m->((ObjectNode)m.path("realmRecord")).put("recordedAt","2000-01-01T00:00:00Z"));
                    case "scope-realm-epoch-changed"->edit(folder,"native-scope-after.json",m->((ObjectNode)m.path("realmRecord")).put("unprojected_response_sha256","0".repeat(64)));
                    case "forged-coherent-native-trace"->trace(folder,2,"mechanismRawNotePresent",true);
                }
                var result=reader.read(context).orElseThrow();require(result.outcome()==Outcome.NOT_VERIFIED,"Altered native proof accepted: "+name);controls.put(name,"NOT_VERIFIED");
            }
            for(var row:originals.entrySet()){Path p=folder.resolve(row.getKey());Files.deleteIfExists(p);Files.write(p,row.getValue());}
            var wrapper=new ForceAuthnMechanismEvidenceTestCase(new IdpForceAuthnScenarioTestCase(KeycloakForceAuthnMechanismEvidence.CASE,
                r->{throw new AssertionError("Native mechanism evidence must not trigger target logins");}),reader);
            require(((CaseStep.Finish)wrapper.start(context)).outcome().equals(original)&&wrapper.evidenceStatus(context).ready()
                &&wrapper.queuedEvidenceOutcome(context).equals(original)
                &&wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(original),"Production wrapper path unavailable");
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"caseId",KeycloakForceAuthnMechanismEvidence.CASE,"productionOutcome",original,"nativeBaseline",baseline,"negativeControls",controls,"productionWrapperVerified",true,"sourceOriginalsChanged",false,"trueLivePasswordUiExecutionClaimed",false)));
        }finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    private static List<TranscriptEntry> entries(Path data,String run)throws Exception{var list=new ArrayList<TranscriptEntry>();var codec=new JsonCodec();
        try(var c=java.sql.DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){
            q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next())list.add(codec.read(rows.getString(1),TranscriptEntry.class));}}return List.copyOf(list);}
    private static void trace(Path folder,int index,String field,Object value)throws Exception{edit(folder,"native-trace.json",m->((ObjectNode)m.path("traces").get(index)).set(field,M.valueToTree(value)));}
    private static void scope(Path folder,String phase,String field,Object value)throws Exception{edit(folder,"native-scope-"+phase+".json",m->((ObjectNode)m).set(field,M.valueToTree(value)));}
}
