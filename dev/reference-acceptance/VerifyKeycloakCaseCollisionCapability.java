package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.time.*;
import java.util.*;

/** Provisional read-only scope/snapshot utility. IDP21 replay/adoption is disabled pending normative controls. */
public final class VerifyKeycloakCaseCollisionCapability {
    private static final ObjectMapper M=new JsonCodec().mapper();
    private static void require(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    private static String hash(byte[] bytes)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(bytes);}
    private static void save(Path file,Object value)throws Exception{Files.write(file,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));}
    public static void main(String[] args)throws Exception{
        require(args.length==5,"mode,data,recipientRun,folder-or-sourceRun,output required");String mode=args[0],run=args[2];require(!mode.equals("replay"),"IDP21 is unregistered and NOT_VERIFIED: same-policy different-subject normative control and recipient transcript unqualified; replay/adoption disabled");Path data=Path.of(args[1]).toAbsolutePath().normalize(),folder=Path.of(args[3]).toAbsolutePath().normalize(),output=Path.of(args[4]);
        require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid recipient Run");var destinationStore=new DefaultAlgorithmSourceRunStore(data,KeycloakCaseCollisionCapabilityEvidence.CASE,KeycloakCaseCollisionCapabilityEvidence.DIGEST);var destination=destinationStore.execution(run);var bridge=new KeycloakNativeRunEvidenceBridge(data);
        String sourceRun=mode.equals("preflight")?args[3]:M.readTree(folder.resolve("manifest.json").toFile()).path("sourceRunId").asText();require(sourceRun.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&!sourceRun.equals(run),"Invalid source Run");
        var sourceStores=new TreeMap<String,DefaultAlgorithmSourceRunStore>();KeycloakPersistentIdentifierEvidence.DIGESTS.forEach((id,digest)->sourceStores.put(id,new DefaultAlgorithmSourceRunStore(data,id,digest)));
        var sources=new TreeMap<String,DefaultAlgorithmSourceRunStore.Binding>();for(var row:sourceStores.entrySet())sources.put(row.getKey(),row.getValue().execution(sourceRun));
        var destHistory=entries(data,run);var sourceHistory=entries(data,sourceRun);var sourceSnapshots=new TreeMap<String,JsonNode>();for(var row:sources.entrySet())sourceSnapshots.put(row.getKey(),KeycloakPersistentIdentifierEvidence.stable(row.getValue().snapshot()));
        var source=sources.firstEntry().getValue();require("single_logout_idp".equals(destination.plan().profile().id())&&"browser_sso_idp".equals(source.plan().profile().id())&&destination.plan().target().entityId().equals(source.plan().target().entityId())&&Arrays.equals(bridge.targetMetadata(run),bridge.targetMetadata(sourceRun)),"Source scope differs");
        var scope=new TreeMap<String,Object>();scope.put("approvedRecipientMembership",true);scope.put("caseId",KeycloakCaseCollisionCapabilityEvidence.CASE);scope.put("caseDigest",KeycloakCaseCollisionCapabilityEvidence.DIGEST);scope.put("runId",run);scope.put("planId",destination.plan().id());scope.put("profile",destination.plan().profile().id());scope.put("definitionIdentity",destination.plan().definitionIdentity());scope.put("sourceRunId",sourceRun);scope.put("sourcePlanId",source.plan().id());scope.put("sourceCaseDigests",KeycloakPersistentIdentifierEvidence.DIGESTS);scope.put("targetEntityId",source.plan().target().entityId());scope.put("targetMetadataSha256",hash(bridge.targetMetadata(run)));scope.put("sourceProtocolTrafficRelabeled",false);
        if(mode.equals("preflight")){save(output,scope);return;}
        if(mode.equals("snapshot")){
            save(folder.resolve("destination-store.json"),KeycloakPersistentIdentifierEvidence.stable(destination.snapshot()));save(folder.resolve("destination-history.json"),destinationStore.history(run,destHistory,bridge::content));save(folder.resolve("source-stores.json"),sourceSnapshots);save(folder.resolve("source-history.json"),sourceStores.firstEntry().getValue().history(sourceRun,sourceHistory,bridge::content));save(output,scope);return;
        }
        if(mode.equals("state")||mode.equals("transition")){
            var state=new TreeMap<String,Object>();state.put("runId",run);state.put("sourceStores",sourceSnapshots);state.put("sourceHistory",sourceStores.firstEntry().getValue().history(sourceRun,sourceHistory,bridge::content));state.put("destinationStore",KeycloakPersistentIdentifierEvidence.stable(destination.snapshot()));state.put("destinationHistory",destinationStore.history(run,destHistory,bridge::content));var cases=new TreeMap<String,Object>();
            try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT case_id,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")){
                q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()){String id=rows.getString(1),raw=rows.getString(2);var execution=M.readValue(raw,CaseExecution.class);require(run.equals(execution.runId())&&id.equals(execution.caseId()),"Foreign execution");var row=new TreeMap<String,Object>();row.put("documentSha256",hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                    if(id.equals(KeycloakCaseCollisionCapabilityEvidence.CASE)){row.put("runId",run);row.put("caseId",id);row.put("revision",execution.revision());row.put("status",execution.status());row.put("updatedAt",execution.updatedAt());row.put("stateSha256",hash(M.writeValueAsBytes(execution.state())));row.put("waitSha256",hash(M.writeValueAsBytes(execution.waitCondition())));row.put("outcome",execution.outcome());row.put("verdict",execution.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,execution.outcome()));
                        if(mode.equals("transition")){var stateData=new LinkedHashMap<String,Object>(execution.state().data());Object audit=stateData.remove("previous_recorded_evidence_result");require(audit instanceof Map<?,?>&&execution.outcome()!=null&&M.valueToTree(audit).equals(M.valueToTree(execution.outcome().details().get("previous_recorded_evidence_result"))),"Prior audit differs");row.put("stateWithoutPriorAuditSha256",hash(M.writeValueAsBytes(new CaseState(execution.state().phase(),stateData))));row.put("stateAuditEqualsOutcomeAudit",true);row.put("priorResultAudit",audit);}}
                    cases.put(id,row);
                }}
            }state.put("cases",cases);save(output,state);return;
        }
        require(mode.equals("replay"),"Unsupported verifier mode");Path temporary=Files.createTempDirectory("kc-case-policy-controls-");Path copy=temporary.resolve(run+".keycloak-case-policy");
        try{
            try(var paths=Files.walk(folder)){for(var from:paths.toList()){require(!Files.isSymbolicLink(from),"Original symlink");Path to=copy.resolve(folder.relativize(from));if(Files.isDirectory(from))Files.createDirectories(to);else Files.copy(from,to);}}
            var reader=new KeycloakCaseCollisionCapabilityEvidence(temporary,data,folder.resolveSibling("source-native"),bridge::content,bridge::targetMetadata);
            var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(Set.of(run,sourceRun).contains(id),"Foreign Run requested");return id.equals(run)?destHistory:sourceHistory;}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No sends");}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}};
            var context=new DefaultCaseContext(run,destination.plan().profile().role(),Clock.systemUTC(),destination.plan().parameters(),destination.plan().interaction(),destination.run().targetToSuiteReachability(),recorder,true);
            var original=reader.read(context).orElseThrow();require(original.outcome()==Outcome.SATISFIED,"Native case-policy did not qualify: "+original);require(Evaluator.toVerdict(Rfc2119Level.MUST,original)==Verdict.PASS,"Central verdict differs");
            var originals=new TreeMap<String,byte[]>();try(var paths=Files.walk(copy)){for(var file:paths.filter(Files::isRegularFile).toList())originals.put(copy.relativize(file).toString(),Files.readAllBytes(file));}
            var controls=new LinkedHashMap<String,String>();for(String name:List.of("wrong-recipient","wrong-source","wrong-case-digest","wrong-recipient-store","wrong-source-store","wrong-source-history","wrong-epoch-image","wrong-native-epoch-original","changed-jre-bytecode","changed-native-diagnostic","native-control-as-product-failure","changed-native-helper","symlink-original")){
                restore(copy,originals);switch(name){
                    case "wrong-recipient"->edit(copy,"manifest.json",m->((ObjectNode)m).put("runId",sourceRun));
                    case "wrong-source"->edit(copy,"manifest.json",m->((ObjectNode)m).put("sourceRunId",run));
                    case "wrong-case-digest"->edit(copy,"manifest.json",m->((ObjectNode)m).put("caseDigest","sha256:"+"0".repeat(64)));
                    case "wrong-recipient-store"->edit(copy,"destination-store.json",m->((ObjectNode)m).put("planDocumentSha256","0".repeat(64)));
                    case "wrong-source-store"->edit(copy,"source-stores.json",m->((ObjectNode)m.path(KeycloakPersistentIdentifierEvidence.DIGESTS.keySet().iterator().next())).put("planDocumentSha256","0".repeat(64)));
                    case "wrong-source-history"->edit(copy,"source-history.json",m->((ObjectNode)m.get(0)).put("entrySha256","0".repeat(64)));
                    case "wrong-epoch-image"->edit(copy,"recipient-native-epoch.json",m->((ObjectNode)m.path("runtime")).put("image","sha256:"+"0".repeat(64)));
                    case "wrong-native-epoch-original"->edit(copy,"recipient-native-epoch-record.json",m->((ObjectNode)m).put("runId",sourceRun));
                    case "changed-jre-bytecode"->{String f="native-jre-classes/java/lang/Long.class";byte[] bytes=Files.readAllBytes(copy.resolve(f));bytes[100]^=1;Files.write(copy.resolve(f),bytes);rehash(copy,f);}
                    case "changed-native-diagnostic"->{String f="compact.stdout.txt";Files.writeString(copy.resolve(f),Files.readString(copy.resolve(f)).replace("tableRestored=true","tableRestored=false"));rehash(copy,f);}
                    case "native-control-as-product-failure"->{String f="compact.stdout.txt";Files.writeString(copy.resolve(f),Files.readString(copy.resolve(f)).replace("productFailureClaimed=false","productFailureClaimed=true"));rehash(copy,f);}
                    case "changed-native-helper"->{Files.writeString(copy.resolve("native-formatter-helper.java"),"other");rehash(copy,"native-formatter-helper.java");}
                    case "symlink-original"->{Files.delete(copy.resolve("compact.stdout.txt"));Files.createSymbolicLink(copy.resolve("compact.stdout.txt"),folder.resolve("compact.stdout.txt"));}
                }
                var changed=reader.read(context).orElseThrow();require(changed.outcome()==Outcome.NOT_VERIFIED,"Changed proof accepted: "+name);controls.put(name,changed.outcome().name());
            }restore(copy,originals);save(output,Map.of("runId",run,"sourceRunId",sourceRun,"productionOutcome",original,"negativeControls",controls,"sourceOriginalsChanged",false,"productSettingWrites",0,"protocolSubmissions",0));
        }finally{try(var paths=Files.walk(temporary)){for(var file:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}
    }
    private static void edit(Path folder,String name,java.util.function.Consumer<JsonNode> mutation)throws Exception{var m=M.readTree(folder.resolve(name).toFile());mutation.accept(m);save(folder.resolve(name),m);if(!name.equals("manifest.json"))rehash(folder,name);}
    private static void rehash(Path folder,String name)throws Exception{var m=(ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());String digest=hash(Files.readAllBytes(folder.resolve(name)));((ObjectNode)m.path("files")).put(name,digest);
        if(name.endsWith(".stdout.txt")||name.endsWith(".stderr.txt")){var process=M.readTree(folder.resolve("native-formatter-process.json").toFile());for(var op:process.path("operations")){if(name.equals(op.path("stdoutFile").asText()))((ObjectNode)op).put("stdoutSha256",digest);if(name.equals(op.path("stderrFile").asText()))((ObjectNode)op).put("stderrSha256",digest);}save(folder.resolve("native-formatter-process.json"),process);((ObjectNode)m.path("files")).put("native-formatter-process.json",hash(Files.readAllBytes(folder.resolve("native-formatter-process.json"))));}
        save(folder.resolve("manifest.json"),m);}
    private static void restore(Path folder,Map<String,byte[]> values)throws Exception{for(var row:values.entrySet()){Path file=folder.resolve(row.getKey());if(Files.isSymbolicLink(file)||!Files.exists(file,LinkOption.NOFOLLOW_LINKS)||!Arrays.equals(Files.readAllBytes(file),row.getValue())){Files.deleteIfExists(file);Files.write(file,row.getValue());}}}
    private static List<TranscriptEntry> entries(Path data,String run)throws Exception{var result=new ArrayList<TranscriptEntry>();try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()){require(result.size()<10_000,"History limit exceeded");result.add(M.readValue(rows.getString(1),TranscriptEntry.class));}}}return List.copyOf(result);}
}
