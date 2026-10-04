package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;

/** Read-only stored identity, complete originals and fresh production-reader replay; never target traffic. */
public final class VerifyKeycloakPersistentIdentifier {
    private static final ObjectMapper M=new JsonCodec().mapper();
    private static final String SCHEMA="samlscope-keycloak-persistent-identifier-stored-v1";
    private static void require(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    public static void main(String[] args)throws Exception {
        if(args.length==3&&"offline".equals(args[0])){
            var state=M.readTree(Path.of(args[1]).toFile());require(SCHEMA.equals(state.path("schema").asText()),"Foreign stored schema");
            require(state.path("runId").asText().matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Foreign stored Run");
            require(state.path("cases").isObject()&&state.path("cases").size()==2,"Missing approved cases");
            for(String id:KeycloakPersistentIdentifierEvidence.DIGESTS.keySet()){
                var row=(ObjectNode)state.path("cases").path(id);require(id.equals(row.path("caseId").asText())&&row.path("runId").equals(state.path("runId")),"Foreign stored case");
                if(!row.path("outcome").isNull())row.put("verdict",Evaluator.toVerdict(Rfc2119Level.MUST,M.treeToValue(row.path("outcome"),CaseOutcome.class)).name());else row.putNull("verdict");
            }
            Files.write(Path.of(args[2]),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(state));return;
        }
        require(args.length==5&&Set.of("snapshot","state","transition","replay").contains(args[0]),"Expected mode,data,run,source,output");
        String mode=args[0],run=args[2];require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid Run identifier");
        Path data=Path.of(args[1]).toAbsolutePath().normalize(),source=Path.of(args[3]).toAbsolutePath().normalize(),output=Path.of(args[4]);
        var stores=new TreeMap<String,DefaultAlgorithmSourceRunStore>();
        KeycloakPersistentIdentifierEvidence.DIGESTS.forEach((id,digest)->stores.put(id,new DefaultAlgorithmSourceRunStore(data,id,digest)));
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var history=entries(data,run);
        var bindings=new TreeMap<String,DefaultAlgorithmSourceRunStore.Binding>();for(var entry:stores.entrySet())bindings.put(entry.getKey(),entry.getValue().execution(run));
        var snapshots=new TreeMap<String,JsonNode>();for(var entry:bindings.entrySet())snapshots.put(entry.getKey(),KeycloakPersistentIdentifierEvidence.stable(entry.getValue().snapshot()));
        var historySnapshot=stores.firstEntry().getValue().history(run,history,bridge::content);
        if("snapshot".equals(mode)){
            for(var entry:snapshots.entrySet())Files.write(source.resolve("source-store-"+entry.getKey()+".json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(entry.getValue()));
            Files.write(source.resolve("source-history.json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(historySnapshot));
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("approvedMembershipVerified",true,"runId",run,"caseDigests",KeycloakPersistentIdentifierEvidence.DIGESTS,"entries",history.size(),"productSettingWrites",0,"protocolSubmissions",0)));return;
        }
        if("state".equals(mode)||"transition".equals(mode)){
            var state=new TreeMap<String,Object>();state.put("schema",SCHEMA);state.put("runId",run);state.put("sourceStores",snapshots);state.put("sourceHistory",historySnapshot);
            var executions=new TreeMap<String,String>();var selected=new TreeMap<String,Object>();
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var statement=connection.prepareStatement("SELECT case_id,revision,status,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")){
                statement.setString(1,run);try(var rows=statement.executeQuery()){while(rows.next()){
                    String id=rows.getString(1),raw=rows.getString(4);var execution=M.readValue(raw,CaseExecution.class);
                    require(run.equals(execution.runId())&&id.equals(execution.caseId())&&execution.revision()==rows.getLong(2)&&execution.status().name().equals(rows.getString(3))&&executions.put(id,hash(raw.getBytes(StandardCharsets.UTF_8)))==null,"Foreign stored execution");
                    if(stores.containsKey(id)){
                        var row=new TreeMap<String,Object>();row.put("runId",run);row.put("caseId",id);row.put("caseDigest",KeycloakPersistentIdentifierEvidence.DIGESTS.get(id));row.put("status",execution.status().name());row.put("revision",execution.revision());row.put("updatedAt",execution.updatedAt().toString());
                        row.put("stateSha256",hash(M.writeValueAsBytes(execution.state())));row.put("waitSha256",hash(M.writeValueAsBytes(execution.waitCondition())));row.put("documentSha256",hash(raw.getBytes(StandardCharsets.UTF_8)));row.put("outcome",execution.outcome());
                        row.put("verdict",execution.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,execution.outcome()).name());
                        if("transition".equals(mode)){
                            var withoutAudit=new LinkedHashMap<String,Object>(execution.state().data());Object audit=withoutAudit.remove("previous_recorded_evidence_result");
                            require(audit instanceof Map<?,?>&&execution.outcome()!=null&&M.valueToTree(audit).equals(M.valueToTree(execution.outcome().details().get("previous_recorded_evidence_result"))),"Central state/outcome audit differs");
                            row.put("stateWithoutPriorAuditSha256",hash(M.writeValueAsBytes(new CaseState(execution.state().phase(),withoutAudit))));row.put("stateAuditEqualsOutcomeAudit",true);row.put("priorResultAudit",audit);
                        }
                        selected.put(id,row);
                    }
                }}
            }
            require(selected.keySet().equals(stores.keySet()),"Missing approved stored cases");state.put("cases",selected);state.put("executions",executions);
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(state));return;
        }
        Path root=Files.createTempDirectory("kc-persistent-reader-controls-");Path folder=root.resolve(run+".keycloak-native-identifier");
        try{
            require(Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(source),"Unsafe source folder");
            try(var paths=Files.walk(source)){for(var from:paths.toList()){
                require(!Files.isSymbolicLink(from),"Source original symlink");var target=folder.resolve(source.relativize(from));
                if(Files.isDirectory(from,LinkOption.NOFOLLOW_LINKS))Files.createDirectories(target);else{require(Files.isRegularFile(from,LinkOption.NOFOLLOW_LINKS)&&Files.size(from)<=67_108_864,"Unsafe original");Files.copy(from,target);}
            }}
            var originals=new TreeMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var file:paths.filter(Files::isRegularFile).toList())originals.put(folder.relativize(file).toString(),Files.readAllBytes(file));}
            var outcomes=new TreeMap<String,CaseOutcome>();var controls=new TreeMap<String,String>();
            for(String id:stores.keySet()){
                var context=bindings.get(id).context(Clock.systemUTC(),history);var reader=new KeycloakPersistentIdentifierEvidence(root,bridge::content,bridge::targetMetadata,stores);
                var baseline=reader.read(context,id).orElseThrow();require(baseline.outcome()==Outcome.SATISFIED&&Evaluator.toVerdict(Rfc2119Level.MUST,baseline)==Verdict.PASS,"Original persistent native proof did not qualify: "+id+" "+baseline);outcomes.put(id,baseline);
                var options=new org.yaml.snakeyaml.LoaderOptions();options.setAllowDuplicateKeys(false);options.setMaxAliasesForCollections(1_000);options.setCodePointLimit(16_777_216);
                com.samlscope.core.casedef.CaseDefinitionCatalog definitions;
                try(var catalog=VerifyKeycloakPersistentIdentifier.class.getResourceAsStream("/catalog/tests/cases.yaml")){
                    require(catalog!=null,"Installed approved catalog unavailable");
                    definitions=com.samlscope.core.casedef.CaseDefinitionCatalogMapper.fromDocument(new org.yaml.snakeyaml.Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor(options)).load(catalog));
                }
                var fallback=ApprovedAttestedCaseRegistry.create(definitions,com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1).require(id);
                var wrapper=new NativePersistentIdentifierEvidenceTestCase(fallback,reader);
                require(((CaseStep.Finish)wrapper.start(context)).outcome().equals(baseline)&&wrapper.evidenceStatus(context).ready()&&wrapper.queuedEvidenceOutcome(context).equals(baseline)
                    &&wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(baseline),"Production wrapper path unavailable");
                var results=new LinkedHashMap<String,String>();
                for(String name:List.of("foreign-run","foreign-plan","foreign-case-digest","foreign-source-store","foreign-history","helper-changed","classpath-subset","metadata-changed","missing-signed-original","symlink-signed-original","seeded-construction-claim","forged-saved-attribute-trace","diagnostic-as-construction","diagnostic-as-saved-original")){
                    restore(folder,originals);
                    switch(name){
                        case "foreign-run"->edit(folder,"manifest.json",node->((ObjectNode)node).put("runId","run_00000000000000000000000000"));
                        case "foreign-plan"->edit(folder,"manifest.json",node->((ObjectNode)node).put("planId","plan_00000000000000000000000000"));
                        case "foreign-case-digest"->edit(folder,"manifest.json",node->((ObjectNode)node.path("caseDigests")).put(id,"sha256:"+"0".repeat(64)));
                        case "foreign-source-store"->edit(folder,"source-store-"+id+".json",node->((ObjectNode)node).put("planDocumentSha256","0".repeat(64)));
                        case "foreign-history"->edit(folder,"source-history.json",node->((ObjectNode)node.get(0)).put("entrySha256","0".repeat(64)));
                        case "helper-changed"->replace(folder,"native-helper.java","class Forged {}".getBytes(StandardCharsets.UTF_8));
                        case "classpath-subset"->replace(folder,"originals/before.native-classpath.txt","subset".getBytes(StandardCharsets.UTF_8));
                        case "metadata-changed"->replace(folder,"target-metadata.xml","<EntityDescriptor/>".getBytes(StandardCharsets.UTF_8));
                        case "missing-signed-original"->Files.delete(folder.resolve("normal-response.xml"));
                        case "symlink-signed-original"->{Files.delete(folder.resolve("normal-response.xml"));Files.createSymbolicLink(folder.resolve("normal-response.xml"),source.resolve("normal-response.xml"));}
                        case "seeded-construction-claim"->edit(folder,"native-helper-replay.json",node->((ObjectNode)node).put("randomnessSeededOrReplaced",true));
                        case "forged-saved-attribute-trace"->edit(folder,"native-helper-replay.json",node->((ObjectNode)node.path("traces").get(1)).put("nativeValue","G-00000000-0000-4000-8000-000000000000"));
                        case "diagnostic-as-construction"->edit(folder,"native-helper-replay.json",node->((com.fasterxml.jackson.databind.node.ArrayNode)node.path("traces")).set(0,node.path("traces").get(2).deepCopy()));
                        case "diagnostic-as-saved-original"->edit(folder,"native-helper-replay.json",node->((com.fasterxml.jackson.databind.node.ArrayNode)node.path("traces")).set(1,node.path("traces").get(2).deepCopy()));
                    }
                    var changed=reader.read(context,id).orElseThrow();require(changed.outcome()==Outcome.NOT_VERIFIED,"Altered proof accepted: "+id+" "+name);results.put(name,changed.outcome().name());
                }
                restore(folder,originals);results.forEach((name,value)->controls.put(id+"/"+name,value));
            }
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("schema","samlscope-keycloak-persistent-identifier-replay-v1","runId",run,"caseDigests",KeycloakPersistentIdentifierEvidence.DIGESTS,"productionOutcomes",outcomes,"negativeControls",controls,"productionWrapperVerified",true,"sourceOriginalsChanged",false,"productSettingWrites",0,"protocolSubmissions",0)));
        }finally{try(var paths=Files.walk(root)){for(var file:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}}
    }
    private static void restore(Path folder,Map<String,byte[]> originals)throws Exception{for(var row:originals.entrySet()){
        var file=folder.resolve(row.getKey());if(Files.isSymbolicLink(file)||!Files.exists(file,LinkOption.NOFOLLOW_LINKS)||!Arrays.equals(Files.readAllBytes(file),row.getValue())){Files.deleteIfExists(file);Files.write(file,row.getValue());}
    }}
    private static void replace(Path folder,String name,byte[] value)throws Exception{Files.write(folder.resolve(name),value);rehash(folder,name);}
    private static void edit(Path folder,String name,java.util.function.Consumer<JsonNode> mutate)throws Exception{var value=M.readTree(folder.resolve(name).toFile());mutate.accept(value);Files.write(folder.resolve(name),M.writeValueAsBytes(value));if(!"manifest.json".equals(name))rehash(folder,name);}
    private static void rehash(Path folder,String name)throws Exception{var manifest=(ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));}
    private static List<TranscriptEntry> entries(Path data,String run)throws Exception{var entries=new ArrayList<TranscriptEntry>();var codec=new JsonCodec();
        try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var statement=connection.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){
            statement.setString(1,run);try(var rows=statement.executeQuery()){while(rows.next()){require(entries.size()<10_000,"History exceeds bounded reader");var entry=codec.read(rows.getString(1),TranscriptEntry.class);require(run.equals(entry.runId()),"Foreign history entry");entries.add(entry);}}
        }return List.copyOf(entries);
    }
}
