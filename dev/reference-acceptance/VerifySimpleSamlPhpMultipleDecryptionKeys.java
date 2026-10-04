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
public final class VerifySimpleSamlPhpMultipleDecryptionKeys {
    private static final Map<String,String> DIGESTS=Map.of(SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE,SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST);
    private static final ObjectMapper M=new JsonCodec().mapper();
    private static final String SCHEMA="samlscope-simplesamlphp-multiple-decryption-keys-stored-v1";
    private static void require(boolean condition,String reason){if(!condition)throw new IllegalArgumentException(reason);}
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    public static void main(String[] args)throws Exception {
        if(args.length==3&&"offline".equals(args[0])){
            var state=M.readTree(Path.of(args[1]).toFile());require(SCHEMA.equals(state.path("schema").asText()),"Foreign stored schema");
            require(state.path("runId").asText().matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Foreign stored Run");
            require(state.path("cases").isObject()&&state.path("cases").size()==1,"Missing approved cases");
            for(String id:DIGESTS.keySet()){
                var row=(ObjectNode)state.path("cases").path(id);require(id.equals(row.path("caseId").asText())&&row.path("runId").equals(state.path("runId")),"Foreign stored case");
                if(!row.path("outcome").isNull())row.put("verdict",Evaluator.toVerdict(Rfc2119Level.MUST,M.treeToValue(row.path("outcome"),CaseOutcome.class)).name());else row.putNull("verdict");
            }
            Files.write(Path.of(args[2]),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(state));return;
        }
        require(args.length==5&&Set.of("native","snapshot","state","transition","replay").contains(args[0]),"Expected mode,data,run,source,output");
        String mode=args[0],run=args[2];require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid Run identifier");
        Path data=Path.of(args[1]).toAbsolutePath().normalize(),source=Path.of(args[3]).toAbsolutePath().normalize(),output=Path.of(args[4]);
        var stores=new TreeMap<String,DefaultAlgorithmSourceRunStore>();
        DIGESTS.forEach((id,digest)->stores.put(id,new DefaultAlgorithmSourceRunStore(data,id,digest)));
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var history=entries(data,run);
        if("native".equals(mode)){
            var binding=stores.firstEntry().getValue().planned(run);require("http://localhost:18380/idp".equals(binding.plan().target().entityId()),"Foreign actual target");
            var reader=new SimpleSamlPhpMultipleDecryptionKeysEvidence(source.getParent(),bridge::content,bridge::targetMetadata,stores.firstEntry().getValue());
            var files=M.createObjectNode();try(var paths=Files.walk(source)){for(var path:paths.filter(Files::isRegularFile).toList())files.put(source.relativize(path).toString(),hash(Files.readAllBytes(path)));}
            var input=M.readTree(source.resolve("native-input.json").toFile());var operations=M.readTree(source.resolve("operations.json").toFile());String helper=null;
            for(var op:operations)if("native-helper-write".equals(op.path("label").asText()))helper=op.path("command").get(op.path("command").size()-1).asText();require(helper!=null,"Missing helper write");
            var manifest=M.createObjectNode();manifest.put("newPrivateKeyPath",helper.substring(0,helper.length()-4)+".key.pem");manifest.put("newCertificatePath",helper.substring(0,helper.length()-4)+".cert.pem");
            var method=SimpleSamlPhpMultipleDecryptionKeysEvidence.class.getDeclaredMethod("validateObservation",Path.class,JsonNode.class,JsonNode.class,JsonNode.class,JsonNode.class);method.setAccessible(true);
            var signed=SimpleSamlPhpMultipleDecryptionKeysEvidence.class.getDeclaredMethod("signedObservation",Path.class,JsonNode.class,String.class,int.class);signed.setAccessible(true);
            for(String phase:List.of("before","after")){
                var report=M.readTree(source.resolve("native-"+phase+".json").toFile());require(report.equals(signed.invoke(reader,source,files,"native-"+phase+".stdout",2)),"Signed original mismatch");
                method.invoke(reader,source,files,report,input,manifest);
            }
            require(signed.invoke(reader,source,files,"native-restored.stdout",1).equals(M.readTree(source.resolve("native-restored.json").toFile())),"Signed restoration mismatch");
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"approvedPlannedMembershipVerified",true,"nativeObservationControlsVerified",true,"nativeOraclePositive","SATISFIED","sourceClosedRemovalControl","VIOLATED","fullProductionReaderQualified",false,"formalCaseExecutionRequired",true,"targetOperations",0)));return;
        }

        var bindings=new TreeMap<String,DefaultAlgorithmSourceRunStore.Binding>();for(var entry:stores.entrySet())bindings.put(entry.getKey(),entry.getValue().execution(run));
        var snapshots=new TreeMap<String,JsonNode>();for(var entry:bindings.entrySet())snapshots.put(entry.getKey(),SimpleSamlPhpMultipleDecryptionKeysEvidence.stable(entry.getValue().snapshot()));
        var historySnapshot=stores.firstEntry().getValue().history(run,history,bridge::content);
        if("snapshot".equals(mode)){
            for(var entry:snapshots.entrySet())Files.write(source.resolve("source-store.json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(entry.getValue()));
            Files.write(source.resolve("source-history.json"),M.writerWithDefaultPrettyPrinter().writeValueAsBytes(historySnapshot));
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("approvedMembershipVerified",true,"runId",run,"caseDigests",DIGESTS,"entries",history.size(),"productSettingWrites",0,"protocolSubmissions",0)));return;
        }
        if("state".equals(mode)||"transition".equals(mode)){
            var state=new TreeMap<String,Object>();state.put("schema",SCHEMA);state.put("runId",run);state.put("sourceStores",snapshots);state.put("sourceHistory",historySnapshot);
            var executions=new TreeMap<String,String>();var selected=new TreeMap<String,Object>();
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var statement=connection.prepareStatement("SELECT case_id,revision,status,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")){
                statement.setString(1,run);try(var rows=statement.executeQuery()){while(rows.next()){
                    String id=rows.getString(1),raw=rows.getString(4);var execution=M.readValue(raw,CaseExecution.class);
                    require(run.equals(execution.runId())&&id.equals(execution.caseId())&&execution.revision()==rows.getLong(2)&&execution.status().name().equals(rows.getString(3))&&executions.put(id,hash(raw.getBytes(StandardCharsets.UTF_8)))==null,"Foreign stored execution");
                    if(stores.containsKey(id)){
                        var row=new TreeMap<String,Object>();row.put("runId",run);row.put("caseId",id);row.put("caseDigest",DIGESTS.get(id));row.put("status",execution.status().name());row.put("revision",execution.revision());row.put("updatedAt",execution.updatedAt().toString());
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
        Path root=Files.createTempDirectory("ssp-keys-reader-controls-");Path folder=root.resolve(run+SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX);
        try{
            require(Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS)&&!Files.isSymbolicLink(source),"Unsafe source folder");
            try(var paths=Files.walk(source)){for(var from:paths.toList()){
                require(!Files.isSymbolicLink(from),"Source original symlink");var target=folder.resolve(source.relativize(from));
                if(Files.isDirectory(from,LinkOption.NOFOLLOW_LINKS))Files.createDirectories(target);else{require(Files.isRegularFile(from,LinkOption.NOFOLLOW_LINKS)&&Files.size(from)<=67_108_864,"Unsafe original");Files.copy(from,target);}
            }}
            var originals=new TreeMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var file:paths.filter(Files::isRegularFile).toList())originals.put(folder.relativize(file).toString(),Files.readAllBytes(file));}
            var outcomes=new TreeMap<String,CaseOutcome>();var controls=new TreeMap<String,String>();
            for(String id:stores.keySet()){
                var context=bindings.get(id).context(Clock.systemUTC(),history);var reader=new SimpleSamlPhpMultipleDecryptionKeysEvidence(root,bridge::content,bridge::targetMetadata,stores.get(id));
                var baseline=reader.read(context).orElseThrow();require(baseline.outcome()==Outcome.SATISFIED&&Evaluator.toVerdict(Rfc2119Level.MUST,baseline)==Verdict.PASS,"Original native CONFIG proof did not qualify: "+id+" "+baseline);outcomes.put(id,baseline);
                var options=new org.yaml.snakeyaml.LoaderOptions();options.setAllowDuplicateKeys(false);options.setMaxAliasesForCollections(1_000);options.setCodePointLimit(16_777_216);
                com.samlscope.core.casedef.CaseDefinitionCatalog definitions;
                try(var catalog=VerifySimpleSamlPhpMultipleDecryptionKeys.class.getResourceAsStream("/catalog/tests/cases.yaml")){
                    require(catalog!=null,"Installed approved catalog unavailable");
                    definitions=com.samlscope.core.casedef.CaseDefinitionCatalogMapper.fromDocument(new org.yaml.snakeyaml.Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor(options)).load(catalog));
                }
                var original=ApprovedConfigCaseRegistry.create(definitions,com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3).require(id);
                var fallback=MultipleDecryptionKeysConfigurationTestCase.publishedOnly(original,
                    ignored->List.of(),(ignoredRun,ignoredCase)->Optional.empty());
                var wrapper=new NativeMultipleDecryptionKeysConfigurationTestCase(fallback,reader);
                require(((CaseStep.Finish)wrapper.start(context)).outcome().equals(baseline)&&wrapper.evidenceStatus(context).ready()
                    &&wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(baseline),"Production wrapper path unavailable");
                var results=new LinkedHashMap<String,String>();
                for(String name:List.of("foreign-run","foreign-case-digest","foreign-source-store","foreign-history","helper-changed","metadata-changed","missing-native-original","symlink-native-original","coherent-control","coherent-decrypt","coherent-settings","coherent-class","duplicate-signer","foreign-native-command","foreign-native-uid","restored-key-changed")){
                    restore(folder,originals);
                    switch(name){
                        case "foreign-run"->edit(folder,"manifest.json",node->((ObjectNode)node).put("runId","run_00000000000000000000000000"));
                        case "foreign-case-digest"->edit(folder,"manifest.json",node->((ObjectNode)node).put("caseDigest","sha256:"+"0".repeat(64)));
                        case "foreign-source-store"->edit(folder,"source-store.json",node->((ObjectNode)node).put("planDocumentSha256","0".repeat(64)));
                        case "foreign-history"->edit(folder,"source-history.json",node->((ObjectNode)node.get(0)).put("entrySha256","0".repeat(64)));
                        case "helper-changed"->replace(folder,"native-probe.php","<?php fake".getBytes(StandardCharsets.UTF_8));
                        case "metadata-changed"->replace(folder,"target-metadata.xml","<EntityDescriptor/>".getBytes(StandardCharsets.UTF_8));
                        case "missing-native-original"->Files.delete(folder.resolve("native-before.stdout"));
                        case "symlink-native-original"->{Files.delete(folder.resolve("native-before.stdout"));Files.createSymbolicLink(folder.resolve("native-before.stdout"),source.resolve("native-before.stdout"));}
                        case "coherent-control","coherent-decrypt","coherent-settings","coherent-class","foreign-native-uid"->{
                            var envelope=(ObjectNode)M.readTree(folder.resolve("native-before.stdout").toFile());var report=(ObjectNode)M.readTree(Base64.getDecoder().decode(envelope.path("payloadBase64").asText()));
                            if(name.equals("coherent-control"))((ObjectNode)report.path("control")).put("sourceSha256","0".repeat(64));
                            if(name.equals("coherent-decrypt"))((ObjectNode)report.path("decryptionControls").get(0).path("attempts").get(0)).put("decrypted",false);
                            if(name.equals("coherent-settings"))((ObjectNode)report.path("settingsSha256")).put("hosted","0".repeat(64));
                            if(name.equals("coherent-class"))((ObjectNode)report.path("loadedClasses").get(0)).put("sha256","0".repeat(64));
                            if(name.equals("foreign-native-uid"))report.put("effectiveUid",0);
                            byte[] raw=M.writeValueAsBytes(report);envelope.put("payloadBase64",Base64.getEncoder().encodeToString(raw));envelope.put("payloadSha256",hash(raw));
                            replace(folder,"native-before.stdout",M.writeValueAsBytes(envelope));replace(folder,"native-before.json",raw);
                            edit(folder,"operations.json",node->{for(var op:node)if("native-before".equals(op.path("label").asText())){try{((ObjectNode)op).put("stdoutSha256",hash(M.writeValueAsBytes(envelope)));}catch(Exception e){throw new IllegalArgumentException(e);}}});
                        }
                        case "duplicate-signer"->edit(folder,"native-before.stdout",node->{var rows=(com.fasterxml.jackson.databind.node.ArrayNode)node.path("signatures");var value=(ObjectNode)rows.get(0).deepCopy();value.put("keyIndex",1);rows.set(1,value);});
                        case "foreign-native-command"->edit(folder,"operations.json",node->{for(var op:node)if("native-before".equals(op.path("label").asText()))((com.fasterxml.jackson.databind.node.ArrayNode)op.path("command")).set(5,M.valueToTree("foreign-product"));});
                        case "restored-key-changed"->edit(folder,"native-restored.json",node->((ObjectNode)node.path("keys").get(0)).put("spkiSha256","0".repeat(64)));
                    }
                    var changed=reader.read(context).orElseThrow();require(changed.outcome()==Outcome.NOT_VERIFIED,"Altered proof accepted: "+id+" "+name);results.put(name,changed.outcome().name());
                }
                restore(folder,originals);results.forEach((name,value)->controls.put(id+"/"+name,value));
            }
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("schema","samlscope-simplesamlphp-multiple-decryption-keys-replay-v1","runId",run,"caseDigests",DIGESTS,"productionOutcomes",outcomes,"negativeControls",controls,"productionWrapperVerified",true,"sourceOriginalsChanged",false,"productSettingWrites",0,"protocolSubmissions",0)));
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
