package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

/** Fresh read-only historical Store proof. Archive origins never claim installed runtime authority. */
public final class ReadArchivedNativeConfigurationSourceState {
    private static final ObjectMapper JSON=new JsonCodec().mapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final String CASE=SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE;
    private static final String DIGEST=SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST;
    private static final Map<String,String> CLASSES=Map.of(
            "runner","com.samlscope.runner.cases.NativeConfigurationSourceRunEvidence",
            "core","com.samlscope.core.evaluation.Evaluator","saml","com.samlscope.saml.normal.SecureXml",
            "store","com.samlscope.store.JsonCodec","api","com.samlscope.api.SamlScopeApplication",
            "peer","com.samlscope.peer.sp.SpPeerService");
    private static void require(boolean condition,String message) {
        if(!condition)throw new IllegalArgumentException(message);
    }
    private static String hash(byte[] raw)throws Exception{return NativeConfigurationSourceRunEvidence.hash(raw);}
    private static void safeParents(Path path) {
        for(Path p=path.toAbsolutePath();p!=null;p=p.getParent())
            require(!Files.isSymbolicLink(p),"Symlink in archive/Store path");
    }
    public static void main(String[] args)throws Exception {
        require(args.length==7,"Expected data,recipient,source,sourceReceipt,binding,archiveAuthority,output");
        Path data=Path.of(args[0]).toAbsolutePath().normalize(), sourceFolder=Path.of(args[3]).toAbsolutePath().normalize(),
                binding=Path.of(args[4]).toAbsolutePath().normalize(), authority=Path.of(args[5]).toAbsolutePath().normalize(),
                output=Path.of(args[6]).toAbsolutePath().normalize();
        String recipient=args[1],source=args[2];
        require(recipient.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&source.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                &&!recipient.equals(source),"Foreign source/recipient scope");
        require(sourceFolder.getFileName().toString().equals(source+SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX)
                &&binding.getFileName().toString().equals(recipient),"Foreign original folder");
        safeParents(authority);require(Files.isRegularFile(authority,LinkOption.NOFOLLOW_LINKS)
                &&Files.size(authority)<=65536,"Invalid archive authority original");
        var pins=JSON.readTree(Files.readAllBytes(authority));
        var before=origins(pins);
        safeParents(data.resolve("samlscope.db"));
        var store=new DefaultAlgorithmSourceRunStore(data,CASE,DIGEST);
        var src=store.planned(source);var dest=store.execution(recipient);
        var bridge=new KeycloakNativeRunEvidenceBridge(data);
        var reader=new NativeConfigurationSourceRunEvidence(data,binding.getParent(),sourceFolder.getParent(),bridge::content,bridge::targetMetadata);
        var fence=reader.fence(src,dest,entries(data,source),entries(data,recipient));
        var e=execution(data,recipient);
        var state=new TreeMap<String,Object>();
        state.put("schema","samlscope-independent-configuration-source-state-v1");
        state.put("sourceRunId",source);state.put("recipientRunId",recipient);state.put("fence",fence);
        state.put("executions",executions(data,recipient));state.put("sourceExecutions",executions(data,source));
        state.put("caseExecution",e);state.put("verdict",e.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,e.outcome()));
        state.put("caseUpdatedAt",e.updatedAt().toString());
        state.put("caseStateSha256",hash(JSON.writeValueAsBytes(e.state())));
        state.put("caseWaitSha256",hash(JSON.writeValueAsBytes(e.waitCondition())));
        state.put("caseDocumentSha256",executions(data,recipient).get(CASE));
        require(before.equals(origins(pins)),"Archive changed during Store proof");
        var result=new TreeMap<String,Object>();result.put("schema","samlscope-archived-native-configuration-state-v1");
        result.put("authority","qualified-historical-project-archive");result.put("installedRuntimeClaimed",false);
        result.put("archivedModuleCodeSources",before);result.put("storedState",state);result.put("targetOperations",0);
        safeParents(output);require(!Files.exists(output,LinkOption.NOFOLLOW_LINKS),"Immutable output already exists");
        Files.write(output,JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(result),StandardOpenOption.CREATE_NEW);
    }
    private static Map<String,Object> origins(JsonNode authority)throws Exception {
        require("samlscope-archived-native-configuration-authority-v1".equals(authority.path("schema").asText()),"Foreign archive authority");
        Path root=Path.of(authority.path("archiveRoot").asText()).toAbsolutePath().normalize();
        require(root.toString().matches("/tmp/ssp-config-source-archive-state-[0-9a-f]{24}"),"Foreign archive root");
        var modules=authority.path("modules");var keys=new HashSet<String>();modules.fieldNames().forEachRemaining(keys::add);
        require(modules.isObject()&&keys.equals(CLASSES.keySet()),"Archive module set differs");
        var result=new TreeMap<String,Object>();
        for(var entry:CLASSES.entrySet()) {
            String expected=modules.path(entry.getKey()).asText();require(expected.matches("[0-9a-f]{64}"),"Invalid archive byte pin");
            var type=Class.forName(entry.getValue(),false,ReadArchivedNativeConfigurationSourceState.class.getClassLoader());
            Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toAbsolutePath().normalize();
            safeParents(actual);require(actual.equals(root.resolve(entry.getKey()+"-0.1.0.jar"))
                    &&Files.isRegularFile(actual,LinkOption.NOFOLLOW_LINKS),"Class escaped qualified archive");
            String observed=hash(Files.readAllBytes(actual));require(expected.equals(observed),"Archived class/JAR bytes differ");
            result.put(entry.getKey(),Map.of("class",entry.getValue(),"path",actual.toString(),"sha256",observed));
        }
        return result;
    }
    private static Connection connection(Path data)throws Exception {
        var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
        try(var statement=c.createStatement()){statement.execute("PRAGMA query_only=ON");}return c;
    }
    private static List<TranscriptEntry> entries(Path data,String run)throws Exception {
        var values=new ArrayList<TranscriptEntry>();var ids=new HashSet<String>();
        try(var c=connection(data);var q=c.prepareStatement("SELECT id,run_id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")) {
            q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()) {
                require(values.size()<10000,"Original history overflow");var entry=JSON.readValue(rows.getString(3),TranscriptEntry.class);
                require(run.equals(rows.getString(2))&&run.equals(entry.runId())&&entry.id().equals(rows.getString(1))
                        &&ids.add(entry.id()),"Foreign/duplicate original row");values.add(entry);
            }}
        }return List.copyOf(values);
    }
    private static CaseExecution execution(Path data,String run)throws Exception {
        try(var c=connection(data);var q=c.prepareStatement("SELECT revision,status,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
            q.setString(1,run);q.setString(2,CASE);try(var rows=q.executeQuery()) {
                require(rows.next(),"Actual recipient execution missing");var e=JSON.readValue(rows.getString(3),CaseExecution.class);
                require(run.equals(e.runId())&&CASE.equals(e.caseId())&&e.revision()==rows.getLong(1)
                        &&e.status().name().equals(rows.getString(2))&&!rows.next(),"Foreign/duplicate actual execution");return e;
            }
        }
    }
    private static Map<String,String> executions(Path data,String run)throws Exception {
        var result=new TreeMap<String,String>();
        try(var c=connection(data);var q=c.prepareStatement("SELECT case_id,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")) {
            q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()) {
                require(result.size()<10000&&result.put(rows.getString(1),hash(rows.getString(2).getBytes(StandardCharsets.UTF_8)))==null,
                        "Duplicate/overflow actual execution");
            }}
        }return result;
    }
}
