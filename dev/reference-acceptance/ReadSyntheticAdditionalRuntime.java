package com.samlscope.api;

import com.samlscope.core.casedef.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

/** Bound synthetic qualification reads only: no migrations, transitions, cached outcomes or API calls. */
public final class ReadSyntheticAdditionalRuntime {
    static final int MAX_ORIGINAL=8*1024*1024;
    static final String CASE="IIP-MD05-a8-idp-01", DIGEST="sha256:64b57fc4a00042b2826b202abb00c6a62e4bcf36ea9b090d2d695fe30bce3973";
    public static void main(String[] args)throws Exception {
        if(args.length==1&&"--self-check".equals(args[0])){selfCheck();return;}
        if(args.length!=3||!args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}")||!Set.of("scope","runtime").contains(args[2]))throw new IllegalArgumentException("data root, bound Run, scope|runtime required");
        Path data=checkedRoot(Path.of(args[0]));var codec=new JsonCodec();var result=new LinkedHashMap<String,Object>();
        try(var db=openReadOnly(data)) {
            TestRun run=codec.read(single(db,"SELECT document_json FROM runs WHERE id=?",args[1]),TestRun.class);
            TestPlan plan=codec.read(single(db,"SELECT document_json FROM plans WHERE id=?",run.planId()),TestPlan.class);
            require(run.id().equals(args[1])&&run.planId().equals(plan.id())&&plan.profile()==FunctionalProfile.METADATA_IDP&&plan.target().kind()==TargetKind.IDP&&plan.definitionIdentity()!=null&&plan.name().startsWith("Synthetic runtime a8 "));
            var entity=java.net.URI.create(plan.target().entityId());require(Set.of("127.0.0.1","localhost","host.docker.internal").contains(entity.getHost())&&entity.getPath().equals("/entity"));
            var documents=CatalogDocuments.load();var releases=FunctionalProfileDocuments.load();
            var definitions=CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));var coverage=CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
            var resolver=new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(),releases.digests(),Map.of("tests/coverage.yaml",documents.bytes("tests/coverage.yaml"),"tests/cases.yaml",documents.bytes("tests/cases.yaml"),"tests/predicates.yaml",documents.bytes("tests/predicates.yaml")),definitions,coverage);
            var membership=resolver.resolve(plan.definitionIdentity()).cases();var selected=membership.stream().filter(c->CASE.equals(c.id())).toList();require(selected.size()==1);
            var slot=selected.getFirst();require(DIGEST.equals(slot.caseDigest())&&slot.role()==TargetRole.IDP&&slot.mode()==CaseDefinitionCatalog.ExecutionMode.CONFIG&&slot.milestone()==CaseDefinitionCatalog.Milestone.M2);
            require(Set.copyOf(slot.coversVariants()).equals(Set.of("IIP-MD05.a8#v-34181f3e0f","IIP-MD05.a8#v-37403b861f"))&&slot.controls().size()==2);
            result.put("schema","samlscope-synthetic-additional-runtime-v1");result.put("runId",run.id());result.put("planId",plan.id());result.put("profile",plan.profile().id());result.put("targetEntityId",plan.target().entityId());result.put("definitionIdentity",plan.definitionIdentity());result.put("approvedCase",slot);
            result.put("actualPinnedCaseIds",membership.stream().map(CaseDefinitionCatalog.CaseDefinition::id).toList());result.put("mode",args[2]);result.put("databaseAccess","read-only-query-only");result.put("productEvidenceAdoption",false);result.put("protocolSubmissionsByReader",0);
            var execution=optional(db,"SELECT document_json FROM case_executions WHERE run_id=? AND case_id=?",run.id(),CASE);
            if("scope".equals(args[2])) {require(execution.isEmpty());result.put("caseStarted",false);result.put("resultGenerated",false);}
            else {
                require(execution.isPresent());var stored=codec.read(execution.orElseThrow(),CaseExecution.class);require(run.id().equals(stored.runId())&&CASE.equals(stored.caseId()));result.put("caseExecution",stored);
                var entries=new ArrayList<TranscriptEntry>();try(var q=db.prepareStatement("SELECT id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){q.setString(1,run.id());try(var rows=q.executeQuery()){while(rows.next()){var entry=codec.read(rows.getString(2),TranscriptEntry.class);require(rows.getString(1).equals(entry.id())&&run.id().equals(entry.runId()));entries.add(entry);}}}
                var ids=new HashSet<String>();var proof=new ArrayList<Map<String,Object>>();
                for(var entry:entries){require(run.id().equals(entry.runId())&&ids.add(entry.id())&&noCredentials(entry.headers()));var facts=new LinkedHashMap<String,Object>();facts.put("id",entry.id());facts.put("direction",entry.direction());facts.put("method",entry.method());facts.put("url",entry.url());facts.put("correlationId",entry.correlationId()==null?"":entry.correlationId());facts.put("summary",entry.samlSummary());facts.put("bodyBytes",entry.bodyBytes());facts.put("decodedSamlBytes",entry.decodedSamlBytes());
                    if(entry.bodyRef()==null){require(entry.bodyBytes()==0);if(entry.samlSummary().containsKey("body_sha256"))require(hash(new byte[0]).equals(entry.samlSummary().get("body_sha256")));}
                    if(entry.bodyRef()!=null){byte[] bytes=original(data,run.id(),entry,false);String hash=hash(bytes);require(!entry.samlSummary().containsKey("body_sha256")||hash.equals(entry.samlSummary().get("body_sha256")));facts.put("storedBodySha256",hash);if("MetadataFetchResponse".equals(entry.samlSummary().get("type")))require(hash.equals(entry.samlSummary().get("original_body_sha256")));require(!new String(bytes,java.nio.charset.StandardCharsets.UTF_8).contains("synthetic-html-sentinel-must-not-be-retained"));}
                    if(entry.decodedSamlRef()==null)require(entry.decodedSamlBytes()==0);
                    if(entry.decodedSamlRef()!=null)facts.put("storedDecodedSha256",hash(original(data,run.id(),entry,true)));
                    proof.add(facts);
                }
                var normal=entries.stream().filter(e->e.direction()==Direction.INBOUND&&Boolean.TRUE.equals(e.samlSummary().get("normalFlowAccepted"))).toList();require(normal.size()==1);var response=normal.getFirst();require(plan.target().entityId().equals(response.samlSummary().get("issuer"))&&response.correlationId().equals(response.samlSummary().get("inResponseTo"))&&entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&"AuthnRequest".equals(e.samlSummary().get("type"))&&response.correlationId().equals(e.correlationId())).count()==1);
                result.put("normalResponseReference",response.id());result.put("transcriptOriginals",proof);result.put("noCredentialOrCookieHeaders",true);
                var outbox=new ArrayList<Map<String,Object>>();try(var q=db.prepareStatement("SELECT action_json,status,send_result_json,transcript_entry_id FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY action_id")){q.setString(1,run.id());q.setString(2,CASE);try(var rows=q.executeQuery()){while(rows.next()){var action=codec.read(rows.getString(1),OutboundAction.class);require(action.kind()==OutboundKind.METADATA_FETCH&&action.payload().length==0&&!action.requiresEphemeralCredential());var row=new LinkedHashMap<String,Object>();row.put("action",action);row.put("status",rows.getString(2));row.put("sendResult",codec.read(rows.getString(3),Map.class));row.put("transcriptEntryId",rows.getString(4)==null?"":rows.getString(4));outbox.add(row);}}}
                result.put("outbox",outbox);var snapshot=data.resolve("target-metadata").resolve(run.id()+".xml");byte[] snapshotBytes=boundedFile(snapshot,5*1024*1024,-1);result.put("runMetadataSnapshotSha256",hash(snapshotBytes));
                var advertised=new com.samlscope.saml.metadata.TargetMetadataParser().parse(snapshotBytes,plan.target().entityId()).signingCertificates();require(advertised.size()==1&&response.decodedSamlRef()!=null&&"POST".equals(response.method()));
                var normalRoot=com.samlscope.saml.normal.SecureXml.parse(original(data,run.id(),response,true)).getDocumentElement();
                var verifier=new com.samlscope.saml.crypto.XmlSignatureVerifier();require(verifier.hasValidEnvelopedSignature(normalRoot,advertised.getFirst()));
                var assertions=normalRoot.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Assertion");require(assertions.getLength()==1&&verifier.hasValidEnvelopedSignature((org.w3c.dom.Element)assertions.item(0),advertised.getFirst()));
                require("urn:oasis:names:tc:SAML:2.0:status:Success".equals(response.samlSummary().get("statusCode")));result.put("normalResponseAndAssertionSignaturesVerified",true);
            }
        }
        System.out.println(codec.write(result));
    }
    static String single(Connection db,String query,String...args)throws Exception{return optional(db,query,args).orElseThrow(()->new IllegalArgumentException("Missing bound object"));}
    static Optional<String> optional(Connection db,String query,String...args)throws Exception {try(var q=db.prepareStatement(query)){for(int i=0;i<args.length;i++)q.setString(i+1,args[i]);try(var rows=q.executeQuery()){if(!rows.next())return Optional.empty();String value=rows.getString(1);require(!rows.next());return Optional.of(value);}}}
    static byte[] original(Path root,String actualRun,TranscriptEntry entry,boolean decoded)throws Exception {
        require(actualRun.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&actualRun.equals(entry.runId())&&entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}"));
        String suffix=decoded?".saml.xml":".body", reference=decoded?entry.decodedSamlRef():entry.bodyRef();int size=decoded?entry.decodedSamlBytes():entry.bodyBytes();
        String expected="transcripts/"+actualRun+"/"+entry.id()+suffix;
        require(expected.equals(reference)&&size>0&&size<=MAX_ORIGINAL);
        byte[] bytes=boundedFile(checkedRoot(root).resolve(expected),MAX_ORIGINAL,size);
        if(!decoded&&entry.samlSummary().containsKey("body_sha256"))require(hash(bytes).equals(entry.samlSummary().get("body_sha256")));
        if(decoded)for(String key:List.of("decodedSha256","decoded_sha256"))if(entry.samlSummary().containsKey(key))require(hash(bytes).equals(entry.samlSummary().get(key)));
        return bytes;
    }
    static Path checkedRoot(Path input)throws Exception {Path absolute=input.toAbsolutePath();Path root=absolute.normalize();require(root.equals(absolute));noSymlinks(root);require(Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS));return root;}
    static void noSymlinks(Path path){for(Path current=path.toAbsolutePath().normalize();current!=null;current=current.getParent())require(!Files.isSymbolicLink(current));}
    static byte[] boundedFile(Path path,int limit,int expected)throws Exception {noSymlinks(path);require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));long size=Files.size(path);require(size>0&&size<=limit&&(expected<0||size==expected));try(var input=Files.newInputStream(path,LinkOption.NOFOLLOW_LINKS)){byte[] bytes=input.readNBytes(limit+1);require(bytes.length==size&&(expected<0||bytes.length==expected));return bytes;}}
    static Connection openReadOnly(Path root)throws Exception {Path db=checkedRoot(root).resolve("samlscope.db");noSymlinks(db);require(Files.isRegularFile(db,LinkOption.NOFOLLOW_LINKS));var connection=DriverManager.getConnection("jdbc:sqlite:"+db.toUri()+"?mode=ro");try{try(var query=connection.createStatement()){query.execute("PRAGMA query_only=ON");try(var row=query.executeQuery("PRAGMA query_only")){require(row.next()&&row.getInt(1)==1);}}return connection;}catch(Exception failed){connection.close();throw failed;}}
    @FunctionalInterface interface Checked {void run()throws Exception;}
    static void rejects(Checked action)throws Exception {try{action.run();}catch(Exception expected){return;}throw new AssertionError("Unsafe original path accepted");}
    static TranscriptEntry fixtureEntry(String run,String tx,String bodyRef,int size,Map<String,Object> summary){return new TranscriptEntry(tx,run,Direction.INBOUND,java.time.Instant.EPOCH,"action_owned","GET","http://localhost/owned",200,Map.of(),bodyRef,size,null,0,"application/xml",null,summary);}
    static void selfCheck()throws Exception {
        Path owner=Files.createTempDirectory(Path.of(System.getProperty("java.io.tmpdir")).toRealPath(),"samlscope-additional-path-guards-");var checks=new ArrayList<String>();
        try {
            Path root=Files.createDirectory(owner.resolve("data spaces # ?"));String run="run_0123456789ABCDEFGHJKMNPQRS",tx="tx_0123456789ABCDEFGHJKMNPQRS",otherRun="run_1123456789ABCDEFGHJKMNPQRS",otherTx="tx_1123456789ABCDEFGHJKMNPQRS";
            Path dir=Files.createDirectories(root.resolve("transcripts").resolve(run));byte[] bytes="<public xmlns='urn:owned:guard'/>".getBytes(java.nio.charset.StandardCharsets.UTF_8);Path file=dir.resolve(tx+".body");Files.write(file,bytes);String ref="transcripts/"+run+"/"+tx+".body";
            Files.createDirectories(root.resolve("transcripts").resolve(otherRun));Files.write(root.resolve("transcripts").resolve(otherRun).resolve(tx+".body"),bytes);Files.write(dir.resolve(otherTx+".body"),bytes);
            Files.createDirectories(root.resolve("private"));Files.write(root.resolve("private/owned-canary.body"),bytes);Files.createDirectories(root.resolve("other"));Files.write(root.resolve("other/owned-canary.body"),bytes);Files.write(owner.resolve("owned-canary.body"),bytes);
            var valid=fixtureEntry(run,tx,ref,bytes.length,Map.of("body_sha256",hash(bytes)));require(Arrays.equals(bytes,original(root,run,valid,false)));checks.add("exact-owned-original");
            rejects(()->original(root,run,fixtureEntry(run,tx,"transcripts/"+otherRun+"/"+tx+".body",bytes.length,Map.of()),false));checks.add("foreign-run-ref-rejected");
            rejects(()->original(root,run,fixtureEntry(run,tx,"transcripts/"+run+"/"+otherTx+".body",bytes.length,Map.of()),false));checks.add("foreign-entry-ref-rejected");
            rejects(()->original(root,run,fixtureEntry(otherRun,tx,"transcripts/"+otherRun+"/"+tx+".body",bytes.length,Map.of()),false));checks.add("foreign-row-run-rejected");
            for(String bad:List.of("private/owned-canary.body","other/owned-canary.body",file.toString(),"../owned-canary.body"))rejects(()->original(root,run,fixtureEntry(run,tx,bad,bytes.length,Map.of()),false));checks.add("unrelated-private-absolute-traversal-refs-rejected");
            rejects(()->original(root,run,fixtureEntry(run,tx,ref,bytes.length+1,Map.of()),false));checks.add("declared-length-mismatch-rejected");
            rejects(()->original(root,run,fixtureEntry(run,tx,ref,bytes.length,Map.of("body_sha256","0".repeat(64))),false));checks.add("row-body-hash-mismatch-rejected");
            Files.move(file,owner.resolve("owned-body-copy"));Files.createSymbolicLink(file,owner.resolve("owned-body-copy"));rejects(()->original(root,run,valid,false));Files.delete(file);Files.move(owner.resolve("owned-body-copy"),file);checks.add("leaf-symlink-rejected");
            Path moved=root.resolve("owned-run-copy");Files.move(dir,moved);Files.createSymbolicLink(dir,moved);rejects(()->original(root,run,valid,false));Files.delete(dir);Files.move(moved,dir);checks.add("parent-symlink-rejected");
            Path rootLink=owner.resolve("owned-data-link");Files.createSymbolicLink(rootLink,root);rejects(()->original(rootLink,run,valid,false));checks.add("root-symlink-rejected");rejects(()->checkedRoot(root.resolve("noncanonical").resolve("..")));checks.add("noncanonical-root-rejected");
            try(var channel=java.nio.channels.FileChannel.open(file,StandardOpenOption.WRITE)){channel.position(MAX_ORIGINAL);channel.write(java.nio.ByteBuffer.wrap(new byte[]{0}));}rejects(()->original(root,run,fixtureEntry(run,tx,ref,MAX_ORIGINAL+1,Map.of()),false));rejects(()->original(root,run,valid,false));Files.write(file,bytes);checks.add("oversize-and-physical-size-rejected-before-read");
            Path db=root.resolve("samlscope.db");try(var setup=DriverManager.getConnection("jdbc:sqlite:"+db.toUri());var query=setup.createStatement()){query.execute("CREATE TABLE owned_guard(value TEXT)");query.execute("INSERT INTO owned_guard VALUES ('owned public fixture')");}
            String before=hash(Files.readAllBytes(db));try(var read=openReadOnly(root);var query=read.createStatement()){try(var row=query.executeQuery("PRAGMA query_only")){require(row.next()&&row.getInt(1)==1);}try(var row=query.executeQuery("SELECT value FROM owned_guard")){require(row.next()&&"owned public fixture".equals(row.getString(1)));}rejects(()->query.execute("INSERT INTO owned_guard VALUES ('must not write')"));}require(before.equals(hash(Files.readAllBytes(db))));checks.add("uri-spaces-hash-question-query-only-no-write");
            System.out.println(new JsonCodec().write(Map.of("schema","synthetic-additional-owned-path-guards-v1","selfCheck","passed","checks",checks,"networkOperations",0,"realDatabaseReads",0,"realPrivateFileReads",0,"readOnlyDatabaseWrites",0,"ownedTemporaryDatabasePreparationWrites",2)));
        } finally {try(var files=Files.walk(owner)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
    static boolean noCredentials(Map<String,List<String>> headers){return headers.keySet().stream().noneMatch(n->Set.of("authorization","proxy-authorization","cookie","set-cookie").contains(n.toLowerCase(Locale.ROOT)));}
    static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
    static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven synthetic Run scope/originals");}
}
