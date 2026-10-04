package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.Clock;
import java.util.*;

/** Current production classes, real read-only Store, and native originals; controls are never adopted. */
public final class VerifyDefaultAlgorithmSourceRun {
    static final JsonCodec J=new JsonCodec();
    static void require(boolean value,String message){if(!value)throw new IllegalArgumentException(message);}
    static String hash(byte[] raw)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(raw);}
    static List<TranscriptEntry> entries(Path data,String run)throws Exception {
        var entries=new ArrayList<TranscriptEntry>();
        try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")) {
            q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()){require(entries.size()<10_000,"Complete history exceeds bound");entries.add(J.read(rows.getString(1),TranscriptEntry.class));}}
        }
        return List.copyOf(entries);
    }
    static TranscriptRecorder recorder(Map<String,List<TranscriptEntry>> rows){return new TranscriptRecorder(){
        public List<TranscriptEntry>list(String run){require(rows.containsKey(run),"Uncaptured history");return rows.get(run);}
        public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Replay wrote Recorder");}
        public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Replay changed original");}
    };}
    static CaseContext context(DefaultAlgorithmSourceRunStore.Binding b,TranscriptRecorder recorder){return new com.samlscope.runner.DefaultCaseContext(
            b.run().id(),b.plan().profile().role(),Clock.systemUTC(),b.plan().parameters(),b.plan().interaction(),b.run().targetToSuiteReachability(),recorder,true);}
    static Map<String,Object> storedCase(Path data,String run)throws Exception {
        try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
                var q=c.prepareStatement("SELECT revision,status,updated_at,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
            q.setString(1,run);q.setString(2,DefaultAlgorithmComparison.CASE);
            try(var rows=q.executeQuery()) {
                require(rows.next(),"Actual approved case execution missing");String raw=rows.getString("document_json");var e=J.read(raw,CaseExecution.class);
                require(run.equals(e.runId())&&DefaultAlgorithmComparison.CASE.equals(e.caseId())&&rows.getLong("revision")==e.revision()
                        &&rows.getString("status").equals(e.status().name())&&java.time.Instant.parse(rows.getString("updated_at")).equals(e.updatedAt())&&!rows.next(),"Stored execution identity differs");
                var n=new TreeMap<String,Object>();n.put("runId",run);n.put("caseId",e.caseId());n.put("revision",e.revision());n.put("status",e.status().name());
                n.put("updatedAt",e.updatedAt().toString());n.put("statePhase",e.state().phase());n.put("stateSha256",hash(J.mapper().writeValueAsBytes(e.state())));
                n.put("waitConditionSha256",hash(J.mapper().writeValueAsBytes(e.waitCondition())));n.put("documentSha256",hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
                n.put("outcome",e.outcome());n.put("verdict",e.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.RECOMMENDED,e.outcome()));return n;
            }
        }
    }
    static Map<String,String> allCases(Path data,String run)throws Exception {
        var result=new TreeMap<String,String>();
        try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
                var q=c.prepareStatement("SELECT case_id,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")) {
            q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next()) {
                String id=rows.getString(1),raw=rows.getString(2);var e=J.read(raw,CaseExecution.class);
                require(result.size()<10_000&&run.equals(e.runId())&&id.equals(e.caseId())&&result.put(id,hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)))==null,"Actual execution inventory differs");
            }}
        }
        return result;
    }
    static void offline(Path state,Path output)throws Exception {
        var n=(ObjectNode)J.mapper().readTree(Files.readAllBytes(state));
        require(n.path("schema").asText().equals("samlscope-default-algorithm-source-stored-v1"),"Unsafe stored-state schema");
        for(String key:List.of("sourceCase","destinationCase")) {
            var e=(ObjectNode)n.path(key);require(DefaultAlgorithmComparison.CASE.equals(e.path("caseId").asText())
                    &&e.path("runId").asText().matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&e.path("revision").asLong(-1)>=0,"Unsafe stored case");
            boolean finished=e.path("status").asText().equals("FINISHED");require(finished==!e.path("outcome").isNull(),"Stored outcome/status mismatch");
            if(finished)e.put("verdict",Evaluator.toVerdict(Rfc2119Level.RECOMMENDED,J.mapper().treeToValue(e.path("outcome"),CaseOutcome.class)).name());else e.putNull("verdict");
        }
        Files.write(output,J.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(n),StandardOpenOption.CREATE_NEW);
    }
    static DefaultAlgorithmSourceRunEvidence reader(Path binding,Path source,DefaultAlgorithmSourceRunStore store,KeycloakNativeRunEvidenceBridge bridge) {
        return reader(binding,source,store,bridge,bridge::content);
    }
    static DefaultAlgorithmSourceRunEvidence reader(Path binding,Path source,DefaultAlgorithmSourceRunStore store,KeycloakNativeRunEvidenceBridge bridge,TranscriptContentReader content) {
        var profile=new SuiteRunProfileLookup(Path.of("/data"));
        var original=new DefaultAlgorithmPreventionEvidence(source,content,bridge::targetMetadata,r->bridge.key(r,"control"),profile::profile,new ShibbolethDefaultAlgorithmNativeAdapter(content));
        return new DefaultAlgorithmSourceRunEvidence(binding,source,store,content,bridge::targetMetadata,original,new ShibbolethDefaultAlgorithmSourceRunPolicy(content));
    }
    static class Fallback implements TestCase,com.samlscope.runner.BrowserFrontChannelScenario,ConfigurationPrompt,AttestationPrompt,ProtocolEvidenceCase,com.samlscope.runner.FallbackEvidenceCase {
        public String id(){return DefaultAlgorithmComparison.CASE;}public com.samlscope.core.plan.TargetRole role(){return com.samlscope.core.plan.TargetRole.IDP;}
        public CaseStep start(CaseContext c){throw new AssertionError("Owned proof reached fallback");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Owned proof reached fallback");}
        public String promptEn(){return "Approved fallback";}public List<AttestationOption>options(){return List.of();}public String instructionEn(){return "Original configuration";}
        public String instructionsEn(CaseState s){return "Original campaign";}public EvidenceStatus evidenceStatus(CaseContext c){throw new AssertionError("Owned proof reached fallback");}
        public boolean resolvedFromExternalEvidence(CaseExecution e){return false;}
    }
    public static void main(String[]args)throws Exception {
        if(args.length==3&&args[0].equals("offline")){offline(Path.of(args[1]),Path.of(args[2]));return;}
        require(args.length==7,"mode data destination source approvedDigest receipt output required");
        String mode=args[0],destination=args[2],source=args[3];Path data=Path.of(args[1]).toRealPath(),receipt=Path.of(args[5]).toRealPath(),output=Path.of(args[6]);
        var store=new DefaultAlgorithmSourceRunStore(data,args[4]);var bridge=new KeycloakNativeRunEvidenceBridge(data);var destinationBinding=store.planned(destination);var sourceBinding=store.execution(source);
        require(destinationBinding.plan().profile().id().equals("ecp_idp")&&sourceBinding.plan().profile().id().equals("browser_sso_idp"),"Unsupported source/destination profiles");
        require(destinationBinding.plan().target().entityId().equals(sourceBinding.plan().target().entityId())&&Arrays.equals(bridge.targetMetadata(destination),bridge.targetMetadata(source)),"Current target bytes differ from original source");
        var sourceEntries=entries(data,source);var currentEntries=entries(data,destination);var all=new HashMap<String,List<TranscriptEntry>>();all.put(source,sourceEntries);all.put(destination,currentEntries);
        var sourceProfile=new SuiteRunProfileLookup(data);var sourceReader=new DefaultAlgorithmPreventionEvidence(data.resolve("default-algorithm-evidence"),bridge::content,bridge::targetMetadata,r->bridge.key(r,"control"),sourceProfile::profile,new ShibbolethDefaultAlgorithmNativeAdapter(bridge::content));
        var sourceOutcome=sourceReader.evaluate(sourceBinding.context(Clock.systemUTC(),sourceEntries)).orElseThrow(()->new IllegalArgumentException("Complete native source campaign no longer qualifies"));
        require(sourceOutcome.outcome()==Outcome.SATISFIED&&!Boolean.TRUE.equals(sourceOutcome.details().get("counterfactual_calibration_only")),"Genuine original source outcome required");
        if(mode.equals("state")) {
            var n=new TreeMap<String,Object>();n.put("schema","samlscope-default-algorithm-source-stored-v1");n.put("destinationRunId",destination);n.put("sourceRunId",source);
            n.put("approvedCaseDigest",store.approvedCaseDigest());n.put("sourceStore",sourceBinding.snapshot());n.put("destinationStore",store.execution(destination).snapshot());
            n.put("sourceHistory",store.history(source,sourceEntries,bridge::content));n.put("destinationHistory",store.history(destination,currentEntries,bridge::content));
            n.put("sourceCase",storedCase(data,source));n.put("destinationCase",storedCase(data,destination));n.put("sourceExecutions",allCases(data,source));n.put("destinationExecutions",allCases(data,destination));
            n.put("targetMetadataSha256",hash(bridge.targetMetadata(destination)));n.put("destinationApprovedMembershipVerified",true);n.put("sourceApprovedMembershipVerified",true);
            Files.write(output,J.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(n),StandardOpenOption.CREATE_NEW);return;
        }
        if(mode.equals("snapshot")) {
            Files.write(receipt.resolve("source-store-snapshot.json"),J.mapper().writeValueAsBytes(sourceBinding.snapshot()),StandardOpenOption.CREATE_NEW);
            Files.write(receipt.resolve("source-transcript-snapshot.json"),J.mapper().writeValueAsBytes(store.history(source,sourceEntries,bridge::content)),StandardOpenOption.CREATE_NEW);
            Files.write(output,J.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("destinationRunId",destination,"destinationPlanId",destinationBinding.plan().id(),
                    "sourceRunId",source,"sourcePlanId",sourceBinding.plan().id(),"approvedCaseDigest",store.approvedCaseDigest(),"destinationApprovedMembershipVerified",true,
                    "sourceApprovedMembershipVerified",true,"sourceOutcome",sourceOutcome,"targetMetadataSha256",hash(bridge.targetMetadata(destination)),"writesToStore",0)),StandardOpenOption.CREATE_NEW);return;
        }
        require(mode.equals("replay"),"Unknown mode");var destinationExecution=store.execution(destination);var c=context(destinationExecution,recorder(all));
        Path root=Files.createTempDirectory("default-source-binding-replay-").toRealPath(),folder=Files.createDirectory(root.resolve(destination));
        try {
            var originals=new TreeMap<String,byte[]>();try(var files=Files.list(receipt)){for(var path:files.toList())if(Files.isRegularFile(path))originals.put(path.getFileName().toString(),Files.readAllBytes(path));}
            for(var item:originals.entrySet())Files.write(folder.resolve(item.getKey()),item.getValue());
            var reader=reader(root,data.resolve("default-algorithm-evidence"),store,bridge);
            var observed=reader.verified(c);
            require(observed.outcome()==sourceOutcome.outcome()&&Boolean.FALSE.equals(observed.details().get("ecp_protocol_traffic_verified")),"Source verdict/protocol provenance changed");
            var wrapper=new DefaultAlgorithmSourceRunTestCase(new Fallback(),reader);var finished=new CaseStep.Finish(observed);
            require(wrapper.start(c).equals(finished),"Start differs");
            for(var event:List.<CaseEvent>of(new CaseEvent.TranscriptReady(),new CaseEvent.ConfigConfirmed(),new CaseEvent.Attested("satisfied","cannot determine")))require(wrapper.resume(c,CaseState.initial(),event).equals(finished),"Resume differs");
            require(wrapper.evidenceStatus(c).ready()&&wrapper.queuedEvidenceOutcome(c).equals(observed)
                    &&wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","pending")).orElseThrow().equals(observed),"Recorded lifecycle differs");
            var controls=new TreeMap<String,String>();JsonNode base=J.mapper().readTree(originals.get("manifest.json"));
            for(String name:List.of("foreign-run","foreign-source-run","foreign-plan","wrong-profile","wrong-source-profile","wrong-case","wrong-case-digest","calibration-label","ecp-traffic-claim","wrong-scope","source-manifest-changed","source-store-changed","source-history-changed","target-bytes-changed","unsupported-policy","missing-ecp-original","symlink-ecp-original","duplicate-source-transcript","missing-source-transcript","incomplete-destination",
                    "native-wrong-ecp-profile","native-custom-security-bean","native-custom-relying-party","native-policy-source-changed","native-restored-provider-changed","native-current-target-changed","native-class-override","native-clock-reversed")) {
                for(var item:originals.entrySet()){Files.deleteIfExists(folder.resolve(item.getKey()));Files.write(folder.resolve(item.getKey()),item.getValue());}
                var m=(ObjectNode)base.deepCopy();CaseContext selected=c;var selectedReader=reader;
                switch(name) {
                    case "foreign-run"->m.put("runId","run_00000000000000000000000000");
                    case "foreign-source-run"->m.put("sourceRunId",destination);
                    case "foreign-plan"->m.put("sourcePlanId",destinationBinding.plan().id());
                    case "wrong-profile"->m.put("profile","browser_sso_idp");case "wrong-source-profile"->m.put("sourceProfile","ecp_idp");
                    case "wrong-case"->m.put("caseId","IIP-MD05-a3-idp-01");case "wrong-case-digest"->m.put("caseDigest","sha256:"+"0".repeat(64));
                    case "calibration-label"->m.put("counterfactualCalibrationOnly",true);case "ecp-traffic-claim"->m.put("ecpProtocolTrafficVerified",true);
                    case "wrong-scope"->m.put("scope","any-protocol-proof");case "source-manifest-changed"->m.put("sourceManifestSha256","0".repeat(64));
                    case "source-store-changed","source-history-changed"->{String file=m.path(name.equals("source-store-changed")?"sourceStoreSnapshotFile":"sourceTranscriptSnapshotFile").asText();byte[] changed="{}".getBytes();Files.write(folder.resolve(file),changed);((ObjectNode)m.path("files")).put(file,hash(changed));}
                    case "target-bytes-changed"->m.put("targetMetadataSha256","0".repeat(64));case "unsupported-policy"->m.put("adapter","unknown-consumer");
                    case "missing-ecp-original","symlink-ecp-original"->{var scope=J.mapper().readTree(originals.get(m.path("beforeScopeFile").asText()));String file=scope.path("ecpProfileFile").asText();Files.delete(folder.resolve(file));if(name.startsWith("symlink"))Files.createSymbolicLink(folder.resolve(file),receipt.resolve(file));}
                    case "duplicate-source-transcript","missing-source-transcript"->{var changed=new ArrayList<>(sourceEntries);if(name.startsWith("duplicate"))changed.add(sourceEntries.getFirst());else changed.removeFirst();var rows=new HashMap<>(all);rows.put(source,List.copyOf(changed));selected=context(destinationExecution,recorder(rows));}
                    case "incomplete-destination"->selected=new com.samlscope.runner.DefaultCaseContext(c.runId(),c.targetRole(),c.clock(),c.parameters(),c.interaction(),c.reachability(),c.transcript(),false);
                    case "native-wrong-ecp-profile","native-custom-security-bean","native-custom-relying-party","native-policy-source-changed","native-restored-provider-changed","native-current-target-changed","native-class-override","native-clock-reversed"->{
                        String scopeFile=m.path("beforeScopeFile").asText(),scopeReference=m.path("beforeScopeReference").asText();var scope=(ObjectNode)J.mapper().readTree(originals.get(scopeFile));
                        if(name.startsWith("native-wrong")||name.startsWith("native-custom")) {
                            String file=scope.path("ecpProfileFile").asText();var profile=(ObjectNode)J.mapper().readTree(originals.get(file));
                            if(name.equals("native-wrong-ecp-profile"))((ObjectNode)profile.path("ProfileConfiguration")).put("id","http://shibboleth.net/ns/profiles/saml2/sso/browser");
                            if(name.equals("native-custom-security-bean"))((ObjectNode)profile.path("RelyingPartyConfiguration")).put("securityConfiguration","operator.CustomSecurityConfiguration");
                            if(name.equals("native-custom-relying-party"))((ObjectNode)profile.path("RelyingPartyConfiguration")).put("id","operator.CustomRelyingParty");
                            byte[] changed=J.mapper().writeValueAsBytes(profile);Files.write(folder.resolve(file),changed);((ObjectNode)scope.path("files")).put(file,hash(changed));((ObjectNode)m.path("files")).put(file,hash(changed));
                        } else if(name.equals("native-policy-source-changed")) ((ObjectNode)scope.path("propertiesSha256")).put("/opt/reference-idp/conf/idp.properties","0".repeat(64));
                        else if(name.equals("native-class-override")) ((com.fasterxml.jackson.databind.node.ArrayNode)scope.path("overrideSourceInventory")).add("/usr/local/tomcat/webapps/idp/WEB-INF/classes/algorithm-override.class");
                        else if(name.equals("native-clock-reversed"))scope.put("startedAt","2100-01-01T00:00:00Z");
                        else {
                            String file=scope.path(name.equals("native-restored-provider-changed")?"restoredConfigurationFiles":"liveTargetMetadataFile").asText();
                            if(name.equals("native-restored-provider-changed"))file=scope.path("restoredConfigurationFiles").path("providers").asText();
                            byte[] changed=(name.equals("native-restored-provider-changed")?"<different-provider/>":"<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://foreign.example/idp'/>").getBytes();
                            Files.write(folder.resolve(file),changed);((ObjectNode)scope.path("files")).put(file,hash(changed));((ObjectNode)m.path("files")).put(file,hash(changed));
                        }
                        byte[] changed=J.mapper().writeValueAsBytes(scope);Files.write(folder.resolve(scopeFile),changed);m.put("beforeScopeSha256",hash(changed));((ObjectNode)m.path("files")).put(scopeFile,hash(changed));
                        var rows=new HashMap<>(all);rows.put(destination,currentEntries.stream().map(e->!e.id().equals(scopeReference)?e:new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),changed.length,e.contentType(),e.rawQuery(),e.samlSummary())).toList());selected=context(destinationExecution,recorder(rows));
                        selectedReader=reader(root,data.resolve("default-algorithm-evidence"),store,bridge,e->e.runId().equals(destination)&&e.id().equals(scopeReference)?changed:bridge.content(e));
                    }
                    default->throw new IllegalArgumentException(name);
                }
                Files.write(folder.resolve("manifest.json"),J.mapper().writeValueAsBytes(m));require(selectedReader.evaluate(selected).isEmpty(),"Binding negative control promoted: "+name);controls.put(name,"NOT_VERIFIED");
            }
            Files.write(output,J.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("destinationRunId",destination,"sourceRunId",source,"outcome",observed,
                    "negativeControls",controls,"fullSourceCampaignReplayedOnEveryQualifiedRead",true,"approvedMembershipVerifiedOnEveryQualifiedRead",true,"sourceOriginalsRelabeled",false,
                    "ecpProtocolTrafficVerified",false,"controlsAdopted",false,"lifecycle",Map.of("start",true,"resume",true,"recordedEvidence",true,"queuedEvidence",true,"evidenceStatus",true))),StandardOpenOption.CREATE_NEW);
        } finally {try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
