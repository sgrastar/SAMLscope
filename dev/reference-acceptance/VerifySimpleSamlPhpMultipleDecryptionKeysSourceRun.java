package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.Clock;
import java.util.*;

/** Read-only actual Store/original replay and controls. The CLI never starts or relabels a Run. */
public final class VerifySimpleSamlPhpMultipleDecryptionKeysSourceRun {
    private static final ObjectMapper JSON=new JsonCodec().mapper();
    private static final String CASE=SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE;
    private static final String DIGEST=SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST;
    private static void require(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
    private static String hash(byte[] raw)throws Exception{return NativeConfigurationSourceRunEvidence.hash(raw);}
    private static byte[] original(Path p,String name)throws Exception{return NativeConfigurationSourceRunEvidence.original(p,name);}
    private static void save(Path p,Object value)throws Exception{
        require(!Files.exists(p,LinkOption.NOFOLLOW_LINKS),"Immutable output already exists: "+p);
        Files.write(p,JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(value));
    }
    public static void main(String[] args)throws Exception {
        if(args.length==3&&args[0].equals("offline")) {
            var state=(ObjectNode)JSON.readTree(Path.of(args[1]).toFile());
            require("samlscope-independent-configuration-source-state-v1".equals(state.path("schema").asText()),"Foreign state schema");
            var execution=JSON.treeToValue(state.path("caseExecution"),CaseExecution.class);
            require(CASE.equals(execution.caseId())&&state.path("recipientRunId").asText().equals(execution.runId()),"Foreign stored execution");
            if(execution.outcome()==null)state.putNull("verdict");else state.put("verdict",Evaluator.toVerdict(Rfc2119Level.MUST,execution.outcome()).name());
            save(Path.of(args[2]),state);return;
        }
        require(args.length==7&&Set.of("prepare","prepare-source","seal","state","replay","installed","transition","candidates").contains(args[0]),
                "Expected mode,data,recipientRun,sourceRun,sourceReceipt,bindingFolder,output");
        String mode=args[0],recipient=args[2],source=args[3];
        require(recipient.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&source.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&!recipient.equals(source),"Foreign Run scope");
        Path data=Path.of(args[1]).toAbsolutePath().normalize(),sourceFolder=Path.of(args[4]).toAbsolutePath().normalize(),folder=Path.of(args[5]).toAbsolutePath().normalize();
        require(sourceFolder.getFileName().toString().equals(source+SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX)
                &&folder.getFileName().toString().equals(recipient),"Unowned source/recipient folder name");
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var store=new DefaultAlgorithmSourceRunStore(data,CASE,DIGEST);
        var src=store.planned(source);
        if(mode.equals("candidates")) {
            byte[] target=bridge.targetMetadata(source);var rows=new ArrayList<Map<String,Object>>();
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var query=connection.prepareStatement("SELECT id FROM runs ORDER BY id");var runs=query.executeQuery()) {
                while(runs.next()) {String id=runs.getString(1);if(id.equals(source))continue;
                    try {var candidate=store.execution(id);if(candidate.run().status()!=com.samlscope.core.run.RunStatus.COMPLETED||!candidate.plan().profile().id().equals("single_logout_idp")||!candidate.plan().target().entityId().equals(src.plan().target().entityId()))continue;
                        byte[] metadata=bridge.targetMetadata(id);rows.add(Map.of("runId",id,"planId",candidate.plan().id(),"targetMetadataSha256",hash(metadata),"sourceTargetBytesEqual",Arrays.equals(target,metadata)));}
                    catch(IllegalArgumentException unqualified) { /* Other products/profiles lack this approved execution. */ }
                }
            }
            save(Path.of(args[6]),Map.of("sourceRunId",source,"sourceTargetMetadataSha256",hash(target),"sourceReceiptTargetMetadataSha256",hash(original(sourceFolder,"target-metadata.xml")),"candidates",rows,"targetOperations",0));return;
        }
        var dest=store.execution(recipient);var sourceHistory=entries(data,source);var recipientHistory=entries(data,recipient);
        var reader=new NativeConfigurationSourceRunEvidence(data,folder.getParent(),sourceFolder.getParent(),bridge::content,bridge::targetMetadata);
        var fence=reader.fence(src,dest,sourceHistory,recipientHistory);
        require(fence.path("sourceExecutions").isEmpty(),"Independent source already has an execution");
        if(mode.equals("prepare")||mode.equals("prepare-source")) {
            save(sourceFolder.resolve("source-store.json"),SimpleSamlPhpMultipleDecryptionKeysEvidence.stable(src.snapshot()));
            save(sourceFolder.resolve("source-history.json"),store.history(source,sourceHistory,bridge::content));
            var sourceFiles=hashes(sourceFolder);var ops=JSON.readTree(original(sourceFolder,"operations.json"));String helper=null;
            for(var op:ops)if("native-helper-write".equals(op.path("label").asText()))helper=op.path("command").get(op.path("command").size()-1).asText();
            require(helper!=null,"Original native helper write absent");
            byte[] target=bridge.targetMetadata(source);require(Arrays.equals(target,original(sourceFolder,"target-metadata.xml")),"Actual source/receipt target bytes differ");
            var m=JSON.createObjectNode();m.put("schema",SimpleSamlPhpMultipleDecryptionKeysEvidence.SCHEMA);m.put("caseId",CASE);m.put("caseDigest",DIGEST);
            m.put("runId",source);m.put("targetEntityId",src.plan().target().entityId());m.put("targetMetadataSha256",hash(target));
            m.put("campaignId","native-multiple-decryption-keys");m.put("outcomeAssigned",false);
            m.put("nativeHelperPath",helper);
            m.put("newPrivateKeyPath",helper.substring(0,helper.length()-4)+".key.pem");m.put("newCertificatePath",helper.substring(0,helper.length()-4)+".cert.pem");
            m.set("files",sourceFiles);save(sourceFolder.resolve("manifest.json"),m);
            var recorder=recorder(source,sourceHistory);var c=new DefaultCaseContext(source,src.plan().profile().role(),Clock.systemUTC(),
                    src.plan().parameters(),src.plan().interaction(),src.run().targetToSuiteReachability(),recorder,false);
            var nativeReader=new SimpleSamlPhpMultipleDecryptionKeysEvidence(sourceFolder.getParent(),bridge::content,bridge::targetMetadata,store);
            var proof=nativeReader.readIndependentConfigurationSource(c,hash(original(sourceFolder,"manifest.json"))).orElseThrow();
            require(proof.outcome()==Outcome.SATISFIED,"Full original native CONFIG validation did not qualify: "+proof);
            if(mode.equals("prepare-source")) {
                save(Path.of(args[6]),Map.of("fullIndependentOriginalNativeProof",proof,"sourceGlobalTranscriptComplete",false,
                        "sourceStatus",src.run().status(),"recipientStatus",dest.run().status(),"sourceHistoryEntries",sourceHistory.size(),
                        "sourceCaseExecutionCreated",false,"sourceOriginalsRelabeled",false,"targetOperations",0,"recipientBindingQualified",false));return;
            }
            byte[] recipientTarget=bridge.targetMetadata(recipient);
            var identity=NativeConfigurationSourceRunEvidence.targetIdentity(target,recipientTarget,original(sourceFolder,"new-public-certificate.pem"),
                    JSON.readTree(original(sourceFolder,"native-before.json")),JSON.readTree(original(sourceFolder,"native-restored.json")));
            save(folder.resolve("target-identity.json"),identity);
            save(folder.resolve("binding-fence.json"),fence);Files.write(folder.resolve("source-target-metadata.xml"),target);
            Files.write(folder.resolve("target-metadata.xml"),recipientTarget);
            var input=JSON.createObjectNode();input.put("sourceRunId",source);input.put("recipientRunId",recipient);input.put("caseDigest",DIGEST);
            input.put("targetEntityId",src.plan().target().entityId());input.put("sourcePeerEntityId","http://localhost:18080/p/"+src.plan().id());
            input.put("sourceTargetMetadataSha256",hash(target));input.put("recipientTargetMetadataSha256",hash(recipientTarget));
            input.put("targetIdentitySha256",hash(original(folder,"target-identity.json")));input.put("sourceManifestSha256",hash(original(sourceFolder,"manifest.json")));
            input.put("bindingFenceSha256",hash(original(folder,"binding-fence.json")));save(folder.resolve("current-input.json"),input);
            save(Path.of(args[6]),Map.of("fullIndependentOriginalNativeProof",proof,"sourceGlobalTranscriptComplete",false,
                    "sourceStatus",src.run().status(),"recipientStatus",dest.run().status(),"sourceHistoryEntries",sourceHistory.size(),
                    "sourceCaseExecutionCreated",false,"sourceOriginalsRelabeled",false,"targetOperations",0));return;
        }
        if(mode.equals("seal")) {
            require(fence.equals(JSON.readTree(original(folder,"binding-fence.json"))),"Actual source/recipient fence changed before sealing");
            var m=JSON.createObjectNode();m.put("schema",NativeConfigurationSourceRunEvidence.SCHEMA);m.put("scope",NativeConfigurationSourceRunEvidence.SCOPE);
            m.put("caseId",CASE);m.put("caseDigest",DIGEST);m.put("runId",recipient);m.put("planId",dest.plan().id());m.put("profile",dest.plan().profile().id());
            m.put("sourceRunId",source);m.put("sourcePlanId",src.plan().id());m.put("sourceProfile",src.plan().profile().id());m.put("sourceTranscriptComplete",false);
            m.put("recipientProtocolOperationsClaimed",0);m.put("targetEntityId",src.plan().target().entityId());
            m.put("targetMetadataSha256",hash(original(sourceFolder,"target-metadata.xml")));m.put("sourceManifestSha256",hash(original(sourceFolder,"manifest.json")));
            m.put("recipientTargetMetadataSha256",hash(original(folder,"target-metadata.xml")));m.put("targetIdentitySha256",hash(original(folder,"target-identity.json")));
            m.set("files",hashes(folder));save(folder.resolve("manifest.json"),m);
            var c=dest.context(Clock.systemUTC(),recipientHistory);
            // Source access remains the actual complete multi-Run Recorder, never a true source context.
            c=withHistories(c,source,sourceHistory,recipient,recipientHistory);
            var result=reader.verified(c);require(result.outcome()==Outcome.SATISFIED,"Current signed source binding did not qualify: "+result);
            save(Path.of(args[6]),Map.of("candidate",result,"formalAdoption",false,"targetOperations",0));return;
        }
        if(mode.equals("state")||mode.equals("transition")) {
            var state=new TreeMap<String,Object>();state.put("schema","samlscope-independent-configuration-source-state-v1");state.put("sourceRunId",source);
            state.put("actualModuleCodeSources",actualModuleCodeSources());
            state.put("recipientRunId",recipient);state.put("fence",fence);state.put("executions",executions(data,recipient));state.put("sourceExecutions",executions(data,source));
            var e=execution(data,recipient);state.put("caseExecution",e);state.put("verdict",e.outcome()==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,e.outcome()));
            state.put("caseUpdatedAt",e.updatedAt().toString());
            state.put("caseStateSha256",hash(JSON.writeValueAsBytes(e.state())));state.put("caseWaitSha256",hash(JSON.writeValueAsBytes(e.waitCondition())));
            state.put("caseDocumentSha256",executions(data,recipient).get(CASE));
            if(mode.equals("transition")) {
                var values=new LinkedHashMap<>(e.state().data());var audit=values.remove("previous_recorded_evidence_result");
                require(e.outcome()!=null,"Actual final outcome absent");
                if(audit==null) {
                    require(!e.outcome().details().containsKey("previous_recorded_evidence_result"),"Unexpected outcome-only prior audit");
                    state.put("transitionKind","configuration-first-outcome");state.put("priorResultAudit",null);state.put("stateAuditEqualsOutcomeAudit",false);
                } else {
                    require(audit instanceof Map<?,?>&&JSON.valueToTree(audit).equals(JSON.valueToTree(e.outcome().details().get("previous_recorded_evidence_result"))),"Normal central audit differs");
                    state.put("transitionKind","recorded-evidence-reevaluation");state.put("priorResultAudit",audit);state.put("stateAuditEqualsOutcomeAudit",true);
                }
                state.put("stateWithoutPriorAuditSha256",hash(JSON.writeValueAsBytes(new CaseState(e.state().phase(),values))));
            }
            save(Path.of(args[6]),state);return;
        }
        if(mode.equals("installed")) {
            var c=withHistories(dest.context(Clock.systemUTC(),recipientHistory),source,sourceHistory,recipient,recipientHistory);
            var registered=ApprovedConfigCaseRegistry.withNativeMultipleDecryptionKeys(fallback(),data,bridge::content,bridge::targetMetadata);
            require(registered instanceof NativeConfigurationSourceRunTestCase,"Installed production registry did not create the source wrapper");
            var actual=((CaseStep.Finish)registered.start(c)).outcome();var expected=reader.verified(c);
            require(actual.equals(expected)&&actual.outcome()==Outcome.SATISFIED,"Actual installed registry reader differs");
            save(Path.of(args[6]),Map.of("actualRegistryClass",registered.getClass().getName(),"actualRegistryOutcome",actual,
                    "evidenceClass",((com.samlscope.runner.FallbackEvidenceCase)registered).evidenceClass(execution(data,recipient)),
                    "actualModuleCodeSources",actualModuleCodeSources(),"targetOperations",0));return;
        }
        replay(data,sourceFolder,folder,source,recipient,sourceHistory,recipientHistory,src,dest,bridge,Path.of(args[6]));
    }
    private static void replay(Path data,Path originalSource,Path originalBinding,String source,String recipient,
            List<TranscriptEntry> sourceHistory,List<TranscriptEntry> recipientHistory,
            DefaultAlgorithmSourceRunStore.Binding src,DefaultAlgorithmSourceRunStore.Binding dest,
            KeycloakNativeRunEvidenceBridge bridge,Path output)throws Exception {
        Path temporary=Files.createTempDirectory("native-config-source-controls-");
        try {
            Path sources=temporary.resolve("sources"),bindings=temporary.resolve("bindings"),s=sources.resolve(originalSource.getFileName()),b=bindings.resolve(recipient);
            copy(originalSource,s);copy(originalBinding,b);var sourceBytes=bytes(s);var bindingBytes=bytes(b);
            var c=withHistories(dest.context(Clock.systemUTC(),recipientHistory),source,sourceHistory,recipient,recipientHistory);
            var reader=new NativeConfigurationSourceRunEvidence(data,bindings,sources,bridge::content,bridge::targetMetadata);
            var baseline=reader.read(c).orElseThrow();require(baseline.outcome()==Outcome.SATISFIED&&Evaluator.toVerdict(Rfc2119Level.MUST,baseline)==Verdict.PASS,"Full source/current positive failed: "+baseline);
            var wrapper=new NativeConfigurationSourceRunTestCase(new NativeMultipleDecryptionKeysConfigurationTestCase(fallback(),
                    new SimpleSamlPhpMultipleDecryptionKeysEvidence(temporary.resolve("empty-same-run"),bridge::content,bridge::targetMetadata,
                            new DefaultAlgorithmSourceRunStore(data,CASE,DIGEST))),reader);
            require(((CaseStep.Finish)wrapper.start(c)).outcome().equals(baseline)
                    &&wrapper.evidenceStatus(c).ready()&&wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(baseline),"Actual approved fallback/wrapper path unavailable");
            var controls=new TreeMap<String,String>();
            for(String name:List.of("foreign-source-run","foreign-recipient-run","foreign-case-digest","source-complete-claim","foreign-source-fence",
                    "foreign-recipient-fence","foreign-source-history","foreign-recipient-history","foreign-other-case","source-manifest-swap",
                    "native-source-missing","native-restore-change","native-coherent-decrypt","native-unknown-stderr","current-input-change",
                    "current-coherent-settings","current-coherent-dependencies","current-signature-change","current-helper-change","current-unknown-stderr",
                    "current-runtime-image-change","current-runtime-mount-overlay","current-time-source-change","current-time-command-change",
                    "recipient-target-change","source-target-copy-change","identity-rule-change")) {
                restore(s,sourceBytes);restore(b,bindingBytes);
                switch(name) {
                    case "foreign-source-run"->edit(b,"manifest.json",v->v.put("sourceRunId","run_22222222222222222222222222"));
                    case "foreign-recipient-run"->edit(b,"manifest.json",v->v.put("runId","run_22222222222222222222222222"));
                    case "foreign-case-digest"->edit(b,"manifest.json",v->v.put("caseDigest","sha256:"+"0".repeat(64)));
                    case "source-complete-claim"->edit(b,"manifest.json",v->v.put("sourceTranscriptComplete",true));
                    case "foreign-source-fence"->edit(b,"binding-fence.json",v->((ObjectNode)v.path("sourceStore")).put("planDocumentSha256","0".repeat(64)));
                    case "foreign-recipient-fence"->edit(b,"binding-fence.json",v->((ObjectNode)v.path("recipientStore")).put("planDocumentSha256","0".repeat(64)));
                    case "foreign-source-history"->edit(b,"binding-fence.json",v->((ObjectNode)v.path("sourceHistory").get(0)).put("entrySha256","0".repeat(64)));
                    case "foreign-recipient-history"->edit(b,"binding-fence.json",v->((ObjectNode)v.path("recipientHistory").get(0)).put("entrySha256","0".repeat(64)));
                    case "foreign-other-case"->edit(b,"binding-fence.json",v->((ObjectNode)v.path("recipientOtherExecutions")).put("IIP-IDP19-c-idp-01","0".repeat(64)));
                    case "source-manifest-swap"->edit(s,"manifest.json",v->v.put("unboundNativeEpoch",true));
                    case "native-source-missing"->Files.delete(s.resolve("native-before.stdout"));
                    case "native-restore-change"->Files.writeString(s.resolve("hosted-final.php"),"changed restored configuration");
                    case "native-coherent-decrypt"->coherentPayload(s,"native-before.stdout","decryptionControls");
                    case "native-unknown-stderr"->Files.writeString(s.resolve("native-before.stderr"),"unknown native error\n");
                    case "current-input-change"->edit(b,"current-input.json",v->v.put("sourceManifestSha256","0".repeat(64)));
                    case "current-coherent-settings"->coherentPayload(b,"current-envelope.json","settingsSha256");
                    case "current-coherent-dependencies"->coherentPayload(b,"current-envelope.json","dependencies");
                    case "current-signature-change"->edit(b,"current-envelope.json",v->((ObjectNode)v.path("signatures").get(0)).put("signatureBase64",Base64.getEncoder().encodeToString(new byte[256])));
                    case "current-helper-change"->Files.writeString(b.resolve("current-helper.php"),"<?php changed helper");
                    case "current-unknown-stderr"->Files.writeString(b.resolve("current-native.stderr"),"unknown native error\n");
                    case "current-runtime-image-change"->edit(b,"current-runtime-before.json",v->v.put("imageId","sha256:"+"0".repeat(64)));
                    case "current-runtime-mount-overlay"->edit(b,"current-runtime-before.json",v->((com.fasterxml.jackson.databind.node.ArrayNode)v.path("mounts")).addObject().put("Type","bind").put("Destination","/var/simplesamlphp/vendor"));
                    case "current-time-source-change"->Files.writeString(b.resolve("current-time-source.php"),"<?php changed current-only dependency");
                    case "current-time-command-change"->{var operations=JSON.readTree(original(b,"current-time-source-operations.json"));((com.fasterxml.jackson.databind.node.ArrayNode)operations.get(1).path("command")).add("unknown");Files.write(b.resolve("current-time-source-operations.json"),JSON.writeValueAsBytes(operations));}
                    case "recipient-target-change"->Files.writeString(b.resolve("target-metadata.xml"),"<EntityDescriptor/>");
                    case "source-target-copy-change"->Files.writeString(b.resolve("source-target-metadata.xml"),"<EntityDescriptor/>");
                    case "identity-rule-change"->edit(b,"target-identity.json",v->v.put("rule","entity-id-only"));
                }
                cohereOperations(s,b,name);
                rehash(s);rehash(b);
                if(name.startsWith("native-"))cohereSourceBinding(s,b);
                var result=reader.read(c).orElseThrow();require(result.outcome()==Outcome.NOT_VERIFIED,"Altered original promoted: "+name);controls.put(name,"NOT_VERIFIED");
                require(((CaseStep.Finish)wrapper.start(c)).outcome().outcome()==Outcome.NOT_VERIFIED
                        &&!wrapper.evidenceStatus(c).ready()&&wrapper.reevaluateRecordedEvidence(c,CaseOutcome.notVerified("pending","case.pending-interaction")).isEmpty(),"Invalid owned evidence borrowed fallback: "+name);
            }
            for(String name:List.of("source-original-after-inner-check","source-manifest-after-inner-check")) {
                restore(s,sourceBytes);restore(b,bindingBytes);var reads=new int[]{0};
                TranscriptContentReader changing=entry->{byte[] raw=bridge.content(entry);
                    if(entry.runId().equals(source)&&"MetadataPrepared".equals(entry.samlSummary().get("type"))&&++reads[0]==3) {
                        try{edit(s,name.contains("manifest")?"manifest.json":"native-before.json",v->v.put("changedAfterInnerRead",true));}
                        catch(Exception failed){throw new IllegalArgumentException(failed);}
                    }return raw;};
                var changed=new NativeConfigurationSourceRunEvidence(data,bindings,sources,changing,bridge::targetMetadata).read(c).orElseThrow();
                require(reads[0]>=3&&changed.outcome()==Outcome.NOT_VERIFIED,"Source changed after validation was accepted: "+name);controls.put(name,"NOT_VERIFIED");
            }
            restore(s,sourceBytes);restore(b,bindingBytes);String expectedSourceManifest=hash(original(s,"manifest.json"));edit(s,"manifest.json",v->v.put("anotherValidEpoch",true));
            var sourceContext=new DefaultCaseContext(source,src.plan().profile().role(),Clock.systemUTC(),src.plan().parameters(),src.plan().interaction(),src.run().targetToSuiteReachability(),recorder(source,sourceHistory),false);
            require(new SimpleSamlPhpMultipleDecryptionKeysEvidence(sources,bridge::content,bridge::targetMetadata,new DefaultAlgorithmSourceRunStore(data,CASE,DIGEST))
                    .readIndependentConfigurationSource(sourceContext,expectedSourceManifest).orElseThrow().outcome()==Outcome.NOT_VERIFIED,"Captured source manifest guard accepted a different valid manifest");controls.put("inner-captured-source-manifest-change","NOT_VERIFIED");
            restore(s,sourceBytes);restore(b,bindingBytes);
            var finalReplay=reader.read(c).orElseThrow();require(baseline.equals(finalReplay),"Controls changed baseline/source originals");
            controls.putAll(recipientWitnessControls(data,bindings,sources,dest,recipientHistory,bridge));
            save(output,Map.of("fullProductionReaderPositive",baseline,"controls",controls,"allControlsRejected",true,
                    "sourceContextTranscriptComplete",false,"sourceCaseExecutionCreated",false,"productionWrapperVerified",true,"targetOperations",0));
        } finally {try(var paths=Files.walk(temporary)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
    private static Map<String,String> recipientWitnessControls(Path data,Path bindings,Path sources,
            DefaultAlgorithmSourceRunStore.Binding dest,List<TranscriptEntry> history,KeycloakNativeRunEvidenceBridge bridge)throws Exception {
        byte[] target=bridge.targetMetadata(dest.run().id());
        var reader=new NativeConfigurationSourceRunEvidence(data,bindings,sources,bridge::content,bridge::targetMetadata);
        var selected=reader.recipientIdentityOriginals(dest,history,target);require(selected.size()==2,"Actual identity baseline differs");
        var request=selected.get(0);var response=selected.get(1);var controls=new TreeMap<String,String>();
        for(String name:List.of("missing-response","ambiguous-response","foreign-response-run","normal-accepted-false",
                "response-signature-change","response-issuer-change","response-destination-change","response-request-id-change","response-id-change",
                "response-status-change","request-id-change","request-issuer-change","request-acs-change","request-destination-change",
                "request-raw-query-change","request-time-after-response","missing-response-original","response-transform-change")) {
            var changed=new ArrayList<>(history);String changedOriginal=null;byte[] bytes=null;
            if(name.equals("missing-response"))changed.remove(response);
            else if(name.equals("ambiguous-response"))changed.add(response);
            else if(name.equals("foreign-response-run")||name.equals("normal-accepted-false")||name.equals("request-raw-query-change")||name.equals("request-time-after-response")) {
                var entry=name.startsWith("request-")?request:response;var value=(ObjectNode)JSON.valueToTree(entry);
                if(name.equals("foreign-response-run"))value.put("runId","run_22222222222222222222222222");
                if(name.equals("normal-accepted-false"))((ObjectNode)value.path("samlSummary")).put("normalFlowAccepted",false);
                if(name.equals("request-raw-query-change"))value.put("url",entry.url()+"&SAMLRequest=invalid-duplicate");
                if(name.equals("request-time-after-response"))value.set("timestamp",JSON.valueToTree(response.timestamp().plusSeconds(1)));
                changed.set(changed.indexOf(entry),JSON.treeToValue(value,TranscriptEntry.class));
            } else {
                var entry=name.startsWith("request-")?request:response;changedOriginal=entry.id();
                if(name.equals("missing-response-original"))bytes=new byte[0];
                else {
                    var document=com.samlscope.saml.normal.SecureXml.parse(bridge.content(entry));var root=document.getDocumentElement();
                    final String ds="http://www.w3.org/2000/09/xmldsig#",assertion="urn:oasis:names:tc:SAML:2.0:assertion",protocol="urn:oasis:names:tc:SAML:2.0:protocol";
                    switch(name) {
                        case "response-signature-change"->{var signature=root.getElementsByTagNameNS(ds,"SignatureValue").item(0);String old=signature.getTextContent();signature.setTextContent((old.charAt(0)=='A'?"B":"A")+old.substring(1));}
                        case "response-transform-change"->((org.w3c.dom.Element)root.getElementsByTagNameNS(ds,"Transform").item(0)).setAttribute("Algorithm","http://www.w3.org/TR/1999/REC-xpath-19991116");
                        case "response-issuer-change","request-issuer-change"->root.getElementsByTagNameNS(assertion,"Issuer").item(0).setTextContent("http://foreign.example/idp");
                        case "response-destination-change","request-destination-change"->root.setAttribute("Destination","http://foreign.example/service");
                        case "response-request-id-change"->root.setAttribute("InResponseTo","_foreign-request");
                        case "response-id-change"->root.setAttribute("ID","_foreign-response");
                        case "response-status-change"->((org.w3c.dom.Element)root.getElementsByTagNameNS(protocol,"StatusCode").item(0)).setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:Responder");
                        case "request-id-change"->root.setAttribute("ID","_foreign-request");
                        case "request-acs-change"->root.setAttribute("AssertionConsumerServiceURL","http://foreign.example/acs");
                        default->throw new IllegalArgumentException("Unsupported identity control");
                    }
                    bytes=com.samlscope.saml.normal.SecureXml.serialize(document);
                }
            }
            final String id=changedOriginal;final byte[] changedBytes=bytes;
            TranscriptContentReader content=e->id!=null&&id.equals(e.id())?changedBytes:bridge.content(e);
            boolean rejected=false;
            try {new NativeConfigurationSourceRunEvidence(data,bindings,sources,content,bridge::targetMetadata).recipientIdentityOriginals(dest,changed,target);}
            catch(Exception expected){rejected=true;}
            require(rejected,"Altered actual recipient identity accepted: "+name);controls.put("recipient-identity/"+name,"NOT_VERIFIED");
        }
        require(reader.recipientIdentityOriginals(dest,history,target).equals(selected),"Identity controls changed original baseline");return controls;
    }
    private static void coherentPayload(Path folder,String file,String field)throws Exception {
        var envelope=(ObjectNode)JSON.readTree(original(folder,file));var payload=(ObjectNode)JSON.readTree(Base64.getDecoder().decode(envelope.path("payloadBase64").asText()));
        if(field.equals("settingsSha256"))((ObjectNode)payload.path(field)).put("hosted","0".repeat(64));
        else if(field.equals("dependencies"))((ObjectNode)payload.path(field).get(0)).put("sha256","0".repeat(64));
        else if(field.equals("decryptionControls"))((ObjectNode)payload.path(field).get(0).path("attempts").get(0)).put("decrypted",false);
        else throw new IllegalArgumentException("Unsupported coherent payload mutation");
        byte[] raw=JSON.writeValueAsBytes(payload);
        envelope.put("payloadBase64",Base64.getEncoder().encodeToString(raw));envelope.put("payloadSha256",hash(raw));Files.write(folder.resolve(file),JSON.writeValueAsBytes(envelope));
        if(file.equals("native-before.stdout"))Files.write(folder.resolve("native-before.json"),raw);
    }
    private static void cohereOperations(Path source,Path binding,String name)throws Exception {
        if(name.startsWith("native-"))updateOperation(source,"operations.json","native-before","native-before.stdout","native-before.stderr");
        if(name.startsWith("current-"))updateOperation(binding,"current-operations.json","native-readback","current-envelope.json","current-native.stderr");
        if(name.startsWith("current-runtime-")) {
            byte[] changed=original(binding,"current-runtime-before.json");Files.write(binding.resolve("current-runtime-before.stdout"),changed);
            Files.write(binding.resolve("current-runtime-after.json"),changed);Files.write(binding.resolve("current-runtime-after.stdout"),changed);
            updateOperation(binding,"current-operations.json","runtime-before","current-runtime-before.stdout",null);
            updateOperation(binding,"current-operations.json","runtime-after","current-runtime-after.stdout",null);
        }
    }
    private static void updateOperation(Path folder,String file,String label,String stdout,String stderr)throws Exception {
        var operations=JSON.readTree(original(folder,file));for(var op:operations)if(label.equals(op.path("label").asText())) {
            if(Files.exists(folder.resolve(stdout)))((ObjectNode)op).put("stdoutSha256",hash(original(folder,stdout)));
            if(stderr!=null)((ObjectNode)op).put("stderrSha256",hash(original(folder,stderr)));
        }Files.write(folder.resolve(file),JSON.writeValueAsBytes(operations));
    }
    private static void cohereSourceBinding(Path source,Path binding)throws Exception {
        String sha=hash(original(source,"manifest.json"));edit(binding,"manifest.json",v->v.put("sourceManifestSha256",sha));
        edit(binding,"current-input.json",v->v.put("sourceManifestSha256",sha));rehash(binding);
    }
    private static TestCase fallback()throws Exception {
        var options=new org.yaml.snakeyaml.LoaderOptions();options.setAllowDuplicateKeys(false);options.setMaxAliasesForCollections(1_000);options.setCodePointLimit(16_777_216);
        com.samlscope.core.casedef.CaseDefinitionCatalog definitions;
        try(var input=VerifySimpleSamlPhpMultipleDecryptionKeysSourceRun.class.getResourceAsStream("/catalog/tests/cases.yaml")) {
            require(input!=null,"Installed approved catalog unavailable");definitions=com.samlscope.core.casedef.CaseDefinitionCatalogMapper.fromDocument(new org.yaml.snakeyaml.Yaml(new org.yaml.snakeyaml.constructor.SafeConstructor(options)).load(input));
        }
        var original=ApprovedConfigCaseRegistry.create(definitions,com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3).require(CASE);
        return MultipleDecryptionKeysConfigurationTestCase.publishedOnly(original,run->List.of(),(run,id)->Optional.empty());
    }
    private static Map<String,Object> actualModuleCodeSources()throws Exception {
        var result=new TreeMap<String,Object>();
        for(var entry:Map.of("runner","com.samlscope.runner.cases.NativeConfigurationSourceRunEvidence",
                "core","com.samlscope.core.evaluation.Evaluator","saml","com.samlscope.saml.normal.SecureXml",
                "store","com.samlscope.store.JsonCodec","api","com.samlscope.api.SamlScopeApplication",
                "peer","com.samlscope.peer.sp.SpPeerService").entrySet()) {
            var type=Class.forName(entry.getValue(),false,VerifySimpleSamlPhpMultipleDecryptionKeysSourceRun.class.getClassLoader());
            Path path=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
            require(path.equals(Path.of("/opt/samlscope/lib/"+entry.getKey()+"-0.1.0.jar"))&&Files.isRegularFile(path),"Read-only state/registry did not load actual installed "+entry.getKey());
            result.put(entry.getKey(),Map.of("class",entry.getValue(),"path",path.toString(),"sha256",hash(Files.readAllBytes(path))));
        }
        return result;
    }
    private interface Mutation {void accept(ObjectNode node)throws Exception;}
    private static void edit(Path folder,String name,Mutation mutation)throws Exception {var node=(ObjectNode)JSON.readTree(original(folder,name));mutation.accept(node);Files.write(folder.resolve(name),JSON.writeValueAsBytes(node));}
    private static void rehash(Path folder)throws Exception {var path=folder.resolve("manifest.json");var node=(ObjectNode)JSON.readTree(Files.readAllBytes(path));var files=(ObjectNode)node.path("files");for(var it=files.fieldNames();it.hasNext();){String name=it.next();if(Files.isRegularFile(folder.resolve(name)))files.put(name,hash(Files.readAllBytes(folder.resolve(name))));}Files.write(path,JSON.writeValueAsBytes(node));}
    private static ObjectNode hashes(Path folder)throws Exception {var result=JSON.createObjectNode();for(var entry:bytes(folder).entrySet())if(!entry.getKey().equals("manifest.json"))result.put(entry.getKey(),hash(entry.getValue()));return result;}
    private static Map<String,byte[]> bytes(Path folder)throws Exception {var result=new TreeMap<String,byte[]>();try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList()){require(!Files.isSymbolicLink(p),"Source symlink");result.put(folder.relativize(p).toString(),Files.readAllBytes(p));}}return result;}
    private static void restore(Path folder,Map<String,byte[]> original)throws Exception {try(var paths=Files.walk(folder)){for(var p:paths.filter(Files::isRegularFile).toList())Files.delete(p);}for(var entry:original.entrySet()){var p=folder.resolve(entry.getKey());Files.createDirectories(p.getParent());Files.write(p,entry.getValue());}}
    private static void copy(Path source,Path target)throws Exception {require(Files.isDirectory(source,LinkOption.NOFOLLOW_LINKS),"Missing source folder");try(var paths=Files.walk(source)){for(var p:paths.toList()){require(!Files.isSymbolicLink(p),"Original symlink");var q=target.resolve(source.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}}
    private static List<TranscriptEntry> entries(Path data,String run)throws Exception {var result=new ArrayList<TranscriptEntry>();try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next())result.add(JSON.readValue(rows.getString(1),TranscriptEntry.class));}}return List.copyOf(result);}
    private static CaseExecution execution(Path data,String run)throws Exception {try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT document_json FROM case_executions WHERE run_id=? AND case_id=?")){q.setString(1,run);q.setString(2,CASE);try(var rows=q.executeQuery()){require(rows.next(),"Recipient actual case execution absent");var e=JSON.readValue(rows.getString(1),CaseExecution.class);require(!rows.next(),"Duplicate recipient case");return e;}}}
    private static Map<String,String> executions(Path data,String run)throws Exception {var result=new TreeMap<String,String>();try(var c=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");var q=c.prepareStatement("SELECT case_id,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")){q.setString(1,run);try(var rows=q.executeQuery()){while(rows.next())result.put(rows.getString(1),hash(rows.getString(2).getBytes(StandardCharsets.UTF_8)));}}return result;}
    private static TranscriptRecorder recorder(String run,List<TranscriptEntry> history){return new TranscriptRecorder(){public List<TranscriptEntry> list(String id){require(run.equals(id),"Foreign source recorder");return history;}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};}
    private static DefaultCaseContext withHistories(CaseContext recipient,String source,List<TranscriptEntry> sourceHistory,String run,List<TranscriptEntry> recipientHistory){var r=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(id.equals(source))return sourceHistory;require(id.equals(run),"Foreign recorder");return recipientHistory;}public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};return new DefaultCaseContext(run,recipient.targetRole(),recipient.clock(),recipient.parameters(),recipient.interaction(),recipient.reachability(),r,true);}
}
