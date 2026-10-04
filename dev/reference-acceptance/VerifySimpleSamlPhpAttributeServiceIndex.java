package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.net.URI;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

/** Actual deployed Reader and shared lifecycle only; no production-class shadowing. */
public final class VerifySimpleSamlPhpAttributeServiceIndex {
    private static final com.fasterxml.jackson.databind.ObjectMapper M=new JsonCodec().mapper();
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void edit(Path folder,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception{
        var value=(ObjectNode)M.readTree(Files.readAllBytes(folder.resolve(name)));edit.accept(value);Files.write(folder.resolve(name),M.writeValueAsBytes(value));
        if(!name.equals("manifest.json")){var manifest=(ObjectNode)M.readTree(Files.readAllBytes(folder.resolve("manifest.json")));((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));}
    }
    private static void reset(Path folder,Map<String,byte[]> originals)throws Exception{for(var row:originals.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}}
    public static void main(String[] args)throws Exception{
        Path source=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]);String run=M.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(M.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var raw=new HashMap<String,byte[]>();
        for(var row:M.readTree(source.resolve("decoded-manifest.json").toFile())){byte[] value=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!hash(value).equals(row.path("sha256").asText()))throw new IllegalArgumentException();raw.put(row.path("id").asText(),value);}
        final String[] alteration={""};var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException();if(alteration[0].isEmpty())return entries;var altered=new ArrayList<>(entries);
            if("duplicate-transcript-id".equals(alteration[0])){altered.set(1,entries.getFirst());return altered;}
            try{int index="foreign-transcript-entry".equals(alteration[0])?0:1;
                var value=(ObjectNode)M.valueToTree(altered.get(index));if(index==0)value.put("runId","run_00000000000000000000000000");else value.put("decodedSamlRef","transcripts/run_00000000000000000000000000/"+entries.get(index).id()+".saml.xml");altered.set(index,M.treeToValue(value,TranscriptEntry.class));return altered;}catch(Exception impossible){throw new IllegalStateException(impossible);}}
            public TranscriptEntry record(TranscriptInput value){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path directory=Files.createTempDirectory("ssp-index-replay-").toRealPath(),nativeDirectory=Files.createDirectory(directory.resolve("attribute-service-index-evidence")),folder=Files.createDirectory(nativeDirectory.resolve(run));
        var originals=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(source.resolve("originals"))){for(var p:paths.toList())originals.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var reader=new SimpleSamlPhpAttributeServiceIndexEvidence(nativeDirectory,e->raw.get(e.id()),id->target,(id,variant)->Optional.empty());var controls=new LinkedHashMap<String,String>();
        try{
            reset(folder,originals);var outcome=reader.evaluate(context).orElseThrow();if(outcome.outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Native signed selector counterexample incomplete: "+outcome.notVerifiedReason());
            var fallback=new TestCase(){public String id(){return "IIP-IDP04-b-idp-01";}public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext c){throw new AssertionError("Native owned proof fell back");}public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){throw new AssertionError("Native owned proof fell back");}};
            var wrapper=new AttributePolicyConfigurationTestCase(fallback,e->raw.get(e.id()),id->target,(id,variant)->Optional.empty(),directory.resolve("attribute-policy-preparations"));
            var finished=new CaseStep.Finish(outcome);if(!wrapper.start(context).equals(finished)||!wrapper.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()).equals(finished)||!wrapper.evidenceStatus(context).ready())throw new IllegalStateException("Shared native lifecycle differs");
            var reevaluated=wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("configuration_pending","case.pending-interaction")).orElseThrow();if(!reevaluated.equals(outcome))throw new IllegalStateException("Shared recorded counterexample differs");
            for(String name:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","wrong-profile","native-factory-changed","native-factory-after-changed","native-attribute-add-changed","native-attribute-map-changed","native-attribute-limit-changed","native-name-map-changed","native-policy-command-changed","native-session-command-changed","native-producer-command-changed","not-restored","restoration-different","state-wrong-request","state-wrong-responder","policy-authproc-unknown","policy-proxy-enabled","policy-authsource-unknown","negative-rejection-unproven","missing-original","symlink-original","foreign-transcript-entry","duplicate-transcript-id","foreign-content-reference","missing-condition","duplicate-condition","wrong-condition-request","wrong-condition-response","matrix-policy-changed","matrix-config-changed","matrix-before-request-missing","matrix-after-response-missing","native-session-changed-midway","native-uid-changed","native-authninstant-changed","native-persistent-association","native-wrong-peer-association","native-unauthenticated","repeated-login","missing-protocol-attempt","native-transport-missing","native-transport-before-request","native-transport-after-response","native-transport-body-hash","native-http-client-changed","native-preprojection-response-hash","wrong-selector","source-principal-alias","producer-wrong-base","producer-unsigned")){
                reset(folder,originals);alteration[0]="";
                switch(name){
                    case "wrong-run"->edit(folder,"manifest.json",n->n.put("runId","run_00000000000000000000000000"));
                    case "wrong-target"->edit(folder,"manifest.json",n->n.put("targetMetadataSha256","0".repeat(64)));
                    case "wrong-campaign"->edit(folder,"manifest.json",n->n.put("campaignId","other"));
                    case "wrong-entity"->edit(folder,"manifest.json",n->n.put("targetEntityId","other"));
                    case "wrong-profile"->edit(folder,"plan.json",n->((ObjectNode)n.at("/plan/plan")).put("profile","metadata_idp"));
                    case "native-factory-changed"->Files.writeString(folder.resolve("native-idp-saml2.php"),"other");
                    case "native-factory-after-changed"->Files.writeString(folder.resolve("native-idp-saml2-after.php"),"other");
                    case "native-session-command-changed"->Files.writeString(folder.resolve("native-session-command.php"),"other");
                    case "not-restored"->edit(folder,"restoration.json",n->((ObjectNode)n.path("remote")).put("restored",false));
                    case "restoration-different"->Files.writeString(folder.resolve("remote-final.php"),"other");
                    case "state-wrong-request"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state")).put("requestId","other"));
                    case "state-wrong-responder"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state")).putArray("responder").add("other").add("sendResponse"));
                    case "policy-authproc-unknown"->edit(folder,"index-0-before.policy.json",n->((ObjectNode)n.path("globalAuthproc")).put("999","core:PHP"));
                    case "policy-proxy-enabled"->edit(folder,"index-0-before.policy.json",n->n.put("proxyAuthnContext",true));
                    case "policy-authsource-unknown"->edit(folder,"index-0-before.policy.json",n->((ObjectNode)n.path("authsource")).put("class","unknown"));
                    case "negative-rejection-unproven"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(0)).put("native_signature_rejection","unknown"));
                    case "missing-original"->Files.delete(folder.resolve("native-state-observations.json"));
                    case "symlink-original"->{Files.delete(folder.resolve("native-state-observations.json"));Files.createSymbolicLink(folder.resolve("native-state-observations.json"),source.resolve("originals/native-state-observations.json"));}
                    case "foreign-transcript-entry","duplicate-transcript-id","foreign-content-reference","scenario-case-id","scenario-fixture-id","scenario-action-id","matrix-request-correlation","matrix-response-correlation"->alteration[0]=name;
                    case "missing-condition"->edit(folder,"manifest.json",n->((com.fasterxml.jackson.databind.node.ArrayNode)n.path("matrix")).remove(1));
                    case "duplicate-condition"->edit(folder,"manifest.json",n->((ObjectNode)n.path("matrix").get(1)).put("key",n.path("matrix").get(0).path("key").asText()));
                    case "wrong-condition-request"->edit(folder,"manifest.json",n->((ObjectNode)n.path("matrix").get(1)).put("requestReference",n.path("matrix").get(0).path("requestReference").asText()));
                    case "wrong-condition-response"->edit(folder,"manifest.json",n->((ObjectNode)n.path("matrix").get(1)).put("responseReference",n.path("matrix").get(0).path("responseReference").asText()));
                    case "matrix-policy-changed"->edit(folder,"index-1-before.policy.json",n->n.put("proxyAuthnContext",true));
                    case "matrix-config-changed"->Files.writeString(folder.resolve("index-1-after.remote.php"),"other");
                    case "matrix-before-request-missing"->edit(folder,"index-1-before.observed.json",n->n.put("recordedAt","2100-01-01T00:00:00Z"));
                    case "matrix-after-response-missing"->edit(folder,"index-1-after.observed.json",n->n.put("recordedAt","1970-01-01T00:00:00Z"));
                    case "native-session-changed-midway"->edit(folder,"index-1-before.session.json",n->n.put("sessionSha256","0".repeat(64)));
                    case "native-uid-changed"->edit(folder,"index-1-after.session.json",n->n.putArray("uid").add("other"));
                    case "native-authninstant-changed"->edit(folder,"index-1-before.session.json",n->n.put("authnInstant",0));
                    case "native-persistent-association"->edit(folder,"index-1-after.session.json",n->((ObjectNode)n.path("associations").get(0)).put("nameIdFormat","urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));
                    case "native-wrong-peer-association"->edit(folder,"index-1-before.session.json",n->((ObjectNode)n.path("associations").get(0)).put("entity","other"));
                    case "native-unauthenticated"->edit(folder,"index-1-after.session.json",n->n.put("authenticated",false));
                    case "repeated-login"->edit(folder,"operation-counts.json",n->n.put("credentialPosts",2));
                    case "missing-protocol-attempt"->edit(folder,"operation-counts.json",n->n.put("protocolOperationsAttempted",4));
                    case "native-transport-missing"->edit(folder,"native-http-observations.json",n->((com.fasterxml.jackson.databind.node.ArrayNode)n.path("records")).remove(3));
                    case "native-transport-before-request"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(3)).put("started_at","1970-01-01T00:00:00Z"));
                    case "native-transport-after-response"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(3)).put("observed_at","2100-01-01T00:00:00Z"));
                    case "native-transport-body-hash"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(3)).put("request_body_sha256","0".repeat(64)));
                    case "native-http-client-changed"->Files.writeString(folder.resolve("native-http-client.py"),"other");
                    case "native-attribute-add-changed"->Files.writeString(folder.resolve("native-attribute-add.php"),"other");
                    case "native-attribute-map-changed"->Files.writeString(folder.resolve("native-attribute-map.php"),"other");
                    case "native-attribute-limit-changed"->Files.writeString(folder.resolve("native-attribute-limit.php"),"other");
                    case "native-name-map-changed"->Files.writeString(folder.resolve("native-name2oid-map.php"),"other");
                    case "native-policy-command-changed"->Files.writeString(folder.resolve("native-policy-command.php"),"other");
                    case "native-producer-command-changed"->Files.writeString(folder.resolve("producer-controls.native-producer-command.php"),"other");
                    case "wrong-selector"->edit(folder,"manifest.json",n->((ObjectNode)n.path("matrix").get(1)).put("selector",0));
                    case "source-principal-alias"->edit(folder,"index-0-before.policy.json",n->((ObjectNode)n.path("publicPrincipals").get(0)).put("principal","other"));
                    case "producer-wrong-base"->edit(folder,"producer-controls.manifest.json",n->((ObjectNode)n.path("records").get(0)).put("baseResponseReference",n.path("records").get(2).path("baseResponseReference").asText()));
                    case "producer-unsigned"->Files.writeString(folder.resolve("producer-controls.correct-index-one.xml"),"<Response/>");
                    case "native-preprojection-response-hash"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(3)).put("response_body_sha256","0".repeat(64)));
                }
                if(reader.evaluate(context).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Altered original accepted: "+name);controls.put(name,"NOT_VERIFIED");
                if(!(wrapper.start(context)instanceof CaseStep.Finish finish)||finish.outcome().outcome()!=Outcome.NOT_VERIFIED||wrapper.evidenceStatus(context).ready())throw new IllegalStateException("Owned invalid proof starts another browser scenario: "+name);
            }
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcome",outcome,"recorded_wrapper_outcome",reevaluated,"negative_controls",controls,"shared_native_scenario_lifecycle",true,"required_selector_conditions",3,"configuration_precondition_supplied",true,"manifestSha256",hash(originals.get("manifest.json")),"transcriptSha256",hash(Files.readAllBytes(source.resolve("transcript.json"))),"verdict_adopted",false)),StandardOpenOption.CREATE_NEW);
        }finally{try(var paths=Files.walk(directory)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
