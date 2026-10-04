package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Runs only archived production classes against immutable originals and semantic alterations. */
public final class VerifySimpleSamlPhpSubjectConfirmation {
    private record UnreachableFallback(String id) implements TestCase,ConfigurationPrompt,AttestationPrompt{
        public TargetRole role(){return TargetRole.IDP;}public String instructionEn(){return "original CONFIG";}public String promptEn(){return "original CONFIG";}public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext context){throw new AssertionError("Owned proof cannot fallback to declarations");}
        public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){throw new AssertionError("Owned proof cannot fallback to declarations");}
    }
    private static final com.fasterxml.jackson.databind.ObjectMapper M=new JsonCodec().mapper();
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void edit(Path folder,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception{
        var node=(ObjectNode)M.readTree(Files.readAllBytes(folder.resolve(name)));edit.accept(node);Files.write(folder.resolve(name),M.writeValueAsBytes(node));
        if(!name.equals("manifest.json")){var manifest=(ObjectNode)M.readTree(Files.readAllBytes(folder.resolve("manifest.json")));((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));}
    }
    private static void reset(Path folder,Map<String,byte[]> originals)throws Exception{for(var row:originals.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}}
    public static void main(String[] args)throws Exception{
        Path source=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]);String run=M.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(M.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var raw=new HashMap<String,byte[]>();
        for(var row:M.readTree(source.resolve("decoded-manifest.json").toFile())){byte[] value=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!hash(value).equals(row.path("sha256").asText()))throw new IllegalArgumentException();raw.put(row.path("id").asText(),value);}
        final String[] transcriptAlteration={""};
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException();
            if(transcriptAlteration[0].isEmpty())return entries;var altered=new ArrayList<>(entries);
            if("duplicate-transcript-id".equals(transcriptAlteration[0])){altered.set(1,entries.getFirst());return altered;}
            try{int index="foreign-transcript-entry".equals(transcriptAlteration[0])?0:1;var value=(ObjectNode)M.valueToTree(altered.get(index));
                if(index==0)value.put("runId","run_00000000000000000000000000");else value.put("decodedSamlRef","transcripts/run_00000000000000000000000000/"+entries.get(index).id()+".saml.xml");
                altered.set(index,M.treeToValue(value,TranscriptEntry.class));return altered;
            }catch(Exception impossible){throw new IllegalStateException(impossible);}}public TranscriptEntry record(TranscriptInput value){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path directory=Files.createTempDirectory("ssp-attester-replay-").toRealPath(),folder=Files.createDirectory(directory.resolve(run));
        var originals=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(source.resolve("originals"))){for(var p:paths.toList())originals.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var reader=new SimpleSamlPhpSubjectConfirmationEvidence(directory,e->raw.get(e.id()),id->"browser_sso_idp");var outcomes=new LinkedHashMap<String,CaseOutcome>();var controls=new LinkedHashMap<String,String>();
        try{
            reset(folder,originals);for(String id:List.of(SimpleSamlPhpSubjectConfirmationEvidence.FR,SimpleSamlPhpSubjectConfirmationEvidence.GD)){
                var result=reader.evaluate(context,id,target).orElseThrow();if(result.outcome()!=Outcome.SATISFIED_WITH_NOTE)throw new IllegalStateException("Native stock proof incomplete: "+result.details());outcomes.put(id,result);
                var wrapper=new SubjectConfirmationConfigurationTestCase(new UnreachableFallback(id),e->raw.get(e.id()),r->target,directory,r->"browser_sso_idp");
                var finished=new CaseStep.Finish(result);if(!wrapper.start(context).equals(finished)||!wrapper.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()).equals(finished)
                    ||!wrapper.evidenceStatus(context).ready()||!wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("case.pending-interaction","case.pending-interaction")).orElseThrow().equals(result))throw new IllegalStateException("Shared native CONFIG lifecycle blocks exact original outcome");
                if(!wrapper.resolvedFromExternalEvidence(new CaseExecution(run,id,1,CaseExecutionStatus.FINISHED,CaseState.initial(),null,result,java.time.Instant.now())))throw new IllegalStateException("Native original outcome loses matching case/Run provenance");
            }
            for(String name:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","native-factory-changed","native-factory-after-changed","not-restored","restoration-different","state-wrong-request","state-wrong-responder","state-wrong-binding","state-different-peer","state-before-request","state-after-response","policy-authproc-unknown","policy-proxy-enabled","policy-authsource-unknown","policy-host-foreign-attester","policy-peer-multiple-attesters","negative-response-unproven","native-signed-control-tampered","native-semantic-control-swapped","missing-original","symlink-original","wrong-profile","foreign-transcript-entry","duplicate-transcript-id","foreign-content-reference")){
                reset(folder,originals);transcriptAlteration[0]="";
                switch(name){
                    case "wrong-run"->edit(folder,"manifest.json",n->n.put("runId","run_00000000000000000000000000"));
                    case "wrong-target"->edit(folder,"manifest.json",n->n.put("targetMetadataSha256","0".repeat(64)));
                    case "wrong-campaign"->edit(folder,"manifest.json",n->n.put("campaignId","other"));
                    case "wrong-entity"->edit(folder,"manifest.json",n->n.put("targetEntityId","other"));
                    case "native-factory-changed"->Files.writeString(folder.resolve("native-idp-saml2.php"),"other");
                    case "native-factory-after-changed"->Files.writeString(folder.resolve("native-idp-saml2-after.php"),"other");
                    case "not-restored"->edit(folder,"restoration.json",n->((ObjectNode)n.path("remote")).put("restored",false));
                    case "restoration-different"->Files.writeString(folder.resolve("remote-final.php"),"other");
                    case "state-wrong-request"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state")).put("requestId","other"));
                    case "state-wrong-responder"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state")).putArray("responder").add("other").add("sendResponse"));
                    case "state-wrong-binding"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state")).put("binding","urn:other"));
                    case "state-different-peer"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0).path("state").path("spMetadata")).put("entityid","other"));
                    case "state-before-request"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0)).put("recordedAt","1970-01-01T00:00:00Z"));
                    case "state-after-response"->edit(folder,"native-state-observations.json",n->((ObjectNode)n.path("observations").get(0)).put("recordedAt","2100-01-01T00:00:00Z"));
                    case "policy-authproc-unknown"->edit(folder,"before.policy.json",n->((ObjectNode)n.path("globalAuthproc")).put("999","core:PHP"));
                    case "policy-proxy-enabled"->edit(folder,"before.policy.json",n->n.put("proxyAuthnContext",true));
                    case "policy-authsource-unknown"->edit(folder,"before.policy.json",n->((ObjectNode)n.path("authsource")).put("class","other"));
                    case "policy-host-foreign-attester"->edit(folder,"before.policy.json",n->((ObjectNode)n.path("hosted")).put("attestingEntity","other"));
                    case "policy-peer-multiple-attesters"->edit(folder,"before.policy.json",n->((ObjectNode)n.path("peer")).putArray("attesters").add("one").add("two"));
                    case "negative-response-unproven"->edit(folder,"native-http-observations.json",n->((ObjectNode)n.path("records").get(0)).put("native_signature_rejection","unknown"));
                    case "native-signed-control-tampered"->Files.writeString(folder.resolve("foreign-positive.xml"),"<Response/>");
                    case "native-semantic-control-swapped"->{Files.write(folder.resolve("multiple-positive.xml"),originals.get("multiple-packed-identifiers.xml"));var manifest=(ObjectNode)M.readTree(folder.resolve("manifest.json").toFile());((ObjectNode)manifest.path("files")).put("multiple-positive.xml",hash(originals.get("multiple-packed-identifiers.xml")));Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));}
                    case "missing-original"->Files.delete(folder.resolve("native-state-observations.json"));
                    case "symlink-original"->{Files.delete(folder.resolve("native-state-observations.json"));Files.createSymbolicLink(folder.resolve("native-state-observations.json"),source.resolve("originals/native-state-observations.json"));}
                    case "wrong-profile"->{}
                    case "foreign-transcript-entry","duplicate-transcript-id","foreign-content-reference"->transcriptAlteration[0]=name;
                }
                var altered=name.equals("wrong-profile")?new SimpleSamlPhpSubjectConfirmationEvidence(directory,e->raw.get(e.id()),id->"metadata_idp"):reader;
                for(String id:outcomes.keySet())if(altered.evaluate(context,id,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Altered evidence accepted: "+name+" "+id);controls.put(name,"NOT_VERIFIED");
            }
            reset(folder,originals);transcriptAlteration[0]="";
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcomes",outcomes,"negative_controls",controls,"native_signed_semantic_controls",4,"shared_native_config_lifecycle",true,"manifestSha256",hash(originals.get("manifest.json")),"transcriptSha256",hash(Files.readAllBytes(source.resolve("transcript.json"))),"verdict_adopted",false)),StandardOpenOption.CREATE_NEW);
        }finally{try(var paths=Files.walk(directory)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
