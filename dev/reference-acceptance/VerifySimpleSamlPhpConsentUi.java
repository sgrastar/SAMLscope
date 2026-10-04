package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.*;
import com.samlscope.runner.DefaultCaseContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;

/** Replays archived production code against native originals, then isolates altered-evidence controls. */
public final class VerifySimpleSamlPhpConsentUi {
    static final com.fasterxml.jackson.databind.ObjectMapper MAPPER=new JsonCodec().mapper();
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static void edit(Path folder,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception{
        var node=(ObjectNode)MAPPER.readTree(Files.readAllBytes(folder.resolve(name)));edit.accept(node);Files.write(folder.resolve(name),MAPPER.writeValueAsBytes(node));
        if(!name.equals("manifest.json")){var manifest=(ObjectNode)MAPPER.readTree(Files.readAllBytes(folder.resolve("manifest.json")));((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(folder.resolve("manifest.json"),MAPPER.writeValueAsBytes(manifest));}}
    public static void main(String[] args)throws Exception{
        Path source=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]);String run=MAPPER.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(MAPPER.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var raw=new HashMap<String,byte[]>();
        for(var row:MAPPER.readTree(source.resolve("decoded-manifest.json").toFile())){byte[] value=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!hash(value).equals(row.path("sha256").asText()))throw new IllegalArgumentException();raw.put(row.path("id").asText(),value);}
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException();return entries;}public TranscriptEntry record(TranscriptInput value){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path directory=Files.createTempDirectory("ssp-consent-replay-"),folder=directory.resolve(run);Files.createDirectory(folder);
        var baseline=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(source.resolve("originals"))){for(var p:paths.toList())baseline.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var reader=new SimpleSamlPhpConsentUiEvidence(directory,e->raw.get(e.id()));var controls=new LinkedHashMap<String,String>();
        try{
            for(var row:baseline.entrySet())Files.write(folder.resolve(row.getKey()),row.getValue());var outcome=reader.evaluate(context,target).orElseThrow();System.out.println(outcome.outcome()+" "+outcome.details());
            if(outcome.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Native full display campaign unproven: "+outcome.details());
            var content=(TranscriptContentReader)(e->raw.get(e.id()));
            var actualCase=new UiDisplayBrowserEvidenceTestCase(content,id->target,directory);
            var wrapper=new NativeUiFeatureAbsenceTestCase(actualCase,id->target,new NativeUiFeatureAbsenceEvidence(directory.resolve("unused-absence"),content));
            var previous=CaseOutcome.notVerified("native_browser_evidence_unproven","browser.ui-display.evidence-incomplete");
            var revised=wrapper.reevaluateRecordedEvidence(context,previous).orElseThrow();
            if(!revised.equals(outcome)||!wrapper.queuedEvidenceOutcome(context).equals(outcome)||!wrapper.evidenceStatus(context).ready())throw new IllegalStateException("Actual wrapper blocks native UI proof");
            var normalized=new LinkedHashMap<String,String>();
            for(var variant:List.of("ui-consumer-display-all","ui-consumer-display-service","ui-consumer-display-entity")){
                var xml=com.samlscope.saml.normal.SecureXml.parse(baseline.get(variant+".fixture.xml")).getDocumentElement();
                String original=MAPPER.writeValueAsString(UiDisplayEvidenceFile.fixedMetadata(xml,variant,run));normalized.put(variant,original);
                xml.setAttributeNS("urn:samlscope:negative-control","control:unexpected-policy","changed");String changed=MAPPER.writeValueAsString(UiDisplayEvidenceFile.fixedMetadata(xml,variant,run));
                if(original.equals(changed))throw new IllegalStateException("Structural normalization discards an uncontrolled field");
            }
            if(new HashSet<>(normalized.values()).size()!=1)throw new IllegalStateException("Actual variants change uncontrolled metadata");
            String state=baseline.keySet().stream().filter(n->n.startsWith("ui-consumer-display-all.ui.")&&n.endsWith(".state.json")).findFirst().orElseThrow();
            String browser=state.replace(".state.json",".browser.json");
            for(String control:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","not-restored","restore-different","state-wrong-request","state-wrong-source","state-wrong-destination","browser-wrong-origin","browser-wrong-language","browser-before-request","browser-unknown-name","native-source-changed","missing-original","symlink-original")){
                for(var row:baseline.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}
                switch(control){
                    case "wrong-run"->edit(folder,"manifest.json",v->v.put("runId","run_00000000000000000000000000"));
                    case "wrong-target"->edit(folder,"manifest.json",v->v.put("targetMetadataSha256","0".repeat(64)));
                    case "wrong-campaign"->edit(folder,"manifest.json",v->v.put("campaignId","other"));
                    case "wrong-entity"->edit(folder,"manifest.json",v->v.put("targetEntityId","other"));
                    case "not-restored"->edit(folder,"restoration.json",v->((ObjectNode)v.path("hosted")).put("restored",false));
                    case "restore-different"->{Files.writeString(folder.resolve("hosted-final.php"),"other");}
                    case "state-wrong-request"->edit(folder,state,v->v.put("requestId","other"));
                    case "state-wrong-source"->edit(folder,state,v->v.put("sourceEntityId","other"));
                    case "state-wrong-destination"->edit(folder,state,v->((ObjectNode)v.path("destination")).put("entityid","other"));
                    case "browser-wrong-origin"->edit(folder,browser,v->v.put("origin","http://other"));
                    case "browser-wrong-language"->edit(folder,browser,v->v.put("preferredLanguage","ja"));
                    case "browser-before-request"->edit(folder,browser,v->v.put("recordedAt","1970-01-01T00:00:00Z"));
                    case "browser-unknown-name"->edit(folder,browser,v->v.put("firstParagraph","Unknown"));
                    case "native-source-changed"->{Files.writeString(folder.resolve("native-template.txt"),"other");}
                    case "missing-original"->Files.delete(folder.resolve(state));
                    case "symlink-original"->{Files.delete(folder.resolve(state));Files.createSymbolicLink(folder.resolve(state),source.resolve("originals").resolve(state));}
                }
                if(reader.evaluate(context,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Altered evidence accepted: "+control);controls.put(control,"NOT_VERIFIED");
            }
            Files.write(output,MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcome",outcome,"negative_controls",controls,"wrapper_readiness_and_reevaluation",true,"normalization_controls",Map.of("actual_variants_only_change_approved_fields",true,"uncontrolled_metadata_change_preserved",true),"manifestSha256",hash(baseline.get("manifest.json")),"transcriptSha256",hash(Files.readAllBytes(source.resolve("transcript.json"))),"verdict_adopted",false)),StandardOpenOption.CREATE_NEW);
        }finally{try(var paths=Files.walk(directory)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
