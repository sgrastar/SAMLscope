package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import com.samlscope.core.transcript.*;
import com.samlscope.core.caseexec.*;
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
public final class VerifySimpleSamlPhpConsentUri {
    private record UnreachableFallback(String id) implements TestCase{
        public TargetRole role(){return TargetRole.IDP;}public CaseStep start(CaseContext context){throw new AssertionError("Owned native proof cannot fallback");}public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){throw new AssertionError("Owned native proof cannot fallback");}}
    static final com.fasterxml.jackson.databind.ObjectMapper MAPPER=new JsonCodec().mapper();
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    static void edit(Path folder,String name,java.util.function.Consumer<ObjectNode> edit)throws Exception{
        var node=(ObjectNode)MAPPER.readTree(Files.readAllBytes(folder.resolve(name)));edit.accept(node);Files.write(folder.resolve(name),MAPPER.writeValueAsBytes(node));
        if(!name.equals("manifest.json")){var manifest=(ObjectNode)MAPPER.readTree(Files.readAllBytes(folder.resolve("manifest.json")));((ObjectNode)manifest.path("files")).put(name,hash(Files.readAllBytes(folder.resolve(name))));Files.write(folder.resolve("manifest.json"),MAPPER.writeValueAsBytes(manifest));
            if(name.endsWith(".browser.json")||name.endsWith(".state.json")||name.endsWith(".state-after.json")){
                String field=name.endsWith(".browser.json")?"browserSha256":name.endsWith(".state-after.json")?"stateAfterSha256":"stateSha256";
                var observations=(ObjectNode)MAPPER.readTree(Files.readAllBytes(folder.resolve("native-ui-observations.json")));
                for(var item:observations.path("observations"))if(name.contains(".ui."+item.path("requestId").asText()+"."))((ObjectNode)item).put(field,hash(Files.readAllBytes(folder.resolve(name))));
                Files.write(folder.resolve("native-ui-observations.json"),MAPPER.writeValueAsBytes(observations));((ObjectNode)manifest.path("files")).put("native-ui-observations.json",hash(Files.readAllBytes(folder.resolve("native-ui-observations.json"))));Files.write(folder.resolve("manifest.json"),MAPPER.writeValueAsBytes(manifest));
            }
        }}
    public static void main(String[] args)throws Exception{
        Path source=Path.of(args[0]).toAbsolutePath(),output=Path.of(args[1]);String run=MAPPER.readTree(source.resolve("created.json").toFile()).at("/run/id").asText();
        var entries=List.of(MAPPER.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var raw=new HashMap<String,byte[]>();
        for(var row:MAPPER.readTree(source.resolve("decoded-manifest.json").toFile())){byte[] value=Files.readAllBytes(source.resolve(row.path("file").asText()));if(!hash(value).equals(row.path("sha256").asText()))throw new IllegalArgumentException();raw.put(row.path("id").asText(),value);}
        var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){if(!run.equals(id))throw new IllegalArgumentException();return entries;}public TranscriptEntry record(TranscriptInput value){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));Path base=Files.createTempDirectory("ssp-consent-uri-replay-").toRealPath(),directory=Files.createDirectory(base.resolve("ui-consent-uri-evidence")),folder=directory.resolve(run);Files.createDirectory(folder);
        var baseline=new LinkedHashMap<String,byte[]>();try(var paths=Files.list(source.resolve("originals"))){for(var p:paths.toList())baseline.put(p.getFileName().toString(),Files.readAllBytes(p));}
        var reader=new SimpleSamlPhpConsentUriEvidence(directory,e->raw.get(e.id()));var controls=new LinkedHashMap<String,String>();
        try{
            for(var row:baseline.entrySet())Files.write(folder.resolve(row.getKey()),row.getValue());
            CaseOutcome outcome=reader.evaluate(context,target).orElseThrow(),discovery=reader.evaluateDiscovery(context,target).orElseThrow();
            if(outcome.outcome()!=Outcome.VIOLATED||!"browser.ui-url.disallowed-scheme-used".equals(outcome.reasonCode())||discovery.outcome()!=Outcome.SATISFIED_WITH_NOTE)throw new IllegalStateException("Native full URI/discovery proof unproven: "+outcome.details()+" "+discovery.details());
            var uriCase=new UiUrlBrowserEvidenceTestCase(e->raw.get(e.id()),id->target,directory.resolveSibling("ui-url-evidence"));
            var discoveryCase=new NativeUiFeatureAbsenceTestCase(new UnreachableFallback("IIP-MD05-fb-idp-01"),id->target,new NativeUiFeatureAbsenceEvidence(directory.resolveSibling("ui-native-feature-absence"),e->raw.get(e.id())),new ShibbolethUiConsumerEvidence(directory.resolveSibling("ui-url-evidence"),e->raw.get(e.id())),reader);
            for(var check:List.of(Map.entry((QueuedProtocolEvidenceCase)uriCase,outcome),Map.entry((QueuedProtocolEvidenceCase)discoveryCase,discovery))){
                var test=(TestCase)check.getKey();var expected=check.getValue();var recorded=(com.samlscope.runner.RecordedEvidenceReevaluation)test;
                if(!test.start(context).equals(new CaseStep.Finish(expected))||!test.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()).equals(new CaseStep.Finish(expected))||!check.getKey().queuedEvidenceOutcome(context).equals(expected)||!check.getKey().evidenceStatus(context).ready()
                    ||!recorded.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("native_browser_evidence_unproven","browser.ui-url.evidence-incomplete")).orElseThrow().equals(expected))throw new IllegalStateException("Shared URI/discovery lifecycle changes exact native outcome");
            }
            var normalized=new HashSet<Object>();var manifest=MAPPER.readTree(baseline.get("manifest.json"));
            for(var condition:manifest.path("conditions")){String variant=condition.path("variant").asText();if(variant.equals("control"))continue;
                var original=com.samlscope.saml.normal.SecureXml.parse(baseline.get(variant+".fixture.xml")).getDocumentElement();var value=SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(original,variant,run);normalized.add(value);
                var changed=(org.w3c.dom.Element)original.cloneNode(true);changed.setAttributeNS("urn:extra","extra:policy","changed");if(value.equals(SimpleSamlPhpConsentUriEvidence.noUrlFixedMetadata(changed,variant,run)))throw new IllegalStateException("URI normalization ignores uncontrolled policy");
            }if(normalized.size()!=1)throw new IllegalStateException("URI inputs differ outside explicit certificate/URL variation");
            String state=baseline.keySet().stream().filter(n->n.startsWith("ui-url-logo-http.ui.")&&n.endsWith(".state.json")).findFirst().orElseThrow();
            String browser=state.replace(".state.json",".browser.json");
            for(String control:List.of("wrong-run","wrong-target","wrong-campaign","wrong-entity","not-restored","restore-different","state-wrong-request","state-wrong-source","state-wrong-destination","browser-wrong-origin","browser-wrong-language","browser-before-request","browser-unknown-name","browser-sp-logo","browser-image-unloaded","browser-resource-tampered","policy-controller","policy-head-override","state-after-changed","native-source-after-changed","native-source-changed","missing-original","symlink-original")){
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
                    case "browser-sp-logo"->edit(folder,browser,v->((ObjectNode)v.path("images").get(0)).put("src","data:image/svg+xml;base64,PHN2Zy8+"));
                    case "browser-image-unloaded"->edit(folder,browser,v->((ObjectNode)v.path("images").get(0)).put("naturalWidth",0));
                    case "browser-resource-tampered"->edit(folder,browser,v->((ObjectNode)v.path("resources").get(0)).put("sha256","0".repeat(64)));
                    case "policy-controller"->edit(folder,"ui-url-logo-http.before.policy.json",v->v.put("themeController","Other"));
                    case "policy-head-override"->edit(folder,"ui-url-logo-http.before.policy.json",v->v.put("optionalHeadExists",true));
                    case "state-after-changed"->edit(folder,state.replace(".state.json",".state-after.json"),v->v.put("requestId","other"));
                    case "native-source-after-changed"->{Files.writeString(folder.resolve("native-footer-template-after.txt"),"other");}
                    case "native-source-changed"->{Files.writeString(folder.resolve("native-template.txt"),"other");}
                    case "missing-original"->Files.delete(folder.resolve(state));
                    case "symlink-original"->{Files.delete(folder.resolve(state));Files.createSymbolicLink(folder.resolve(state),source.resolve("originals").resolve(state));}
                }
                if(reader.evaluate(context,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED||reader.evaluateDiscovery(context,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Altered evidence accepted: "+control);controls.put(control,"NOT_VERIFIED");
            }
            for(var row:baseline.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}
            var uriControls=new LinkedHashMap<String,String>();String privacyData=baseline.keySet().stream().filter(n->n.startsWith("ui-url-privacy-data.ui.")&&n.endsWith(".browser.json")).findFirst().orElseThrow();
            for(String control:List.of("dom-only-no-signal","window-open-without-user-gesture","window-open-before-click","link-wrong-element","link-wrong-href","link-wrong-native-slot","link-wrong-service-caption")){
                for(var row:baseline.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}
                edit(folder,privacyData,v->{switch(control){
                    case "dom-only-no-signal"->{v.putArray("urlWindowOpens");v.putArray("urlRequests");v.putArray("urlNavigations");v.putArray("urlConsole");}
                    case "window-open-without-user-gesture"->((ObjectNode)v.path("urlWindowOpens").get(0)).put("userGesture",false);
                    case "window-open-before-click"->((ObjectNode)v.path("urlWindowOpens").get(0)).put("recordedAt","1970-01-01T00:00:00Z");
                    case "link-wrong-element"->((ObjectNode)v.path("nativeLinkUse")).put("element","Logo");
                    case "link-wrong-href"->((ObjectNode)v.path("nativeLinkUse")).put("href","data:text/plain,other");
                    case "link-wrong-native-slot"->((ObjectNode)v.path("nativeLinkUse")).put("anchorOuterHtml","<a href='data:text/plain,other'>Other link</a>");
                    case "link-wrong-service-caption"->{var link=(ObjectNode)v.path("nativeLinkUse");link.put("anchorOuterHtml",link.path("anchorOuterHtml").asText().replace("SAMLscope URL policy control","Other service"));}
                }});
                if(reader.evaluate(context,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("URI use control accepted: "+control);uriControls.put(control,"NOT_VERIFIED");
            }
            var discoveryControls=new LinkedHashMap<String,String>();
            for(String control:List.of("unknown-authsource","custom-authproc","challenge-wrong-request","challenge-after-response","challenge-other-responder")){
                for(var row:baseline.entrySet()){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}
                switch(control){
                    case "unknown-authsource"->edit(folder,"control.before.authentication-policy.json",v->((ObjectNode)v.path("authsource")).put("class","unknown"));
                    case "custom-authproc"->edit(folder,"control.before.authentication-policy.json",v->((ObjectNode)v.path("globalAuthproc")).put("999","core:PHP"));
                    case "challenge-wrong-request"->edit(folder,"native-authentication-observations.json",v->((ObjectNode)v.path("observations").get(0).path("state")).put("requestId","other"));
                    case "challenge-after-response"->edit(folder,"native-authentication-observations.json",v->((ObjectNode)v.path("observations").get(0)).put("recordedAt","2100-01-01T00:00:00Z"));
                    case "challenge-other-responder"->edit(folder,"native-authentication-observations.json",v->((ObjectNode)v.path("observations").get(0).path("state")).putArray("responder").add("custom").add("sendResponse"));
                }
                if(reader.evaluateDiscovery(context,target).orElseThrow().outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Discovery control accepted: "+control);discoveryControls.put(control,"NOT_VERIFIED");
            }
            Files.write(output,MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcomes",Map.of("IIP-MD05-fh-idp-01",outcome,"IIP-MD05-fb-idp-01",discovery),"negative_controls",controls,"uri_use_controls",uriControls,"discovery_controls",discoveryControls,"manifestSha256",hash(baseline.get("manifest.json")),"transcriptSha256",hash(Files.readAllBytes(source.resolve("transcript.json"))),"shared_native_ui_lifecycle",true,"verdict_adopted",false)),StandardOpenOption.CREATE_NEW);
        }finally{try(var paths=Files.walk(base)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
}
