package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.*;
import java.time.Clock;
import java.util.*;

/** Replay actual public originals against the production reader. No product/API activity. */
public final class VerifyShibbolethNativeUiEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final List<String> IDS=List.of("IIP-MD05-fb-idp-01","IIP-MD05-fg-idp-01","IIP-MD05-fh-idp-01","IIP-MD05-fj-idp-01");
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static ObjectNode row(ObjectNode manifest,String variant){
        for(var row:manifest.path("observations"))if(variant.equals(row.path("variant").asText()))return(ObjectNode)row;
        throw new IllegalArgumentException("Missing row");
    }
    private static void replace(Path folder,ObjectNode row,String file,String digest,byte[] bytes)throws Exception {
        Files.write(folder.resolve(row.path(file).asText()),bytes);row.put(digest,hash(bytes));
    }
    private static Optional<CaseOutcome> evaluate(Path root,ObjectNode manifest,List<TranscriptEntry> entries,Map<String,byte[]> bodies,byte[] target,String id,boolean complete)throws Exception {
        String run=manifest.path("runId").asText();var original=root.resolve(run).resolve("manifest.json");
        // Preserve actual physical originals for baseline evidence hashes. Only a deliberate
        // mutation writes new bytes; equivalent JSON reserialization is not a product test.
        if(!Files.exists(original)||!manifest.equals(JSON.mapper().readTree(Files.readAllBytes(original))))
            Files.write(original,JSON.mapper().writeValueAsBytes(manifest));
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String r){if(!run.equals(r))throw new IllegalArgumentException();return entries;}
            public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
        return new ShibbolethUiConsumerEvidence(root,e->bodies.get(e.id())).read(context,target,id);
    }
    private static void restore(Path source,Path folder)throws Exception {
        try(var paths=Files.walk(source)){for(var path:paths.toList()) {
            var destination=folder.resolve(source.relativize(path));
            if(Files.isDirectory(path)){Files.createDirectories(destination);continue;}
            if(Files.isSymbolicLink(path))throw new IllegalArgumentException("Symbolic link original");
            Files.copy(path,destination,StandardCopyOption.REPLACE_EXISTING);
        }}
    }
    public static void main(String[]args)throws Exception {
        var source=Path.of(args[0]);var output=Path.of(args[1]);if(Files.exists(output))throw new IllegalArgumentException("Immutable replay exists");
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var base=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(source.resolve("manifest.json")));String run=base.path("runId").asText();
        var entries=List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));var bodies=new HashMap<String,byte[]>();
        for(var entry:entries)if(entry.decodedSamlRef()!=null){var raw=Files.readAllBytes(source.resolve("decoded").resolve(entry.id()+".xml"));
            if(raw.length!=entry.decodedSamlBytes())throw new IllegalArgumentException("Original size changed");bodies.put(entry.id(),raw);}
        var target=Files.readAllBytes(source.resolve("target-metadata.xml"));var root=Files.createTempDirectory("native-ui-reader-replay-");var folder=root.resolve(run);
        var actual=new LinkedHashMap<String,CaseOutcome>();var controls=new LinkedHashMap<String,String>();
        try {
            restore(source,folder);
            for(var id:IDS){var outcome=evaluate(root,base.deepCopy(),entries,bodies,target,id,true).orElseThrow(()->new IllegalStateException("Actual original not accepted "+id));
                if(outcome.outcome()!=(id.contains("-fj-")?Outcome.VIOLATED:Outcome.SATISFIED_WITH_NOTE))throw new IllegalStateException("Unexpected actual "+id+" "+outcome);
                actual.put(id,outcome);}
            for(var mutation:List.of("missing-variant","missing-fg-javascript","wrong-run","foreign-run-entry","duplicate-entry","wrong-target", "wrong-runtime", "missing-native-class", "wrong-getter-source",
                "wrong-restoration","missing-readback","late-before","wrong-browser-request","populated-hidden-token","dom-assignment-only","missing-slot-control","wrong-slot-control","unknown-dialog","target-response-bad-signature","unsigned-request","discovery-flow-enabled","incomplete-transcript","non-target-case")) {
                restore(source,folder);var manifest=base.deepCopy();var changedEntries=entries;var changedBodies=new HashMap<>(bodies);byte[] changedTarget=target;boolean complete=true;
                String id=mutation.equals("missing-fg-javascript")||mutation.contains("slot-control")||mutation.equals("unknown-dialog")?IDS.get(1):mutation.equals("dom-assignment-only")?IDS.get(2):IDS.get(0);
                switch(mutation) {
                    case "missing-variant" -> {for(int i=0;i<manifest.path("observations").size();i++)if("full-ui-info".equals(manifest.path("observations").get(i).path("variant").asText()))((com.fasterxml.jackson.databind.node.ArrayNode)manifest.path("observations")).remove(i);}
                    case "missing-fg-javascript" -> {for(int i=0;i<manifest.path("observations").size();i++)if("ui-safety-information-javascript".equals(manifest.path("observations").get(i).path("variant").asText()))((com.fasterxml.jackson.databind.node.ArrayNode)manifest.path("observations")).remove(i);}
                    case "wrong-run" -> manifest.put("runId","run_00000000000000000000000000");
                    case "foreign-run-entry" -> {var e=entries.getFirst();var wrong=new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary());var copy=new ArrayList<>(entries);copy.set(0,wrong);changedEntries=copy;}
                    case "duplicate-entry" -> {var copy=new ArrayList<>(entries);copy.add(entries.getFirst());changedEntries=copy;}
                    case "wrong-target" -> changedTarget="<wrong/>".getBytes();
                    case "wrong-runtime" -> {var value=(ObjectNode)JSON.mapper().readTree(folder.resolve(manifest.path("runtimeAfterFile").asText()).toFile());((ObjectNode)value.path("binding")).put("image_id","sha256:wrong");replace(folder,manifest,"runtimeAfterFile","runtimeAfterSha256",JSON.mapper().writeValueAsBytes(value));}
                    case "missing-native-class" -> Files.delete(folder.resolve(manifest.path("nativeClassFile").asText()));
                    case "wrong-getter-source" -> replace(folder,manifest,"nativeGetterSourceFile","nativeGetterSourceSha256","untrusted source".getBytes());
                    case "wrong-restoration" -> {var value=(ObjectNode)manifest.path("configurationFiles").get(0);replace(folder,value,"finalFile","finalSha256","different state".getBytes());}
                    case "missing-readback" -> ((com.fasterxml.jackson.databind.node.ArrayNode)row(manifest,"full-ui-info").path("readBacks")).remove(0);
                    case "late-before" -> ((ObjectNode)row(manifest,"full-ui-info").path("readBacks").get(0)).put("recordedAt","2099-01-01T00:00:00Z");
                    case "wrong-browser-request" -> {var value=row(manifest,"full-ui-info");var browser=(ObjectNode)JSON.mapper().readTree(folder.resolve(value.path("browserFile").asText()).toFile());((ObjectNode)browser.path("requests").get(0)).put("requestId","_wrong");replace(folder,value,"browserFile","browserSha256",JSON.mapper().writeValueAsBytes(browser));}
                    case "populated-hidden-token" -> {var value=row(manifest,"full-ui-info");var body=new String(Files.readAllBytes(folder.resolve(value.path("challengeFile").asText()))).replace("[REDACTED]","unsafe-token");replace(folder,value,"challengeFile","challengeSha256",body.getBytes());var browser=(ObjectNode)JSON.mapper().readTree(folder.resolve(value.path("browserFile").asText()).toFile());((ObjectNode)browser.path("challenge")).put("bodySha256",hash(body.getBytes()));replace(folder,value,"browserFile","browserSha256",JSON.mapper().writeValueAsBytes(browser));}
                    case "dom-assignment-only" -> {var value=row(manifest,"ui-url-logo-https");var browser=(ObjectNode)JSON.mapper().readTree(folder.resolve(value.path("browserFile").asText()).toFile());browser.remove("resources");replace(folder,value,"browserFile","browserSha256",JSON.mapper().writeValueAsBytes(browser));}
                    case "missing-slot-control" -> Files.delete(folder.resolve(row(manifest,"ui-safety-logo-data").path("slotControlFile").asText()));
                    case "wrong-slot-control" -> {var value=row(manifest,"ui-safety-logo-data");var slot=(ObjectNode)JSON.mapper().readTree(folder.resolve(value.path("slotControlFile").asText()).toFile());slot.put("scope","isolated-top-level-svg");replace(folder,value,"slotControlFile","slotControlSha256",JSON.mapper().writeValueAsBytes(slot));}
                    case "unknown-dialog" -> {var value=row(manifest,"ui-safety-logo-data");var browser=(ObjectNode)JSON.mapper().readTree(folder.resolve(value.path("browserFile").asText()).toFile());browser.putArray("dialogs").addObject().put("type","alert").put("probeToken",false);replace(folder,value,"browserFile","browserSha256",JSON.mapper().writeValueAsBytes(browser));}
                    case "target-response-bad-signature" -> {var response=entries.stream().filter(e->"Response".equals(e.samlSummary().get("type"))&&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(e.samlSummary().get("statusCode"))).findFirst().orElseThrow();var raw=new String(bodies.get(response.id()));raw=raw.replaceFirst("(?s)(<ds:SignatureValue[^>]*>)([A-Za-z0-9])","$1?");changedBodies.put(response.id(),raw.getBytes());}
                    case "unsigned-request" -> {var ref=row(manifest,"full-ui-info").path("requestReference").asText();var raw=new String(bodies.get(ref)).replaceFirst("(?s)<ds:Signature\\b.*?</ds:Signature>","");changedBodies.put(ref,raw.getBytes());}
                    case "discovery-flow-enabled" -> {var value=(ObjectNode)manifest.path("configurationFiles").get(5);replace(folder,value,"originalFile","originalSha256","idp.ui.fallbackLanguages=en,fr,de\nidp.authn.flows=Password|Discovery\n".getBytes());replace(folder,value,"finalFile","finalSha256","idp.ui.fallbackLanguages=en,fr,de\nidp.authn.flows=Password|Discovery\n".getBytes());}
                    case "incomplete-transcript" -> complete=false;
                    case "non-target-case" -> id="IIP-MD05-fa-idp-01";
                }
                // A wrong-run manifest names a nonexistent folder; do not create that folder.
                Optional<CaseOutcome> result;
                if(mutation.equals("wrong-run")) {
                    Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
                    var original=base.deepCopy();original.put("runId",run);
                    // The context still owns the original Run while the receipt claims another.
                    var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return entries;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
                    var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
                    result=new ShibbolethUiConsumerEvidence(root,e->bodies.get(e.id())).read(context,target,id);
                }else result=evaluate(root,manifest,changedEntries,changedBodies,changedTarget,id,complete);
                if(result.isPresent())throw new IllegalStateException("Unproven mutation accepted: "+mutation+" "+result);
                controls.put(mutation,"NOT_VERIFIED");
            }
            restore(source,folder);var execution=base.deepCopy();var row=row(execution,"ui-safety-logo-data");var browser=(ObjectNode)JSON.mapper().readTree(folder.resolve(row.path("browserFile").asText()).toFile());
            browser.putArray("dialogs").addObject().put("type","alert").put("probeToken",true);replace(folder,row,"browserFile","browserSha256",JSON.mapper().writeValueAsBytes(browser));
            if(evaluate(root,execution,entries,bodies,target,IDS.get(1),true).orElseThrow().outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Actual correlated execution did not violate");
            controls.put("correlated-metadata-probe-execution","VIOLATED");
            Files.write(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"cases",actual,"controls",controls,"privateCredentialsUsed",false,"productOperations",0)));
        }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
