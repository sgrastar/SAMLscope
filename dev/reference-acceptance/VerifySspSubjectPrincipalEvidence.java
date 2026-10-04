package com.samlscope.runner.cases;

import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;

/** Replays actual reader and native signed semantic controls without writes to Recorder. */
public final class VerifySspSubjectPrincipalEvidence {
    static final JsonCodec JSON=new JsonCodec();
    static void require(boolean b,String note){if(!b)throw new IllegalArgumentException(note);}
    static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static TranscriptEntry foreign(TranscriptEntry e){return new TranscriptEntry(e.id(),"run_00000000000000000000000000",e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary());}
    static com.samlscope.core.evaluation.CaseOutcome observe(Path source,String mutation)throws Exception {
        var receipt=source.resolve("receipt-v1");var manifest=(ObjectNode)JSON.mapper().readTree(receipt.resolve("manifest.json").toFile());var run=manifest.path("runId").asText();
        var entries=new ArrayList<>(List.of(JSON.mapper().readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class)));var bodies=new HashMap<String,byte[]>();var ids=new HashMap<String,TranscriptEntry>();
        for(var e:entries)require(run.equals(e.runId())&&ids.put(e.id(),e)==null,"Transcript not unique Run-bound");
        for(var row:JSON.mapper().readTree(source.resolve("decoded-manifest.json").toFile())){
            var path=source.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(source.resolve("decoded")),"Unsafe decoded path");
            var raw=Files.readAllBytes(path);var e=ids.get(row.path("id").asText());require(e!=null&&sha(raw).equals(row.path("sha256").asText())&&raw.length==e.decodedSamlBytes(),"Decoded original changed");bodies.put(e.id(),raw);
        }
        byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));
        if(mutation.equals("foreign-run-transcript"))entries.set(0,foreign(entries.getFirst()));
        if(mutation.equals("missing-response"))entries.remove(entries.stream().filter(e->e.direction()==Direction.INBOUND).findFirst().orElseThrow());
        if(mutation.equals("wrong-response-original")){var e=entries.stream().filter(v->v.direction()==Direction.INBOUND).findFirst().orElseThrow();bodies.put(e.id(),bodies.get(entries.getFirst().id()));}
        var temporary=Files.createTempDirectory("ssp-subject-principal-");
        try {
            var folder=Files.createDirectory(temporary.resolve(run));try(var files=Files.list(receipt)){for(var file:files.toList())Files.copy(file,folder.resolve(file.getFileName()));}
            var files=(ObjectNode)manifest.path("files");
            if(mutation.equals("wrong-receipt-run"))manifest.put("runId","run_00000000000000000000000000");
            if(mutation.equals("wrong-target-hash"))manifest.put("targetMetadataSha256","0".repeat(64));
            if(mutation.equals("missing-native-source"))Files.delete(folder.resolve("native-userpass.php"));
            if(mutation.equals("changed-native-source"))Files.writeString(folder.resolve("native-userpass.php"),"<?php arbitrary source");
            if(mutation.equals("missing-control"))Files.delete(folder.resolve("different-confirmation-principal.xml"));
            if(mutation.equals("fake-control")){
                var raw=Files.readAllBytes(folder.resolve("same-principal-different-format.xml"));Files.write(folder.resolve("different-confirmation-principal.xml"),raw);files.put("different-confirmation-principal.xml",sha(raw));
            }
            if(mutation.equals("broken-control-signature")) {
                var raw=Files.readAllBytes(folder.resolve("different-confirmation-principal.xml"));var xml=com.samlscope.saml.normal.SecureXml.parse(raw);
                var sig=xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);var decoded=Base64.getMimeDecoder().decode(sig.getTextContent());decoded[0]^=1;sig.setTextContent(Base64.getEncoder().encodeToString(decoded));
                raw=com.samlscope.saml.normal.SecureXml.serialize(xml);Files.write(folder.resolve("different-confirmation-principal.xml"),raw);files.put("different-confirmation-principal.xml",sha(raw));
            }
            if(mutation.equals("wrong-auth-restoration")) {
                var file=folder.resolve("restoration.json");var value=(ObjectNode)JSON.mapper().readTree(file.toFile());((ObjectNode)value.path("authsource")).put("nativeFinalSha256","0".repeat(64));var raw=JSON.mapper().writeValueAsBytes(value);Files.write(file,raw);files.put("restoration.json",sha(raw));
            }
            if(mutation.equals("late-before-readback")) {
                var file=folder.resolve("before-observed.json");var value=(ObjectNode)JSON.mapper().readTree(file.toFile());value.put("recordedAt","2099-01-01T00:00:00Z");var raw=JSON.mapper().writeValueAsBytes(value);Files.write(file,raw);files.put("before-observed.json",sha(raw));
            }
            if(Set.of("uid-alias","wrong-nameid-map","unrecognized-attribute","changed-authsource","changed-salt","wrong-sp","disabled-generator").contains(mutation)) {
                for(String phase:List.of("before","after")) {
                    if(mutation.equals("changed-salt")&&phase.equals("before"))continue;
                    var file=folder.resolve(phase+"-native-resolution.json");var value=(ObjectNode)JSON.mapper().readTree(file.toFile());
                    var principal=(ObjectNode)value.path("nativeAuthenticatedPrincipals").get(1);
                    switch(mutation) {
                        case "uid-alias" -> ((ArrayNode)principal.path("attributes").path("uid")).set(0,new TextNode(value.path("nativeAuthenticatedPrincipals").get(0).path("attributes").path("uid").get(0).asText()));
                        case "wrong-nameid-map" -> ((ObjectNode)principal.path("nameId")).put("value","0".repeat(40));
                        case "unrecognized-attribute" -> ((ObjectNode)principal.path("attributes")).putArray("unknownIdentifyingAttribute").add("foreign-account");
                        case "changed-authsource" -> ((ObjectNode)value.path("authenticationSource")).put("originalSha256","0".repeat(64));
                        case "changed-salt" -> value.put("saltSha256","0".repeat(64));
                        case "wrong-sp" -> value.put("spEntityId","https://foreign.invalid/sp");
                        case "disabled-generator" -> ((ObjectNode)value.path("hostedAuthproc").path("20")).put("class","saml:TransientNameID");
                    }
                    var raw=JSON.mapper().writeValueAsBytes(value);Files.write(file,raw);files.put(phase+"-native-resolution.json",sha(raw));
                }
            }
            Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
            TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String id){return id.equals(run)?entries:List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError();}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object> m){throw new AssertionError();}};
            var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
            return new SimpleSamlPhpSubjectPrincipalEvidence(temporary,e->bodies.get(e.id()),id->id.equals(run)?target:null).evaluate(context);
        }finally{try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
    public static void main(String[] args)throws Exception {
        var source=Path.of(args[0]).toAbsolutePath();var output=Path.of(args[1]);require(!Files.exists(output),"Refusing replacement");
        var base=observe(source,"none");require(base.outcome()==com.samlscope.core.evaluation.Outcome.SATISFIED,"Native positive not satisfied: "+base.details());
        var checks=new TreeMap<String,String>();checks.put("native-positive","SATISFIED");
        for(String mutation:List.of("foreign-run-transcript","missing-response","wrong-response-original","wrong-receipt-run","wrong-target-hash",
            "missing-native-source","changed-native-source","missing-control","fake-control","broken-control-signature","wrong-auth-restoration","late-before-readback",
            "uid-alias","wrong-nameid-map","unrecognized-attribute","changed-authsource","changed-salt","wrong-sp","disabled-generator")) {
            var result=observe(source,mutation);require(result.outcome()==com.samlscope.core.evaluation.Outcome.NOT_VERIFIED,"Mutation accepted: "+mutation);checks.put(mutation,"NOT_VERIFIED");
        }
        var report=new TreeMap<String,Object>();report.put("checks",checks);report.put("outcome",base.outcome().name());report.put("reasonCode",base.reasonCode());report.put("details",base.details());report.put("evidence",base.evidence());
        report.put("nativeSignedSemanticControlsVerified",4);report.put("privateKeyExported",false);report.put("credentialsPersisted",false);Files.writeString(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(report)+"\n");
    }
}
