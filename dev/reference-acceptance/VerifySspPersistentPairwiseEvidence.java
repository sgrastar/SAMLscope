package com.samlscope.runner.cases;

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.*;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.normal.SecureXml;

/** Independent production-reader replay over captured native originals; no product configuration changes. */
public final class VerifySspPersistentPairwiseEvidence {
    static final JsonCodec JSON=new JsonCodec();
    static void require(boolean b){if(!b)throw new IllegalArgumentException("Unproven native pairwise originals");}
    static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static TranscriptEntry replaceRun(TranscriptEntry e,String run){return new TranscriptEntry(e.id(),run,e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),e.decodedSamlBytes(),e.contentType(),e.rawQuery(),e.samlSummary());}
    static void verifiedSameValueProducer(Path campaign)throws Exception {
        var names=new HashSet<String>();var identities=new HashSet<String>();int count=0;
        for(var label:List.of("primary","secondary")) {
            var folder=campaign.resolve(label);var metadata=SecureXml.parse(Files.readAllBytes(folder.resolve("fixture.xml"))).getDocumentElement();
            var target=SecureXml.parse(Files.readAllBytes(folder.resolve("target-metadata.xml"))).getDocumentElement();var keys=MetadataAlgorithmEvidence.signingKeys(target);
            var entries=List.of(JSON.mapper().readValue(folder.resolve("transcript.json").toFile(),TranscriptEntry[].class));
            for(var response:entries) {
                if(response.direction()!=Direction.INBOUND)continue;
                var raw=Files.readAllBytes(folder.resolve("decoded").resolve(response.id()+".xml"));var xml=SecureXml.parse(raw).getDocumentElement();
                var request=entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&e.correlationId().equals(xml.getAttribute("InResponseTo"))).findFirst().orElseThrow();
                var assertion=VerifiedResponseAssertion.read(xml,target.getAttribute("entityID"),keys,metadata,Optional.empty(),request.correlationId(),response.url());
                var n=assertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","NameID");require(n.getLength()==1);
                names.add(n.item(0).getTextContent());var values=new ArrayList<String>();
                for(var attribute:MetadataAlgorithmEvidence.children(MetadataAlgorithmEvidence.children(assertion,"urn:oasis:names:tc:SAML:2.0:assertion","AttributeStatement").getFirst(),"urn:oasis:names:tc:SAML:2.0:assertion","Attribute")) {
                    if(!"uid".equals(attribute.getAttribute("Name")))continue;
                    for(var value:MetadataAlgorithmEvidence.children(attribute,"urn:oasis:names:tc:SAML:2.0:assertion","AttributeValue"))values.add(value.getTextContent());
                }
                require(values.size()==1);identities.add(values.getFirst());count++;
            }
        }
        require(count==4&&names.size()==1&&identities.size()==1&&names.equals(identities));
    }
    static Optional<com.samlscope.core.evaluation.CaseOutcome> observe(Path campaign,String mutation)throws Exception {
        var receipt=campaign.resolve("receipt-v1");var manifest=(ObjectNode)JSON.mapper().readTree(Files.readAllBytes(receipt.resolve("manifest.json")));
        var run=manifest.path("runId").asText();var entries=new HashMap<String,List<TranscriptEntry>>();var bodies=new HashMap<String,byte[]>();var targets=new HashMap<String,byte[]>();
        for(var label:List.of("primary","secondary")) {
            var member=campaign.resolve(label);var created=JSON.mapper().readTree(member.resolve("created.json").toFile()).path("run");var id=created.path("id").asText();
            var list=new ArrayList<>(List.of(JSON.mapper().readValue(member.resolve("transcript.json").toFile(),TranscriptEntry[].class)));
            var ids=new HashMap<String,TranscriptEntry>();for(var e:list)require(id.equals(e.runId())&&ids.put(e.id(),e)==null);
            for(var row:JSON.mapper().readTree(member.resolve("decoded-manifest.json").toFile())) {
                var path=member.resolve(row.path("file").asText()).normalize();require(path.getParent().equals(member.resolve("decoded")));
                var raw=Files.readAllBytes(path);var e=ids.get(row.path("id").asText());require(e!=null&&sha(raw).equals(row.path("sha256").asText())&&raw.length==e.decodedSamlBytes()&&bodies.put(e.id(),raw)==null);
            }
            entries.put(id,list);targets.put(id,Files.readAllBytes(member.resolve("target-metadata.xml")));
        }
        var primary=entries.get(run);var response=primary.stream().filter(e->e.direction()==Direction.INBOUND).findFirst().orElseThrow();
        var request=primary.stream().filter(e->e.direction()==Direction.OUTBOUND).findFirst().orElseThrow();
        if(mutation.equals("foreign-run-transcript"))primary.set(primary.indexOf(response),replaceRun(response,"run_00000000000000000000000000"));
        if(mutation.equals("missing-response"))primary.remove(response);
        if(mutation.equals("corrupt-response-signature")) {
            var xml=SecureXml.parse(bodies.get(response.id()));var sig=xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0);
            var bytes=Base64.getMimeDecoder().decode(sig.getTextContent());bytes[0]^=1;sig.setTextContent(Base64.getEncoder().encodeToString(bytes));bodies.put(response.id(),SecureXml.serialize(xml));
        }
        if(mutation.equals("wrong-target"))targets.put(run,new String(targets.get(run),StandardCharsets.UTF_8).replace("http://localhost:18380/idp","https://foreign.invalid/idp").getBytes(StandardCharsets.UTF_8));
        if(mutation.equals("foreign-request-original"))bodies.put(request.id(),bodies.get(response.id()));
        var temporary=Files.createTempDirectory("ssp-pairwise-reader-");
        try {
            var folder=Files.createDirectory(temporary.resolve(run));try(var files=Files.list(receipt)){for(var file:files.toList())Files.copy(file,folder.resolve(file.getFileName()));}
            switch(mutation) {
                case "missing-peer" -> ((ArrayNode)manifest.path("peers")).remove(1);
                case "wrong-request-reference" -> ((ObjectNode)manifest.path("peers").get(0).path("exchanges").get(0)).put("requestReference",response.id());
                case "wrong-restoration" -> {
                    var row=(ObjectNode)manifest.path("restoration").path("hosted");var raw="altered native restoration".getBytes(StandardCharsets.UTF_8);
                    Files.write(folder.resolve(row.path("finalFile").asText()),raw);row.put("finalSha256",sha(raw));
                }
                case "missing-readback" -> ((ArrayNode)manifest.path("readBacks")).remove(3);
                case "late-before-readback" -> ((ObjectNode)manifest.path("readBacks").get(0)).put("recordedAt","2099-01-01T00:00:00Z");
                case "missing-native-source" -> Files.delete(folder.resolve("native-persistent-filter.php"));
                case "wrong-native-source" -> Files.writeString(folder.resolve("native-userpass.php"),"<?php forged native source");
                case "wrong-native-sp-metadata" -> {
                    var row=(ObjectNode)manifest.path("peers").get(0);var raw=Files.readAllBytes(folder.resolve(row.path("metadataFile").asText()));
                    raw=new String(raw,StandardCharsets.UTF_8).replace(row.path("entityId").asText(),"https://foreign.invalid/sp").getBytes(StandardCharsets.UTF_8);
                    Files.write(folder.resolve(row.path("metadataFile").asText()),raw);row.put("metadataSha256",sha(raw));
                }
                case "uid-alias-collision","unknown-principal","changed-authsource","changed-salt","disabled-generator","global-uid-rewrite" -> {
                    int index=mutation.equals("changed-authsource")||mutation.equals("changed-salt")?3:0;
                    var row=(ObjectNode)manifest.path("readBacks").get(index);var file=folder.resolve(row.path("file").asText());var value=(ObjectNode)JSON.mapper().readTree(file.toFile());
                    switch(mutation) {
                        case "uid-alias-collision" -> {var users=(ArrayNode)value.path("authenticationSource").path("users");var clone=((ObjectNode)users.get(0)).deepCopy();clone.put("principal","different-account-same-uid");users.add(clone);}
                        case "unknown-principal" -> ((ArrayNode)value.path("authenticationSource").path("users").get(0).path("uid")).set(0,new TextNode("foreign-uid"));
                        case "changed-authsource" -> ((ObjectNode)value.path("authenticationSource")).put("originalSha256","0".repeat(64));
                        case "changed-salt" -> value.put("saltSha256","0".repeat(64));
                        case "disabled-generator" -> ((ObjectNode)value.path("hostedAuthproc").path("20")).put("class","saml:TransientNameID");
                        case "global-uid-rewrite" -> ((ObjectNode)value.path("globalAuthproc")).put("10","core:AttributeAdd");
                    }
                    var raw=JSON.mapper().writeValueAsBytes(value);Files.write(file,raw);row.put("sha256",sha(raw));
                }
            }
            Files.write(folder.resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
            TranscriptRecorder recorder=new TranscriptRecorder(){
                public List<TranscriptEntry> list(String id){return entries.getOrDefault(id,List.of());}
                public TranscriptEntry record(TranscriptInput i){throw new AssertionError();}
                public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> s){throw new AssertionError();}
            };
            var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
            return new SimpleSamlPhpPersistentPairwiseEvidence(temporary,e->bodies.get(e.id()),targets::get).evaluate(context);
        }finally{try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
    public static void main(String[] args)throws Exception {
        var positive=Path.of(args[0]).toAbsolutePath();var mutant=Path.of(args[1]).toAbsolutePath();var output=Path.of(args[2]);require(!Files.exists(output));
        var base=observe(positive,"none").orElseThrow(()->new IllegalArgumentException("Native positive evidence did not satisfy production reader"));
        verifiedSameValueProducer(mutant);
        require(base.outcome()==com.samlscope.core.evaluation.Outcome.SATISFIED&&observe(mutant,"none").isEmpty());
        var checks=new TreeMap<String,String>();checks.put("native-positive","SATISFIED");checks.put("native-same-value-producer-control","NOT_VERIFIED");
        for(var mutation:List.of("foreign-run-transcript","missing-response","corrupt-response-signature","wrong-target","foreign-request-original",
            "missing-peer","wrong-request-reference","wrong-restoration","missing-readback","late-before-readback","missing-native-source","wrong-native-source",
            "wrong-native-sp-metadata","uid-alias-collision","unknown-principal","changed-authsource","changed-salt","disabled-generator","global-uid-rewrite")) {
            require(observe(positive,mutation).isEmpty());checks.put(mutation,"NOT_VERIFIED");
        }
        var report=new TreeMap<String,Object>();report.put("checks",checks);report.put("outcome",base.outcome().name());report.put("reasonCode",base.reasonCode());report.put("details",base.details());report.put("evidence",base.evidence());
        report.put("nativeSameValueProducerVerified",true);report.put("privateKeyExported",false);report.put("credentialsPersisted",false);Files.writeString(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(report)+"\n");
    }
}
