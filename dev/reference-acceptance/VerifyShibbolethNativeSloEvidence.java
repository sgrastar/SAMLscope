package com.samlscope.runner.cases;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.normal.SecureXml;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.net.URI;
import org.w3c.dom.Element;

/** Archived production-reader replay inside Suite. Keys and plaintext identities stay in memory. */
public final class VerifyShibbolethNativeSloEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion",DS="http://www.w3.org/2000/09/xmldsig#",CASE=ShibbolethNativeSloPropagationEvidence.CASE;
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
    private static void restore(Path source,Path folder)throws Exception {
        if(Files.exists(folder))try(var paths=Files.walk(folder)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
        try(var paths=Files.walk(source)){for(var path:paths.toList()){
            var destination=folder.resolve(source.relativize(path));
            if(Files.isDirectory(path)){Files.createDirectories(destination);continue;}
            if(Files.isSymbolicLink(path))throw new IllegalArgumentException("Symbolic original");Files.copy(path,destination,StandardCopyOption.REPLACE_EXISTING);
        }}
    }
    private static void put(Path folder,ObjectNode manifest,String file,byte[] raw)throws Exception {
        Files.write(folder.resolve(file),raw);((ObjectNode)manifest.path("originals")).put(file,hash(raw));
    }
    private static ObjectNode json(Path folder,String file)throws Exception{return (ObjectNode)JSON.mapper().readTree(Files.readAllBytes(folder.resolve(file)));}
    private static void put(Path folder,ObjectNode manifest,String file,ObjectNode node)throws Exception{put(folder,manifest,file,JSON.mapper().writeValueAsBytes(node));}
    private static CaseOutcome evaluate(Path root,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> bodies,Map<String,byte[]> targets,
            Map<String,PrivateKey> keys,boolean complete,String selected,boolean writeManifest)throws Exception {
        String primary=manifest.path("runId").asText();if(writeManifest)Files.write(root.resolve(primary).resolve("manifest.json"),JSON.mapper().writeValueAsBytes(manifest));
        TranscriptRecorder recorder=new TranscriptRecorder(){
            public List<TranscriptEntry> list(String run){return entries.getOrDefault(run,List.of());}
            public TranscriptEntry record(TranscriptInput input){throw new UnsupportedOperationException();}
            public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new UnsupportedOperationException();}
        };
        var context=new DefaultCaseContext(primary,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);
        return new ShibbolethNativeSloPropagationEvidence(root,e->bodies.get(e.id()),targets::get,r->Optional.ofNullable(keys.get(r))).read(context,selected).orElse(null);
    }
    private static TranscriptEntry resize(TranscriptEntry e,byte[] raw,String query) {
        return new TranscriptEntry(e.id(),e.runId(),e.direction(),e.timestamp(),e.correlationId(),e.method(),e.url(),e.status(),e.headers(),e.bodyRef(),e.bodyBytes(),e.decodedSamlRef(),raw.length,e.contentType(),query,e.samlSummary());
    }
    private static Map<String,List<TranscriptEntry>> sized(Map<String,List<TranscriptEntry>> source,Map<String,byte[]> bodies) {
        var result=new HashMap<String,List<TranscriptEntry>>();source.forEach((r,list)->result.put(r,list.stream().map(e->bodies.containsKey(e.id())?resize(e,bodies.get(e.id()),e.rawQuery()):e).toList()));return result;
    }
    private static String finalId(List<TranscriptEntry> list){return list.stream().filter(e->e.direction()==Direction.INBOUND&&"LogoutResponse".equals(e.samlSummary().get("type"))).findFirst().orElseThrow().id();}
    private static String failureId(List<TranscriptEntry> list){return list.stream().filter(e->e.direction()==Direction.INBOUND&&"SloFailParticipant".equals(e.samlSummary().get("type"))).findFirst().orElseThrow().id();}
    private static void updateBrowser(Path folder,ObjectNode manifest,Map<String,byte[]> bodies)throws Exception {
        for(String label:List.of("failure","all-success")) {
            var b=json(folder,label+"/browser-original.json");
            for(var resource:b.path("nativeResources"))for(String name:List.of("samlRequest","samlResponse","generatedRequest"))if(resource.has(name)) {
                var description=(ObjectNode)resource.path(name);String id=description.path("id").asText();
                for(byte[] raw:bodies.values()){var xml=SecureXml.parse(raw).getDocumentElement();if(xml.getAttribute("ID").equals(id)){description.put("sha256",hash(raw));description.put("bytes",raw.length);break;}}
            }
            put(folder,manifest,label+"/browser-original.json",b);
        }
    }
    // Memory-only signed controls prove semantic checks, rather than failing every altered XML
    // at its signature. This is a control fixture, never claimed as fresh product behavior.
    private static void semantic(Path folder,ObjectNode manifest,Map<String,List<TranscriptEntry>> entries,Map<String,byte[]> bodies,Map<String,byte[]> targets,
            PlanCredentials signer,Map<String,PrivateKey> keys,String mutation)throws Exception {
        byte[] before=targets.get(manifest.path("runId").asText());var md=SecureXml.parse(before);var certs=md.getElementsByTagNameNS(DS,"X509Certificate");
        for(int i=0;i<certs.getLength();i++)certs.item(i).setTextContent(Base64.getEncoder().encodeToString(signer.certificate().getEncoded()));byte[] target=SecureXml.serialize(md);
        manifest.put("targetMetadataSha256",hash(target));String primary=manifest.path("runId").asText(),control=manifest.path("controlRunId").asText();
        for(String label:List.of("failure","all-success"))put(folder,manifest,label+"/target-metadata.xml",target);targets.put(primary,target);targets.put(control,target);
        String badFinal=finalId(entries.get(primary)),badAttempt=failureId(entries.get(primary));
        for(var pair:new HashMap<>(entries).entrySet()){
            var rewritten=new ArrayList<TranscriptEntry>();
            for(var old:pair.getValue()) {
                var entry=old;
                if(entry.direction()==Direction.INBOUND&&Set.of("Response","LogoutResponse","LogoutRequest","SloFailParticipant").contains(entry.samlSummary().get("type"))) {
                    var doc=SecureXml.parse(bodies.get(entry.id()));var xml=doc.getDocumentElement();
                    for(var sig:MetadataAlgorithmEvidence.children(xml,DS,"Signature"))xml.removeChild(sig);
                    if(entry.id().equals(badFinal)) {
                        if(mutation.equals("proper-partial-logout")) {
                            var code=(Element)xml.getElementsByTagNameNS(P,"StatusCode").item(0);var nested=doc.createElementNS(P,"samlp:StatusCode");nested.setAttribute("Value","urn:oasis:names:tc:SAML:2.0:status:PartialLogout");code.appendChild(nested);
                        }
                        if(mutation.equals("wrong-final-destination"))xml.setAttribute("Destination","https://other-sp.example/slo");
                        if(mutation.equals("wrong-final-correlation"))xml.setAttribute("InResponseTo","_other-processing");
                    }
                    if(entry.id().equals(badAttempt)) {
                        if(mutation.equals("wrong-session-index"))((Element)xml.getElementsByTagNameNS(P,"SessionIndex").item(0)).setTextContent("_other-session");
                        if(Set.of("wrong-name-format","wrong-name-qualifier","wrong-sp-qualifier").contains(mutation)){
                            var encrypted=MetadataAlgorithmEvidence.children(xml,S,"EncryptedID").getFirst();var name=new SamlXmlDecrypter().decrypt(encrypted,keys.get(pair.getKey()));
                            xml.replaceChild(doc.importNode(name,true),encrypted);name=MetadataAlgorithmEvidence.children(xml,S,"NameID").getFirst();
                            name.setAttribute(mutation.equals("wrong-name-format")?"Format":mutation.equals("wrong-name-qualifier")?"NameQualifier":"SPNameQualifier","https://different-identity.example");
                        }
                    }
                    byte[] raw=SecureXml.serialize(doc);
                    if("GET".equals(entry.method())) {var encoded=new SignedRedirectEncoder().encode(URI.create(xml.getAttribute("Destination")),raw,null,signer);raw=encoded.decodedXml();entry=resize(entry,raw,encoded.rawQuery());}
                    else {new XmlSigner().sign(xml,signer,null);raw=SecureXml.serialize(doc);entry=resize(entry,raw,entry.rawQuery());}
                    bodies.put(entry.id(),raw);
                }
                rewritten.add(entry);
            }
            entries.put(pair.getKey(),rewritten);
        }
        updateBrowser(folder,manifest,bodies);
    }
    public static void main(String[] args)throws Exception {
        var source=Path.of(args[0]);var output=Path.of(args[1]);if(Files.exists(output))throw new IllegalArgumentException("Immutable output exists");
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var base=(ObjectNode)JSON.mapper().readTree(source.resolve("manifest.json").toFile());String primary=base.path("runId").asText(),control=base.path("controlRunId").asText();
        var sourceEntries=new HashMap<String,List<TranscriptEntry>>();var sourceBodies=new HashMap<String,byte[]>();var sourceTargets=new HashMap<String,byte[]>();var keys=new HashMap<String,PrivateKey>();
        String plan=base.path("planId").asText();if(!plan.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Plan");
        byte[] keyBytes=Files.readAllBytes(Path.of("/data/keys/"+plan+"/signing-key.pk8"));
        var signer=new PlanCredentials(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes)),(X509Certificate)CertificateFactory.getInstance("X.509")
            .generateCertificate(Files.newInputStream(Path.of("/data/keys/"+plan+"/signing-certificate.der"))));Arrays.fill(keyBytes,(byte)0);
        for(var label:List.of("failure","all-success")){
            String run=label.equals("failure")?primary:control;if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
            var list=List.of(JSON.mapper().readValue(source.resolve(label+"/transcript.json").toFile(),TranscriptEntry[].class));sourceEntries.put(run,list);
            for(var entry:list)if(entry.decodedSamlRef()!=null){
                if(!entry.runId().equals(run)||!entry.id().matches("tx_[0-9A-HJKMNP-TV-Z]{26}")
                    ||!("transcripts/"+run+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef()))throw new IllegalArgumentException("Foreign content reference");
                byte[] raw=Files.readAllBytes(Path.of("/data").resolve(entry.decodedSamlRef()));if(raw.length!=entry.decodedSamlBytes())throw new IllegalArgumentException("Wrong content size");sourceBodies.put(entry.id(),raw);
                if(!Arrays.equals(raw,Files.readAllBytes(source.resolve(label+"/decoded/"+entry.id()+".xml"))))throw new IllegalArgumentException("Original transcript mismatch");
            }
            sourceTargets.put(run,Files.readAllBytes(Path.of("/data/target-metadata/"+run+".xml")));keys.put(run,signer.privateKey());
        }
        var root=Files.createTempDirectory("samlscope-native-slo-replay-");var folder=root.resolve(primary);var controls=new TreeMap<String,String>();
        try {
            restore(source,folder);
            var actual=evaluate(root,base.deepCopy(),sourceEntries,sourceBodies,sourceTargets,keys,true,CASE,false);
            if(actual==null||actual.outcome()!=Outcome.VIOLATED)throw new IllegalStateException("Actual native SLO originals rejected");
            String badId=failureId(sourceEntries.get(primary)),badFinal=finalId(sourceEntries.get(primary));
            for(String mutation:List.of("proper-partial-logout","wrong-final-destination","wrong-final-correlation","wrong-session-index","wrong-name-format","wrong-name-qualifier","wrong-sp-qualifier",
                "foreign-run-entry","duplicate-entry","foreign-content-reference","wrong-content-size","multiple-origin-processing","missing-final-response","post-logout-authentication","wrong-target",
                "wrong-control-run","wrong-browser-plan","ambient-cookie","wrong-native-scope","mixed-native-flow","missing-participant","wrong-native-session-key","missing-native-source","wrong-native-source",
                "wrong-restoration","missing-readback","late-before-readback","early-after-readback","missing-500-response","failure-before-origin","failure-after-browser","missing-native-json",
                "native-json-failure","missing-suite-reply","wrong-accepted-reply","unknown-http-delivery","wrong-counterexample-signature","incomplete-transcript","non-target-case","asynchronous-origin","forged-native-context")) {
                restore(source,folder);var manifest=base.deepCopy();Map<String,List<TranscriptEntry>> entries=new HashMap<>(sourceEntries);var bodies=new HashMap<>(sourceBodies);var targets=new HashMap<>(sourceTargets);boolean complete=true;String selected=CASE;
                if(Set.of("proper-partial-logout","wrong-final-destination","wrong-final-correlation","wrong-session-index","wrong-name-format","wrong-name-qualifier","wrong-sp-qualifier").contains(mutation))semantic(folder,manifest,entries,bodies,targets,signer,keys,mutation);
                else if(Set.of("foreign-run-entry","duplicate-entry","foreign-content-reference","wrong-content-size","multiple-origin-processing","missing-final-response","post-logout-authentication","missing-suite-reply","unknown-http-delivery").contains(mutation)) {
                    var list=new ArrayList<>(entries.get(primary));
                    if(mutation.equals("duplicate-entry"))list.add(list.getFirst());
                    else if(mutation.equals("multiple-origin-processing")){
                        var old=list.stream().filter(e->e.direction()==Direction.OUTBOUND&&"LogoutRequest".equals(e.samlSummary().get("type"))).findFirst().orElseThrow();var node=(ObjectNode)JSON.mapper().valueToTree(old);node.put("id","tx_00000000000000000000000000");list.add(JSON.mapper().treeToValue(node,TranscriptEntry.class));
                    }else if(mutation.equals("missing-final-response"))list.removeIf(e->e.id().equals(badFinal));
                    else if(mutation.equals("missing-suite-reply"))list.removeIf(e->e.direction()==Direction.OUTBOUND&&"LogoutResponse".equals(e.samlSummary().get("type")));
                    else for(int i=0;i<list.size();i++) {
                        var old=list.get(i);if((mutation.equals("post-logout-authentication")&&"Response".equals(old.samlSummary().get("type")))||old.id().equals(badId)) {
                            var node=(ObjectNode)JSON.mapper().valueToTree(old);
                            switch(mutation){case "foreign-run-entry"->node.put("runId",control);case "foreign-content-reference"->node.put("decodedSamlRef","transcripts/"+control+"/"+old.id()+".saml.xml");
                                case "wrong-content-size"->node.put("decodedSamlBytes",1);case "post-logout-authentication"->node.put("timestamp",Instant.parse("2099-01-01T00:00:00Z").getEpochSecond());case "unknown-http-delivery"->node.putNull("status");}
                            list.set(i,JSON.mapper().treeToValue(node,TranscriptEntry.class));
                        }
                    }
                    entries.put(primary,list);
                }else switch(mutation) {
                    case "wrong-target"->manifest.put("targetMetadataSha256","0".repeat(64));
                    case "wrong-control-run"->manifest.put("controlRunId",primary);
                    case "missing-native-source"->Files.delete(folder.resolve("native-logout-logout-propagation-flow.xml"));
                    case "wrong-native-source"->put(folder,manifest,"native-logout-logout-propagation-flow.xml","changed-native-flow".getBytes(StandardCharsets.UTF_8));
                    case "wrong-restoration"->put(folder,manifest,"final-providers.xml","changed-provider".getBytes(StandardCharsets.UTF_8));
                    case "missing-readback"->Files.delete(folder.resolve("failure/before-readback.json"));
                    case "late-before-readback","early-after-readback"->{String file="failure/"+(mutation.startsWith("late")?"before":"after")+"-readback.json";var node=json(folder,file);node.put("recordedAt",mutation.startsWith("late")?"2099-01-01T00:00:00Z":"2000-01-01T00:00:00Z");put(folder,manifest,file,node);}
                    case "incomplete-transcript"->complete=false;
                    case "non-target-case"->selected="IIP-IDP17-r-idp-01";
                    case "wrong-counterexample-signature"->{byte[] raw=bodies.get(badId);String text=new String(raw,StandardCharsets.UTF_8).replace("LogoutRequest","LogoutRequesx");bodies.put(badId,text.getBytes(StandardCharsets.UTF_8));entries=sized(entries,bodies);updateBrowser(folder,manifest,bodies);}
                    case "asynchronous-origin"->{var origin=sourceEntries.get(primary).stream().filter(e->e.direction()==Direction.OUTBOUND&&"LogoutRequest".equals(e.samlSummary().get("type"))).findFirst().orElseThrow();var doc=SecureXml.parse(bodies.get(origin.id()));var xml=doc.getDocumentElement();for(var sig:MetadataAlgorithmEvidence.children(xml,DS,"Signature"))xml.removeChild(sig);var ext=doc.createElementNS(P,"samlp:Extensions");ext.appendChild(doc.createElementNS(P+":ext:async-slo","aslo:Asynchronous"));xml.appendChild(ext);new XmlSigner().sign(xml,signer,null);bodies.put(origin.id(),SecureXml.serialize(doc));entries=sized(entries,bodies);updateBrowser(folder,manifest,bodies);}
                    default->{var b=json(folder,"failure/browser-original.json");
                        switch(mutation) {
                            case "wrong-browser-plan"->b.put("planId","plan_00000000000000000000000000");
                            case "ambient-cookie"->b.put("initialCookieCount",1);
                            case "wrong-native-scope"->((ObjectNode)b.path("nativePropagationContext")).put("flowScopeSha256","0".repeat(64));
                            case "mixed-native-flow"->((ArrayNode)b.path("nativeFlowScopes")).add("0".repeat(64));
                            case "missing-participant"->((ArrayNode)b.path("nativePropagationContext").path("participants")).remove(0);
                            case "wrong-native-session-key"->((ObjectNode)b.path("nativePropagationContext").path("participants").get(0)).put("sessionKeySha256","0".repeat(64));
                            case "forged-native-context"->{String text=Files.readString(folder.resolve("failure/native-propagation-context.html"));text=text.replace("sender_sha256:","sender_unknown:");byte[] raw=text.getBytes(StandardCharsets.UTF_8);put(folder,manifest,"failure/native-propagation-context.html",raw);((ObjectNode)b.path("nativePropagationContext")).put("sha256",hash(raw));}
                            default->{for(var r:b.path("nativeResources")) {
                                var row=(ObjectNode)r;
                                if(row.path("status").asInt()==500)switch(mutation) {case "missing-500-response"->row.remove("status");case "failure-before-origin"->row.put("respondedAt","2000-01-01T00:00:00Z");case "failure-after-browser"->row.put("respondedAt","2099-01-01T00:00:00Z");}
                                if(row.has("bodyFile"))switch(mutation){case "missing-native-json"->Files.deleteIfExists(folder.resolve("failure/"+row.path("bodyFile").asText()));case "native-json-failure"->{byte[] raw="{\"result\":\"Failure\"}".getBytes(StandardCharsets.UTF_8);put(folder,manifest,"failure/"+row.path("bodyFile").asText(),raw);row.put("sha256",hash(raw));}case "wrong-accepted-reply"->((ObjectNode)row.path("samlResponse")).put("sha256","0".repeat(64));}
                            }}
                        }
                        put(folder,manifest,"failure/browser-original.json",b);
                    }
                }
                var result=evaluate(root,manifest,entries,bodies,targets,keys,complete,selected,true);
                Outcome expected=mutation.equals("proper-partial-logout")?Outcome.SATISFIED:Outcome.NOT_VERIFIED;
                Outcome observed=result==null?Outcome.NOT_VERIFIED:result.outcome();if(observed!=expected)throw new IllegalStateException("Control accepted: "+mutation+" "+observed);controls.put(mutation,observed.name());
            }
            Files.write(output,JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",primary,"outcome",actual,"controls",controls,"privateCredentialsUsed",true,"privateCredentialsPersisted",false,"productOperations",0)));
        }finally{try(var paths=Files.walk(root)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}}
    }
}
