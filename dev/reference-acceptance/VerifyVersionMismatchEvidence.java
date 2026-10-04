package com.samlscope.runner.cases;

import java.nio.file.*;
import java.time.*;
import java.net.URI;
import java.util.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;

/** Pure replay of immutable public originals with the existing Suite Run key held in memory. */
public final class VerifyVersionMismatchEvidence {
    private static final JsonCodec JSON=new JsonCodec();
    private static final String CASE="IIP-SSO01-ep-idp-01";
    private static List<TranscriptEntry> entries;
    private static Map<String,byte[]> originals;
    private static KeycloakNativeRunEvidenceBridge bridge;
    private static IdpErrorProbeConfiguration configuration;
    private static byte[] targetBytes;
    private static String run;
    private static CaseOutcome observe(Path folder,List<TranscriptEntry> list,Map<String,byte[]> raw)throws Exception{
        var test=new IdpVersionMismatchScenarioTestCase(r->configuration,r->bridge.key(r,"primary"),e->raw.get(e.id()),r->targetBytes,r->bridge.primaryKey(r),folder.resolve("version-mismatch-evidence"));
        TranscriptRecorder recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return list;}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException("Read only");}public TranscriptEntry updateSamlAnalysis(String a,String b,Map<String,Object> c){throw new UnsupportedOperationException("Read only");}};
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),new TestPlan.Interaction(false,false),Reachability.CONFIRMED,recorder,true);
        var step=test.start(context);if(!(step instanceof CaseStep.Finish finish))throw new IllegalArgumentException("Replay generated an action");return finish.outcome();
    }
    private static TranscriptEntry replace(TranscriptEntry e,java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> change)throws Exception{
        var node=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.mapper().valueToTree(e);change.accept(node);return JSON.mapper().treeToValue(node,TranscriptEntry.class);
    }
    private static TranscriptEntry request(String fixture){return entries.stream().filter(e->e.direction()==Direction.OUTBOUND&&fixture.equals(e.samlSummary().get("fixture_id"))&&CASE.equals(e.samlSummary().get("scenario_case_id"))).findFirst().orElseThrow();}
    private static void nv(Map<String,Object> controls,String name,Path folder,List<TranscriptEntry> list,Map<String,byte[]> raw)throws Exception{
        var result=observe(folder,list,raw);if(result.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalArgumentException("Contamination was adopted: "+name);controls.put(name,result);
    }
    private static void nativeMutation(Map<String,Object> controls,String name,Path folder,java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> edit,String file,java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> fileEdit)throws Exception{
        Path copy=Files.createTempDirectory("version-control-");try{
            try(var walk=Files.walk(folder)){for(var p:walk.toList()){Path q=copy.resolve(folder.relativize(p));if(Files.isDirectory(p))Files.createDirectories(q);else Files.copy(p,q);}}
            Path side=copy.resolve("version-mismatch-evidence/"+run),manifest=copy.resolve("version-mismatch-evidence/"+run+".json");
            var m=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.mapper().readTree(Files.readAllBytes(manifest));edit.accept(m);var list=new ArrayList<>(entries);var raw=new HashMap<>(originals);
            if(file!=null){Path p=side.resolve(file);var node=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.mapper().readTree(Files.readAllBytes(p));fileEdit.accept(node);Files.write(p,JSON.mapper().writeValueAsBytes(node));}
            // Rebind the copied public capture to changed file bytes. The production predicate,
            // rather than a stale manifest hash alone, must reject the semantic contamination.
            for(var row:m.path("terminals")){
                var p=side.resolve(row.path("captureFile").asText());var n=(com.fasterxml.jackson.databind.node.ObjectNode)JSON.mapper().readTree(Files.readAllBytes(p));
                n.put("nativeHttpSha256",VersionMismatchTerminalEvidence.hash(Files.readAllBytes(side.resolve(row.path("nativeHttpFile").asText()))));
                n.put("runtimeBeforeSha256",VersionMismatchTerminalEvidence.hash(Files.readAllBytes(side.resolve(m.path("runtimeBeforeFile").asText()))));
                n.put("runtimeAfterSha256",VersionMismatchTerminalEvidence.hash(Files.readAllBytes(side.resolve(m.path("runtimeAfterFile").asText()))));
                byte[] bytes=JSON.mapper().writeValueAsBytes(n);Files.write(p,bytes);String ref=row.path("captureReference").asText();raw.put(ref,bytes);
                for(int i=0;i<list.size();i++)if(list.get(i).id().equals(ref))list.set(i,replace(list.get(i),e->e.put("decodedSamlBytes",bytes.length)));
            }
            for(var f:m.path("files")){Path p=side.resolve(f.path("file").asText());((com.fasterxml.jackson.databind.node.ObjectNode)f).put("sha256",VersionMismatchTerminalEvidence.hash(Files.readAllBytes(p))).put("size",Files.size(p));}
            Files.write(manifest,JSON.mapper().writeValueAsBytes(m));nv(controls,name,copy,list,raw);
        }finally{try(var walk=Files.walk(copy)){for(var p:walk.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}}
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=3&&args.length!=4)throw new IllegalArgumentException("data root, replay folder, Run and optional diagnostic output required");
        Path folder=Path.of(args[1]).toRealPath();run=args[2];var codec=JSON;
        if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Invalid Run");
        bridge=new KeycloakNativeRunEvidenceBridge(Path.of(args[0]));entries=codec.mapper().readValue(Files.readAllBytes(folder.resolve("transcript.json")),new TypeReference<List<TranscriptEntry>>(){});
        var seen=new HashSet<String>();for(var entry:entries)if(!run.equals(entry.runId())||!seen.add(entry.id()))throw new IllegalArgumentException("Mixed or duplicate transcript");
        originals=new HashMap<>();for(var item:codec.mapper().readTree(Files.readAllBytes(folder.resolve("decoded-manifest.json")))){
            String file=item.path("file").asText();Path path=folder.resolve(file).normalize();if(!path.startsWith(folder)||Files.isSymbolicLink(path))throw new IllegalArgumentException("Unsafe original");
            byte[] raw=Files.readAllBytes(path);if(!VersionMismatchTerminalEvidence.hash(raw).equals(item.path("sha256").asText())||originals.put(item.path("id").asText(),raw)!=null)throw new IllegalArgumentException("Original hash duplicate/mismatch");
        }
        var peer=SecureXml.parse(Files.readAllBytes(folder.resolve("suite-metadata.xml"))).getDocumentElement();var role=IdpVersionMismatchScenarioTestCase.single(peer,IdpVersionMismatchScenarioTestCase.MD,"SPSSODescriptor");
        var acss=MetadataAlgorithmEvidence.children(role,IdpVersionMismatchScenarioTestCase.MD,"AssertionConsumerService").stream().filter(e->"0".equals(e.getAttribute("index"))).toList();if(acss.size()!=1)throw new IllegalArgumentException("Actual ACS0 unavailable");
        targetBytes=Files.readAllBytes(folder.resolve("target-metadata.xml"));if(!Arrays.equals(targetBytes,bridge.targetMetadata(run)))throw new IllegalArgumentException("Fixed target metadata changed");
        var target=SecureXml.parse(targetBytes).getDocumentElement();var endpoint=new ArrayList<String>();for(var r:MetadataAlgorithmEvidence.children(target,IdpVersionMismatchScenarioTestCase.MD,"IDPSSODescriptor"))for(var e:MetadataAlgorithmEvidence.children(r,IdpVersionMismatchScenarioTestCase.MD,"SingleSignOnService"))if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(e.getAttribute("Binding")))endpoint.add(e.getAttribute("Location"));
        if(endpoint.size()!=1)throw new IllegalArgumentException("Target SSO ambiguous");configuration=new IdpErrorProbeConfiguration(URI.create(endpoint.getFirst()),peer.getAttribute("entityID"),URI.create(acss.getFirst().getAttribute("Location")),Duration.ofHours(2),true,true,false);
        var result=observe(folder,entries,originals);var controls=new TreeMap<String,Object>();var r=request("version-1-1");
        var changed=new ArrayList<>(entries);changed.add(r);nv(controls,"duplicate-outbound",folder,changed,originals);
        changed=new ArrayList<>(entries);changed.remove(request("baseline-success"));nv(controls,"missing-normal-control",folder,changed,originals);
        changed=new ArrayList<>(entries);for(int i=0;i<changed.size();i++)if(changed.get(i).id().equals(r.id()))changed.set(i,replace(r,n->((com.fasterxml.jackson.databind.node.ObjectNode)n.path("samlSummary")).put("delivery","UNKNOWN_DELIVERY")));nv(controls,"unknown-delivery",folder,changed,originals);
        var raw=new HashMap<>(originals);raw.put(r.id(),new String(raw.get(r.id()),java.nio.charset.StandardCharsets.UTF_8).replace("Version=\"1.1\"","Version=\"2.0\"").getBytes(java.nio.charset.StandardCharsets.UTF_8));nv(controls,"tampered-signed-request",folder,entries,raw);
        var normal=request("baseline-success");String normalId=SecureXml.parse(originals.get(normal.id())).getDocumentElement().getAttribute("ID");var response=entries.stream().filter(e->e.direction()==Direction.INBOUND&&normalId.equals(e.correlationId())&&"Response".equals(e.samlSummary().get("type"))).findFirst().orElseThrow();
        raw=new HashMap<>(originals);String originalText=new String(raw.get(response.id()),java.nio.charset.StandardCharsets.UTF_8);var pattern=java.util.regex.Pattern.compile("(<(?:[\\w.-]+:)?(?:SignatureValue|CipherValue)\\b[^>]*>)([^<]+)(</(?:[\\w.-]+:)?(?:SignatureValue|CipherValue)>)");var matcher=pattern.matcher(originalText);var corrupted=new StringBuffer();int altered=0;while(matcher.find()){String value=matcher.group(2);int i=0;while(i<value.length()&&Character.isWhitespace(value.charAt(i)))i++;if(i==value.length())throw new IllegalArgumentException("Empty signature/cipher");String changedValue=value.substring(0,i)+(value.charAt(i)=='A'?'B':'A')+value.substring(i+1);matcher.appendReplacement(corrupted,java.util.regex.Matcher.quoteReplacement(matcher.group(1)+changedValue+matcher.group(3)));altered++;}matcher.appendTail(corrupted);if(altered==0)throw new IllegalArgumentException("Normal authentication signature absent");raw.put(response.id(),corrupted.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));nv(controls,"invalid-normal-signature-or-cipher",folder,entries,raw);
        nativeMutation(controls,"foreign-manifest-run",folder,m->m.put("runId","run_00000000000000000000000000"),null,null);
        nativeMutation(controls,"foreign-adapter",folder,m->m.put("adapter","unknown-native-adapter"),null,null);
        nativeMutation(controls,"counterfactual-proof",folder,m->m.put("counterfactualCalibrationOnly",true),null,null);
        nativeMutation(controls,"foreign-target-metadata",folder,m->m.put("targetMetadataSha256","0".repeat(64)),null,null);
        nativeMutation(controls,"foreign-http-request",folder,m->{},"version-1-1-http.json",n->n.put("requestId","_foreign"));
        nativeMutation(controls,"foreign-http-hash",folder,m->{},"version-1-1-http.json",n->n.put("requestSha256","0".repeat(64)));
        nativeMutation(controls,"http-with-response-form",folder,m->{},"version-1-1-http.json",n->n.put("samlResponseFormPresent",true));
        nativeMutation(controls,"foreign-native-runtime",folder,m->{},"runtime-after.json",n->n.put("containerId","0".repeat(64)));
        nativeMutation(controls,"source-covering-mount",folder,m->{},"runtime-before.json",n->{var a=(com.fasterxml.jackson.databind.node.ArrayNode)n.path("mounts");var x=JSON.mapper().createObjectNode();x.put("Type","bind").put("Source","/tmp/foreign").put("Destination","/var/simplesamlphp/vendor").put("RW",false).put("Mode","ro").put("Propagation","rprivate");a.add(x);});
        var diagnostic=new TreeMap<String,Object>();
        if(args.length==4){var model=JSON.mapper().readTree(Files.readAllBytes(Path.of(args[3])));if(!run.equals(model.path("runId").asText())||!model.path("counterfactualCalibrationOnly").asBoolean()||model.path("controlsAdopted").asBoolean(true))throw new IllegalArgumentException("Wrong diagnostic provenance");
            for(var row:model.path("controls")){
                String name=row.path("fixtureId").asText(),fixture=name.equals("nonversion-wrong-code")?"invalid-issue-instant":"version-1-1";var q=request(fixture);byte[] bytes=Base64.getDecoder().decode(row.path("responseBase64").asText());if(!VersionMismatchTerminalEvidence.hash(bytes).equals(row.path("sha256").asText()))throw new IllegalArgumentException("Diagnostic output hash changed");
                var old=entries.stream().filter(e->e.direction()==Direction.INBOUND&&q.correlationId().equals(e.correlationId())&&"BROWSER".equals(e.method())).findFirst().orElseThrow();
                String requestId=SecureXml.parse(originals.get(q.id())).getDocumentElement().getAttribute("ID");
                var list=new ArrayList<>(entries);list.remove(old);var sum=Map.<String,Object>of("type","Response","inResponseTo",requestId);
                list.add(new TranscriptEntry(old.id(),run,Direction.INBOUND,old.timestamp(),requestId,"POST",configuration.registeredAcs().toString(),200,Map.of(),old.bodyRef(),bytes.length,"transcripts/"+run+"/"+old.id()+".saml.xml",bytes.length,"application/xml",null,sum));
                var modelRaw=new HashMap<>(originals);modelRaw.put(old.id(),bytes);var outcome=observe(folder,list,modelRaw);Outcome expected=name.equals("version-1-1-mutant")?Outcome.VIOLATED:name.equals("nonversion-wrong-code")?Outcome.NOT_VERIFIED:result.outcome();if(outcome.outcome()!=expected)throw new IllegalArgumentException("Approved diagnostic not detected: "+name);diagnostic.put(name,outcome);
            }
            if(diagnostic.size()!=3)throw new IllegalArgumentException("Missing diagnostics");
        }
        var origins=new TreeMap<String,String>();for(var c:List.of(IdpVersionMismatchScenarioTestCase.class,VersionMismatchTerminalEvidence.class,CaseOutcome.class,SecureXml.class,JsonCodec.class))origins.put(c.getName(),Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).getFileName().toString());
        System.out.println(codec.write(Map.of("schema","samlscope-version-status-replay-v1","runId",run,"caseId",CASE,"outcome",result,"negativeControls",controls,"diagnosticOnlyControls",diagnostic,"codeSources",origins,"readOnly",true,"outboundActions",0,"privateKeyExported",false)));
    }
}
