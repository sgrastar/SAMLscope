package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Runs the production reader against actual native originals; mutations never touch source originals. */
public final class VerifyKeycloakAuthenticationIdentity {
    private static final com.fasterxml.jackson.databind.ObjectMapper M=new JsonCodec().mapper();
    private static void rehash(Path folder,String name)throws Exception {
        var manifest=(ObjectNode)M.readTree(Files.readAllBytes(folder.resolve("manifest.json")));
        ((ObjectNode)manifest.path("files")).put(name,KeycloakAuthenticationIdentityEvidence.hash(Files.readAllBytes(folder.resolve(name))));
        Files.write(folder.resolve("manifest.json"),M.writeValueAsBytes(manifest));
    }
    private static void edit(Path folder,String name,java.util.function.Consumer<JsonNode> mutation)throws Exception {
        var node=M.readTree(Files.readAllBytes(folder.resolve(name)));mutation.accept(node);Files.write(folder.resolve(name),M.writeValueAsBytes(node));
        if(!name.equals("manifest.json"))rehash(folder,name);
    }
    private static void nativeEdit(Path folder,String name,java.util.function.Consumer<JsonNode> mutation)throws Exception {
        edit(folder,name,record->{try {var raw=Base64.getDecoder().decode(record.path("response_base64").asText());var value=M.readTree(raw);mutation.accept(value);
            byte[] bytes=M.writeValueAsBytes(value);((ObjectNode)record).put("response_base64",Base64.getEncoder().encodeToString(bytes));((ObjectNode)record).put("response_sha256",KeycloakAuthenticationIdentityEvidence.hash(bytes));
        }catch(Exception e){throw new IllegalStateException(e);}});
    }
    private static final class Fallback implements TestCase,ConfigurationPrompt,AttestationPrompt {
        public String id(){return KeycloakAuthenticationIdentityEvidence.CASE;}public TargetRole role(){return TargetRole.IDP;}
        public String instructionEn(){return "Native identity prerequisite";}public String promptEn(){return "Native identity evidence";}
        public List<AttestationOption> options(){return List.of();}
        public CaseStep start(CaseContext c){throw new AssertionError("Native proof escaped to declaration");}
        public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){throw new AssertionError("Native proof escaped to declaration");}
    }
    public static void main(String[] args)throws Exception {
        Path source=Path.of(args[0]).toRealPath(),output=Path.of(args[1]);var originalManifest=M.readTree(source.resolve("manifest.json").toFile());String run=originalManifest.path("runId").asText();
        var entries=List.of(M.readValue(source.resolve("transcript.json").toFile(),TranscriptEntry[].class));byte[] target=Files.readAllBytes(source.resolve("target-metadata.xml"));
        var decoded=new HashMap<String,byte[]>();for(var e:M.readTree(source.resolve("decoded-manifest.json").toFile())) {
            var raw=Files.readAllBytes(source.resolve(e.path("file").asText()));if(!KeycloakAuthenticationIdentityEvidence.hash(raw).equals(e.path("sha256").asText()))throw new IllegalArgumentException("Changed decoded original");decoded.put(e.path("id").asText(),raw);
        }
        final String[] history={""};var recorder=new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id){if(history[0].isBlank())return entries;var result=new ArrayList<>(entries);if(history[0].equals("duplicate-transcript")){result.add(entries.getFirst());return result;}
                try{var row=(ObjectNode)M.valueToTree(entries.getFirst());row.put("runId","run_00000000000000000000000000");result.set(0,M.treeToValue(row,TranscriptEntry.class));return result;}catch(Exception x){throw new IllegalStateException(x);}}
            public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read-only replay");}
            public TranscriptEntry updateSamlAnalysis(String r,String i,Map<String,Object>s){throw new AssertionError("Read-only replay");}
        };
        var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
        Path root=Files.createTempDirectory("kc-identity-replay-").toRealPath(),directory=Files.createDirectory(root.resolve("keycloak-authentication-identity-evidence")),folder=Files.createDirectory(directory.resolve(run));
        var originals=new HashMap<String,byte[]>();try(var paths=Files.walk(source)) {for(var path:paths.filter(Files::isRegularFile).toList()) {String name=source.relativize(path).toString();if(name.equals("manifest.json")||originalManifest.path("files").has(name)) {byte[] raw=Files.readAllBytes(path);originals.put(name,raw);Files.createDirectories(folder.resolve(name).getParent());Files.write(folder.resolve(name),raw);}}}
        var reader=args.length>4?new KeycloakAuthenticationIdentityEvidence(directory,e->decoded.get(e.id()),r->target,r->Optional.empty(),args[3],args[4]):new KeycloakAuthenticationIdentityEvidence(directory,e->decoded.get(e.id()),r->target,r->Optional.empty());
        boolean leafOnly=args.length>2&&args[2].equals("candidate-leaf");var wrapper=new AuthenticationIdentityConfigurationTestCase(new Fallback(),e->decoded.get(e.id()),r->target,r->Optional.empty(),root.resolve("authentication-identity-evidence"));
        var controls=new LinkedHashMap<String,String>();
        try {
            var result=reader.evaluate(context).orElseThrow();if(result.outcome()!=Outcome.SATISFIED)throw new IllegalStateException("Original evidence not conclusive: "+result);
            if(!leafOnly) lifecycle(wrapper,context,result);
            for(String name:List.of("wrong-run","wrong-case","wrong-target","wrong-adapter","wrong-campaign","wrong-profile","collector-changed","native-jar-changed","native-classpath-subset","missing-original","symlink-original","binding-changed","ambient-cookie-authenticator","required-password-disabled","execution-config-changed","policy-selector-added","client-config-changed","normal-cookie-present","passive-cookie-present","credential-before-challenge","credentials-recorded","missing-password-challenge","challenge-after-response","missing-password-projection","forged-challenge-path","normal-arrival-wrong-query","normal-arrival-wrong-request","passive-credential-present","wrong-positive-response","wrong-passive-response","not-restored","flow-inventory-differs","invalid-readback-redaction","cost-underreported","duplicate-transcript","foreign-transcript")) {
                history[0]="";for(var row:originals.entrySet())if(!Files.exists(folder.resolve(row.getKey()),LinkOption.NOFOLLOW_LINKS)||Files.isSymbolicLink(folder.resolve(row.getKey()))||!Arrays.equals(Files.readAllBytes(folder.resolve(row.getKey())),row.getValue())){Files.deleteIfExists(folder.resolve(row.getKey()));Files.write(folder.resolve(row.getKey()),row.getValue());}
                switch(name) {
                    case "wrong-run"->edit(folder,"manifest.json",m->((ObjectNode)m).put("runId","other"));
                    case "wrong-case"->edit(folder,"manifest.json",m->((ObjectNode)m).put("caseId","other"));
                    case "wrong-target"->edit(folder,"manifest.json",m->((ObjectNode)m).put("targetMetadataSha256","0".repeat(64)));
                    case "wrong-adapter"->edit(folder,"manifest.json",m->((ObjectNode)m).put("adapter","other"));
                    case "wrong-campaign"->edit(folder,"manifest.json",m->((ObjectNode)m).put("campaignId","other"));
                    case "wrong-profile"->edit(folder,"plan.json",m->((ObjectNode)m.at("/plan/plan")).put("profile","metadata_idp"));
                    case "collector-changed"->Files.writeString(folder.resolve("originals/collector.py"),"other");
                    case "native-jar-changed"->Files.writeString(folder.resolve("originals/native-runtime/org.keycloak.keycloak-services-26.7.2.jar"),"other");
                    case "native-classpath-subset"->{Files.writeString(folder.resolve("originals/before.native-classpath.txt"),"subset");rehash(folder,"originals/before.native-classpath.txt");}
                    case "missing-original"->Files.delete(folder.resolve("originals/native-client-before.json"));
                    case "symlink-original"->{Files.delete(folder.resolve("originals/native-client-before.json"));Files.createSymbolicLink(folder.resolve("originals/native-client-before.json"),source.resolve("originals/native-client-before.json"));}
                    case "binding-changed"->nativeEdit(folder,"originals/native-client-before.json",m->((ObjectNode)m.path("authenticationFlowBindingOverrides")).put("browser","00000000-0000-0000-0000-000000000000"));
                    case "ambient-cookie-authenticator"->nativeEdit(folder,"originals/flow-executions-before.json",m->((ObjectNode)m.get(0)).put("providerId","auth-cookie"));
                    case "required-password-disabled"->nativeEdit(folder,"originals/flow-executions-before.json",m->((ObjectNode)m.get(0)).put("requirement","DISABLED"));
                    case "execution-config-changed"->nativeEdit(folder,"originals/flow-executions-after.json",m->((ObjectNode)m.get(0)).put("level",1));
                    case "policy-selector-added"->nativeEdit(folder,"originals/policy-policies-before.json",m->((ObjectNode)m).putArray("policies").addObject().put("enabled",true));
                    case "client-config-changed"->nativeEdit(folder,"originals/native-client-after.json",m->((ObjectNode)m.path("attributes")).put("saml.client.signature","false"));
                    case "normal-cookie-present"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(0)).put("cookieCountBefore",1));
                    case "passive-cookie-present"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(2)).put("cookieCountBefore",1));
                    case "credential-before-challenge"->edit(folder,"credential-actions.json",m->((ObjectNode)m.get(0)).put("recordedAt","2000-01-01T00:00:00Z"));
                    case "credentials-recorded"->edit(folder,"credential-actions.json",m->((ObjectNode)m.get(0)).put("valuesPersisted",true));
                    case "missing-password-challenge"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(1)).put("kind","unrelated"));
                    case "challenge-after-response"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(1)).put("recordedAt","2099-01-01T00:00:00Z"));
                    case "missing-password-projection"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(1)).putArray("inputNames").add("username"));
                    case "forged-challenge-path"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(1)).put("publicResponsePath","/unrelated"));
                    case "normal-arrival-wrong-query"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(0)).put("rawQuerySha256","0".repeat(64)));
                    case "normal-arrival-wrong-request"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(0)).put("requestId","other"));
                    case "passive-credential-present"->edit(folder,"native-observations.json",m->((ObjectNode)m.get(2)).put("credentialPostsBefore",1));
                    case "wrong-positive-response"->edit(folder,"manifest.json",m->((ObjectNode)m).put("positiveResponseReference",m.path("passiveResponseReference").asText()));
                    case "wrong-passive-response"->edit(folder,"manifest.json",m->((ObjectNode)m).put("passiveResponseReference",m.path("positiveResponseReference").asText()));
                    case "not-restored"->edit(folder,"restoration.json",m->((ObjectNode)m).put("restored",false));
                    case "flow-inventory-differs"->nativeEdit(folder,"originals/flow-inventory-after.json",m->((com.fasterxml.jackson.databind.node.ArrayNode)m).remove(0));
                    case "invalid-readback-redaction"->edit(folder,"originals/native-client-before.json",m->{((ObjectNode)m).put("response_projection","native-client-public-readback-v1");((ObjectNode)m).putArray("redactions").add("$.authenticationFlowBindingOverrides");});
                    case "cost-underreported"->edit(folder,"operation-counts.json",m->((ObjectNode)m).put("protocol_operations_attempted",1));
                    case "duplicate-transcript","foreign-transcript"->history[0]=name;
                }
                var invalid=reader.evaluate(context).orElseThrow();if(invalid.outcome()!=Outcome.NOT_VERIFIED)throw new IllegalStateException("Invalid original accepted: "+name);
                if(!leafOnly&&(!(wrapper.start(context) instanceof CaseStep.Finish f)||f.outcome().outcome()!=Outcome.NOT_VERIFIED||wrapper.evidenceStatus(context).ready()))throw new IllegalStateException("Owned invalid escaped: "+name);
                controls.put(name,"NOT_VERIFIED");
            }
            Files.write(output,M.writerWithDefaultPrettyPrinter().writeValueAsBytes(Map.of("runId",run,"production_outcome",result,"negative_controls",controls,"shared_native_lifecycle",!leafOnly,"manifestSha256",KeycloakAuthenticationIdentityEvidence.hash(originals.get("manifest.json")),"transcriptSha256",KeycloakAuthenticationIdentityEvidence.hash(Files.readAllBytes(source.resolve("transcript.json"))),"privateMaterialExported",false)),StandardOpenOption.CREATE_NEW);
            System.out.println("Keycloak authentication identity production replay PASS: "+controls.size()+" altered-original controls");
        }finally{try(var paths=Files.walk(root)){for(var p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
    }
    private static void lifecycle(AuthenticationIdentityConfigurationTestCase wrapper,CaseContext context,CaseOutcome result) {
        require(new CaseStep.Finish(result).equals(wrapper.start(context))&&new CaseStep.Finish(result).equals(wrapper.resume(context,CaseState.initial(),new CaseEvent.TranscriptReady()))&&wrapper.evidenceStatus(context).ready()
            &&wrapper.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","case.pending-interaction")).orElseThrow().equals(result));
    }
    private static void require(boolean c){if(!c)throw new IllegalStateException("Native lifecycle differs");}
}
