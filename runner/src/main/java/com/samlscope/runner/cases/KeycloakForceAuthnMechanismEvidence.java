package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;
import java.util.function.Function;
import java.util.jar.JarFile;
import java.util.concurrent.TimeUnit;

/** Original-backed native producer/selected-form access capability; never a live true password login. */
final class KeycloakForceAuthnMechanismEvidence implements NativeForceAuthnMechanismEvidence {
    static final String SCHEMA="samlscope-keycloak-forceauthn-mechanism-v1";
    static final String CASE="IIP-IDP06-b-idp-01";
    static final String DIGEST="sha256:7642c77cfa0d640d1cc6baf96d91301709754a1a4597db479114c855e26bd671";
    static final String CLASSPATH="3073a5b0513586ca9faa3319c459204209038e2c1dfe9044a77645465a98d68e";
    static final String COLLECTOR="9f426e9a4449490d8333422e973569bf50a2738ccf4d96d755917d29a20bddaa";
    static final String HELPER="6fabbc63c3a9e1adadb13c5792c204e78009f012502290094bed2a4970b89c7e";
    private static final String PACKAGED_HELPER="2d5f38a4ae72f1c6cfa0f37eba9016f7ee16758832769c61e8e8befaca346b49";
    private static final Map<String,String> HELPER_CLASSES=Map.ofEntries(
        Map.entry("ProbeKeycloakForceAuthnMechanism$Boundary.class","d46106b68f204f4fd68f417cf34498b01221abadc05f4e1c24a107ff7d011607"),
        Map.entry("ProbeKeycloakForceAuthnMechanism$Call.class","38e15609c35bbef2d38c02b48e377f918bd05ed601f437c67246c71b99bb6f18"),
        Map.entry("ProbeKeycloakForceAuthnMechanism$Environment$1.class","a8816141cd73f1c5012faa5484337b93b74dbcd27b36e149789b580fb70f9877"),
        Map.entry("ProbeKeycloakForceAuthnMechanism$Environment.class","0b46b933603607f2ead190e91f3d15f3c113dbf95ffc023ae9593b0a8fddfef8"),
        Map.entry("ProbeKeycloakForceAuthnMechanism$Producer.class","f9d55bd424e83662f2c78b0779e11fb996caf728a34446d7d99ab01eb1594ce3"),
        Map.entry("ProbeKeycloakForceAuthnMechanism.class","032e244e0d24ed9be5a661d4a1a13e1bea596d4109bb2f48d748da8f249868aa"));
    private static final String SCOPE_COLLECTOR="5ac9ec97048c29ef28541d6dbfe4cde21a6e7fa6367ebfa8984cfb4003202d7a";
    private static final String MECHANISM="org.keycloak.authentication.authenticators.browser.UsernamePasswordForm";
    private static final Map<String,String> CLASSES=Map.ofEntries(
        Map.entry("org.keycloak.protocol.saml.SamlService","9595db004ef39dfa3e560ae4817d30646c15d117dbff08737283d14f0fbc7f45"),
        Map.entry("org.keycloak.protocol.saml.SamlService$BindingProtocol","1567d07d08492c6a80587e50e1db84ce5a4aab8a32ead70f043a7b8648ce172d"),
        Map.entry("org.keycloak.protocol.AuthorizationEndpointBase","b10ed06caead23572261319c2196a3c1aa1aa36f2dd6260750da552049513e65"),
        Map.entry("org.keycloak.models.utils.AuthenticationFlowResolver","0c27c207e5cef377b938f1962d0244b6301522cc0d229f01309a7541bd2ad034"),
        Map.entry("org.keycloak.authentication.AuthenticationProcessor","ffb7dfb5bf5485111c042520292455656869212516323cc07875c96d1334776d"),
        Map.entry("org.keycloak.authentication.AuthenticationProcessor$Result","29287972e753543234a1fac819d664f2265785b69b5f465e0213f276c546332d"),
        Map.entry("org.keycloak.authentication.DefaultAuthenticationFlow","0441eb9182e7787c703795f8a8ec27c11872ffa2afdeb243cf6f186f521dce81"),
        Map.entry("org.keycloak.authentication.AuthenticationSelectionResolver","6130599a333da5844664b07389143ed5f163039a127af33fccae3dded6d87537"),
        Map.entry(MECHANISM,"e48578be61fe13b03148acd965a368e16205baf6db242c177353c7deb6ed9615"),
        Map.entry(MECHANISM+"Factory","530479a13f2254b337f8fb4f0f41e265ac68191bdddefa6eecf294b8a521cb2d"),
        Map.entry("org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter","a1f6d3ea291455f06268c88fffa70a5d902bc2ddf5d9c274744c68cc606f144b"),
        Map.entry("org.keycloak.models.sessions.infinispan.entities.AuthenticationSessionEntity","63861e84ad3d6b9a4380cd629e28a0da3ad55dc19a811f40d1c9852d7e24d716"),
        Map.entry("org.keycloak.protocol.saml.SamlProtocol","4ad89b08f6d37e00a02e3cb0a4563883935f7d66b3f3bb717f9da8c316104100"),
        Map.entry("org.keycloak.saml.processing.core.parsers.saml.SAMLParser","9cdd0be734dd0b50b1d9df146551a33dbc594872a1cedbcea09bc51e2e503e1a"),
        Map.entry("org.keycloak.dom.saml.v2.protocol.AuthnRequestType","3601c3a11c25e79f3a654acf21d46682e841ec20cf7ee64c835dab64b9561d08"));
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final DefaultAlgorithmSourceRunStore sourceStore;
    private final ObjectMapper json=new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    KeycloakForceAuthnMechanismEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,DefaultAlgorithmSourceRunStore sourceStore) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.sourceStore=Objects.requireNonNull(sourceStore);
        require(CASE.equals(sourceStore.approvedCaseId())&&DIGEST.equals(sourceStore.approvedCaseDigest()));
    }
    private Path folder(String run){return directory.resolve(run+".keycloak-forceauthn-mechanism");}
    public boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS);}
    public NativeForceAuthnMechanismEvidence withKeys(SamlDecryptionKeyProvider ignored){return this;}
    public Optional<CaseOutcome> read(CaseContext context) {
        if(!exists(context.runId()))return Optional.empty();String stage="approved-source-run";
        try {
            require(context.transcriptComplete()&&context.targetRole()==TargetRole.IDP);
            var binding=sourceStore.execution(context.runId());
            require("browser_sso_idp".equals(binding.plan().profile().id())&&context.runId().equals(binding.run().id()));
            Path f=folder(context.runId());byte[] manifestRaw=raw(f,"manifest.json");var m=json.readTree(manifestRaw);
            require(SCHEMA.equals(text(m,"schema"))&&CASE.equals(text(m,"caseId"))&&DIGEST.equals(text(m,"caseDigest"))
                &&context.runId().equals(text(m,"runId"))&&binding.plan().id().equals(text(m,"planId"))
                &&"native-authentication-mechanism".equals(text(m,"campaignId")));
            var files=m.path("files");require(files.isObject()&&files.size()>500&&files.size()<1000);
            var names=files.fieldNames();while(names.hasNext()){String name=names.next();require(hash(raw(f,name)).equals(text(files,name)));}
            require(stableSnapshot(binding.snapshot()).equals(json.readTree(checked(f,files,"source-store-snapshot.json")))
                &&sourceStore.history(context.runId(),context.transcript().list(context.runId()),content).equals(json.readTree(checked(f,files,"source-history.json"))));
            require(Arrays.equals(metadata.apply(context.runId()),checked(f,files,"target-metadata.xml"))
                &&hash(metadata.apply(context.runId())).equals(text(m,"targetMetadataSha256")));
            var membership=json.readTree(checked(f,files,"approved-membership.json"));
            require(context.runId().equals(text(membership,"runId"))&&binding.plan().id().equals(text(membership,"planId"))
                &&CASE.equals(text(membership,"caseId"))&&DIGEST.equals(text(membership,"caseDigest"))
                &&json.valueToTree(binding.plan().definitionIdentity()).equals(membership.path("definitionIdentity")));
            stage="original-native-authentication-baseline";
            Path source=f.resolve("source");
            var baseline=new KeycloakAuthenticationIdentityEvidence(source,content,metadata,r->Optional.empty(),COLLECTOR,CLASSPATH).evaluate(context).orElseThrow();
            require(baseline.outcome()==Outcome.SATISFIED);
            Path originalFolder=source.resolve(context.runId());var original=json.readTree(raw(originalFolder,"manifest.json"));
            require(hash(raw(originalFolder,"manifest.json")).equals(text(m,"sourceManifestSha256"))
                &&Arrays.equals(raw(originalFolder,"originals/before.native-classpath.txt"),checked(f,files,"native-classpath.txt")));
            stage="unchanged-native-origins";
            require(HELPER.equals(hash(checked(f,files,"native-helper.java"))));
            var trace=json.readTree(checked(f,files,"native-trace.json"));var process=json.readTree(checked(f,files,"native-process.json"));
            require("samlscope-keycloak-forceauthn-native-instrumentation-v1".equals(text(trace,"schema"))
                &&"isolated-native-request-producer-and-selected-password-boundary-capability".equals(text(trace,"scope"))
                &&isFalse(trace,"trueLivePasswordUiExecutionClaimed")&&isFalse(trace,"sourceOriginalsChanged")&&isFalse(trace,"verdictAdopted")
                &&process.path("exitCode").asInt(-1)==0&&process.path("isolatedInfrastructure").asBoolean(false)
                &&HELPER.equals(text(process,"helperSha256"))&&CLASSPATH.equals(text(process,"nativeClasspathSha256")));
            for(String cost:List.of("productSettingWrites","protocolSubmissions","credentialPosts"))require(trace.path(cost).isInt()&&trace.path(cost).asInt(-1)==0&&process.path(cost).asInt(-1)==0);
            verifyNativeSupplement(f,files,m,process,originalFolder,binding);
            verifyOrigins(f,files,trace);
            stage="native-producer-selected-mechanism-controls";
            var entries=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(context.runId()))require(context.runId().equals(e.runId())&&entries.put(e.id(),e)==null);
            var normal=entries.get(text(original,"positiveRequestReference"));var forced=entries.get(text(original,"passiveRequestReference"));require(normal!=null&&forced!=null);
            byte[] normalRaw=content.readDecodedSaml(normal),forcedRaw=content.readDecodedSaml(forced);
            var n=SecureXml.parse(normalRaw).getDocumentElement();var t=SecureXml.parse(forcedRaw).getDocumentElement();
            var client=reply(raw(originalFolder,"originals/native-client-before.json"));String flow=text(client.path("authenticationFlowBindingOverrides"),"browser");
            require(client.path("enabled").isBoolean()&&client.path("enabled").booleanValue()&&"saml".equals(text(client,"protocol"))
                &&isFalse(client,"consentRequired")&&isFalse(client,"alwaysDisplayInConsole"));
            var rows=trace.path("traces");require(rows.isArray()&&rows.size()==5);
            check(rows.get(0),normalRaw,n,false,false,"none",flow,Outcome.SATISFIED);
            check(rows.get(1),forcedRaw,t,true,true,"none",flow,Outcome.SATISFIED);
            check(rows.get(2),forcedRaw,t,true,true,"drop-indicator",flow,Outcome.VIOLATED);
            check(rows.get(3),forcedRaw,t,true,true,"lose-indicator",flow,Outcome.VIOLATED);
            check(rows.get(4),forcedRaw,t,true,true,"misbound-request",flow,Outcome.NOT_VERIFIED);
            stage="actual-native-producer-selected-mechanism-replay";
            replayNative(f,files,originalFolder,normalRaw,forcedRaw,trace);
            var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",SCHEMA);details.put("run_id",context.runId());
            details.put("approved_mode","ATTESTED");details.put("attested",false);details.put("scope","isolated-native-producer-selected-password-boundary-capability");
            details.put("true_live_password_ui_execution",false);details.put("true_live_no_passive_retained",true);details.put("same_native_session_object",true);
            details.put("native_selected_flow_executed",true);details.put("positive_flag_seeded_by_harness",false);details.put("selected_mechanism",MECHANISM);
            details.put("isolated_infrastructure_doubles",List.of("archived-public-realm-client-models","fresh-native-infinispan-session-factory","cookie-services"));
            details.put("native_instrumented_mutants",List.of("drop-indicator","lose-indicator","misbound-request"));details.put("configuration_restored",true);details.put("realm_scope","later-read-only-native-replay-supplement");
            var refs=new ArrayList<>(baseline.evidence());refs.add(new EvidenceRef("native-force-authn-mechanism",context.runId()+".keycloak-forceauthn-mechanism/manifest.json#"+hash(manifestRaw)));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,"idp.force-authn.mechanism-reachability.native-proven","idp.force-authn.mechanism-reachability.native-proven",refs,details));
        }catch(Exception missing){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_mechanism_reachability_unproven","idp.force-authn.mechanism-reachability.unproven","idp.force-authn.mechanism-reachability.unproven",List.of(),Map.of("evidence_adapter",SCHEMA,"stage",stage)));}
    }
    static JsonNode stableSnapshot(JsonNode snapshot){var stable=((ObjectNode)snapshot).deepCopy();stable.remove(List.of("runDocumentSha256","caseExecutionSha256"));return stable;}
    /** Replays every native control on original request bytes; recorded booleans alone cannot qualify. */
    private void replayNative(Path f,JsonNode files,Path source,byte[] normal,byte[] forced,JsonNode expected)throws Exception {
        byte[] resource;
        try(var input=KeycloakForceAuthnMechanismEvidence.class.getResourceAsStream("native-keycloak-forceauthn-helper.json")) {
            require(input!=null);resource=input.readNBytes(100_001);require(resource.length<=100_000&&PACKAGED_HELPER.equals(hash(resource)));
        }
        var packaged=json.readTree(resource);require("samlscope-keycloak-forceauthn-packaged-helper-v1".equals(text(packaged,"schema"))
            &&HELPER.equals(text(packaged,"sourceSha256"))&&CLASSPATH.equals(text(packaged,"nativeClasspathSha256")));
        var classes=packaged.path("classes");require(classes.isObject()&&classes.size()==HELPER_CLASSES.size());
        Path temporary=Files.createTempDirectory("kc-forceauthn-native-replay-");Process process=null;
        try {
            Path compiled=Files.createDirectory(temporary.resolve("classes")),originals=Files.createDirectory(temporary.resolve("originals"));
            for(var entry:HELPER_CLASSES.entrySet()) {
                var record=classes.path(entry.getKey());byte[] bytes=Base64.getDecoder().decode(text(record,"base64"));
                require(entry.getValue().equals(text(record,"sha256"))&&entry.getValue().equals(hash(bytes)));
                Files.write(compiled.resolve(entry.getKey()),bytes);
            }
            for(String name:List.of("native-client-before.json","flow-executions-before.json","flow-creation.json"))
                Files.write(originals.resolve(name),checked(f,files,f.relativize(source.resolve("originals").resolve(name)).toString()));
            Files.write(originals.resolve("native-realm-before.json"),checked(f,files,"native-realm-before.json"));
            Path normalFile=temporary.resolve("normal.xml"),forcedFile=temporary.resolve("forced.xml"),output=temporary.resolve("trace.json");
            Files.write(normalFile,normal);Files.write(forcedFile,forced);
            var nativePaths=new LinkedHashMap<String,String>();var classpath=new ArrayList<String>();classpath.add(compiled.toString());
            for(String line:new String(checked(f,files,"native-classpath.txt"),java.nio.charset.StandardCharsets.UTF_8).lines().toList()) {
                String nativePath=line.split("  ",-1)[1];String archive=f.resolve("native-complete/"+nativePath.substring("/opt/keycloak/lib/".length())).toString();
                require(nativePaths.put(archive,nativePath)==null);classpath.add(archive);
            }
            Path executable=Path.of(System.getProperty("java.home"),"bin","java");require(Files.isExecutable(executable));
            var launch=new ProcessBuilder(executable.toString(),"-Xmx512m","-cp",String.join(java.io.File.pathSeparator,classpath),
                "ProbeKeycloakForceAuthnMechanism",temporary.toString(),normalFile.toString(),forcedFile.toString(),output.toString())
                .directory(temporary.toFile()).redirectErrorStream(true).redirectOutput(temporary.resolve("process.log").toFile());
            launch.environment().clear();process=launch.start();
            require(process.waitFor(20,TimeUnit.SECONDS)&&process.exitValue()==0);
            var replay=json.readTree(raw(temporary,"trace.json"));require(replay.path("classes").isArray());
            for(var origin:replay.path("classes")) {
                String canonical=nativePaths.get(text(origin,"jarPath"));require(canonical!=null);((ObjectNode)origin).put("jarPath",canonical);
            }
            require(replay.equals(expected));
        } finally {
            if(process!=null&&process.isAlive()){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS);}
            try(var paths=Files.walk(temporary)){for(var path:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(path);}
        }
    }
    private void verifyNativeSupplement(Path f,JsonNode files,JsonNode manifest,JsonNode process,Path source,DefaultAlgorithmSourceRunStore.Binding binding)throws Exception {
        require(SCOPE_COLLECTOR.equals(hash(checked(f,files,"native-scope-collector.py"))));
        var before=json.readTree(checked(f,files,"native-scope-before.json"));var after=json.readTree(checked(f,files,"native-scope-after.json"));
        var model=reply(checked(f,files,"native-realm-before.json"));
        var originalRuntime=json.readTree(raw(source,"originals/before.environment.json")).path("runtime");
        var restoredFlows=reply(raw(source,"originals/flow-inventory-before.json"));
        for(var scope:List.of(before,after)) {
            require("samlscope-keycloak-forceauthn-later-native-scope-v1".equals(text(scope,"schema"))
                &&"later-read-only-native-replay-supplement".equals(text(scope,"scope"))
                &&binding.run().id().equals(text(scope,"runId"))&&binding.plan().id().equals(text(scope,"planId"))
                &&binding.plan().target().entityId().equals(text(scope,"targetEntityId"))
                &&text(manifest,"sourceManifestSha256").equals(text(scope,"sourceManifestSha256"))
                &&hash(checked(f,files,"source-store-snapshot.json")).equals(text(scope,"sourceStoreSnapshotSha256"))
                &&hash(checked(f,files,"source-history.json")).equals(text(scope,"sourceHistorySha256"))
                &&CLASSPATH.equals(text(scope,"nativeClasspathSha256"))&&originalRuntime.equals(scope.path("runtime")));
            var record=scope.path("realmRecord");require("native-realm-public-authentication-view-v1".equals(text(record,"response_projection"))
                &&model.equals(nativeReply(record,"http://localhost:18180/admin/realms/samlscope"))
                &&"samlscope".equals(text(model,"realm"))&&!text(model,"id").isBlank());
            String lookup="http://localhost:18180/admin/realms/samlscope/clients?clientId="+java.net.URLEncoder.encode("http://localhost:18080/p/"+binding.plan().id(),java.nio.charset.StandardCharsets.UTF_8);
            var absentClient=nativeReply(scope.path("restoredClientAbsenceRecord"),lookup);
            require(absentClient.isArray()&&absentClient.isEmpty()
                &&restoredFlows.equals(nativeReply(scope.path("restoredFlowInventoryRecord"),"http://localhost:18180/admin/realms/samlscope/authentication/flows")));
            var operations=scope.path("operations");require(operations.isArray()&&operations.size()==3);
            for(var operation:operations)require("GET".equals(text(operation,"method"))&&operation.path("status").asInt(-1)==200&&isFalse(operation,"productSettingWrite"));
            for(String cost:List.of("productSettingWrites","protocolSubmissions","credentialPosts"))require(scope.path(cost).isInt()&&scope.path(cost).asInt(-1)==0);
        }
        require(before.path("realmRecord").path("response_sha256").equals(after.path("realmRecord").path("response_sha256"))
            &&before.path("realmRecord").path("unprojected_response_sha256").equals(after.path("realmRecord").path("unprojected_response_sha256"))
            &&java.time.Instant.parse(text(before.path("realmRecord"),"recordedAt")).isBefore(java.time.Instant.parse(text(process,"startedAt")))
            &&java.time.Instant.parse(text(process,"finishedAt")).isBefore(java.time.Instant.parse(text(after.path("realmRecord"),"recordedAt"))));
    }
    private JsonNode nativeReply(JsonNode record,String url)throws Exception {
        require("GET".equals(text(record,"method"))&&url.equals(text(record,"url"))&&record.path("status").asInt(-1)==200);
        byte[] raw=Base64.getDecoder().decode(text(record,"response_base64"));require(hash(raw).equals(text(record,"response_sha256")));return json.readTree(raw);
    }
    private void verifyOrigins(Path f,JsonNode files,JsonNode trace)throws Exception {
        byte[] inventory=checked(f,files,"native-classpath.txt");require(CLASSPATH.equals(hash(inventory)));
        var jars=new LinkedHashMap<String,String>();var occurrences=new HashMap<String,List<String>>();
        for(String line:new String(inventory,java.nio.charset.StandardCharsets.UTF_8).lines().toList()){
            var parts=line.split("  ",-1);require(parts.length==2&&parts[0].matches("[0-9a-f]{64}")&&parts[1].startsWith("/opt/keycloak/lib/")&&jars.put(parts[1],parts[0])==null);
            String name="native-complete/"+parts[1].substring("/opt/keycloak/lib/".length());byte[] archived=checked(f,files,name);require(hash(archived).equals(parts[0]));
            try(var zip=new JarFile(f.resolve(name).toFile())){for(String cls:CLASSES.keySet()){var entry=zip.getJarEntry(cls.replace('.','/')+".class");if(entry!=null){
                require(CLASSES.get(cls).equals(hash(zip.getInputStream(entry).readAllBytes())));occurrences.computeIfAbsent(cls,k->new ArrayList<>()).add(parts[1]);}}}
        }
        require(jars.size()==471);var seen=new HashSet<String>();var origins=trace.path("classes");require(origins.isArray()&&origins.size()==CLASSES.size());
        for(var origin:origins){String cls=text(origin,"class"),jar=text(origin,"jarPath");require(seen.add(cls)&&CLASSES.containsKey(cls)
            &&CLASSES.get(cls).equals(text(origin,"classSha256"))&&Objects.equals(jars.get(jar),text(origin,"jarSha256"))&&List.of(jar).equals(occurrences.get(cls)));}
    }
    private static void check(JsonNode row,byte[] raw,org.w3c.dom.Element request,boolean forced,boolean passive,String mutant,String flow,Outcome expected)throws Exception {
        require(hash(raw).equals(text(row,"inputSha256"))&&request.getAttribute("ID").equals(text(row,"requestId"))&&mutant.equals(text(row,"mutation"))
            &&row.path("inputForceAuthn").isBoolean()&&row.path("inputForceAuthn").asBoolean()==forced&&row.path("inputIsPassive").asBoolean()==passive
            &&row.path("inputIsPassive").isBoolean()&&row.path("nativeFlagInitiallyAbsent").asBoolean(false)&&isFalse(row,"positiveFlagSeededByHarness")
            &&row.path("sameNativeSessionObject").asBoolean(false)&&row.path("nativeSelectedFlowExecuted").asBoolean(false)&&row.path("mechanismEntryExecuted").asBoolean(false)
            &&"org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter".equals(text(row,"nativeSessionClass"))
            &&"org.keycloak.authentication.AuthenticationProcessor$Result".equals(text(row,"nativeResultClass"))&&flow.equals(text(row,"nativeResolvedFlowId"))
            &&row.path("producerNativeIndicator").isBoolean()&&row.path("producerNativeIndicator").asBoolean()==forced
            &&row.path("producerRawNotePresent").isBoolean()&&row.path("producerRawNotePresent").asBoolean()==forced
            &&request.getAttribute("ID").equals(text(row,"producerRequestId"))&&row.path("mechanismNativeIndicator").isBoolean());
        require(NativeMechanismStateComparison.compare(new NativeMechanismStateComparison.Observation(request.getAttribute("ID"),forced,
            text(row,"mechanismRequestId"),row.path("mechanismNativeIndicator").booleanValue(),MECHANISM,text(row,"mechanismClass")))==expected);
        if(mutant.equals("none"))require(row.path("mechanismRawNotePresent").isBoolean()&&row.path("mechanismRawNotePresent").asBoolean()==forced);
    }
    private JsonNode reply(byte[] raw)throws Exception {var record=json.readTree(raw);return json.readTree(Base64.getDecoder().decode(text(record,"response_base64")));}
    private static boolean isFalse(JsonNode n,String key){return n.path(key).isBoolean()&&!n.path(key).booleanValue();}
    private static String text(JsonNode n,String key){return DefaultAlgorithmPreventionEvidence.text(n,key);}
    private static String hash(byte[] raw)throws Exception{return DefaultAlgorithmPreventionEvidence.hash(raw);}
    private static void require(boolean value){DefaultAlgorithmPreventionEvidence.require(value);}
    private static byte[] checked(Path f,JsonNode files,String name)throws Exception {byte[] bytes=raw(f,name);require(hash(bytes).equals(text(files,name)));return bytes;}
    private static byte[] raw(Path f,String name)throws Exception {
        require(name!=null&&!Path.of(name).isAbsolute());Path path=f.resolve(name).toAbsolutePath().normalize();require(path.startsWith(f.toAbsolutePath().normalize())&&!path.equals(f));
        for(Path at=path;at!=null;at=at.getParent())require(!Files.isSymbolicLink(at));require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<=67_108_864);return Files.readAllBytes(path);
    }
}
