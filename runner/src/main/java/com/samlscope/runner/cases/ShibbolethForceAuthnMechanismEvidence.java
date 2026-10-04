package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Function;
import java.util.jar.JarFile;

/** Selected stock Password-boundary instrumented capability, not live true/IsPassive UI execution.
 * The signed ae originals retain their native Success/NoPassive results. No operator declaration is invented.
 * Native fixture replay is an adoption requirement; mode remains the approved ATTESTED mode.
 */
final class ShibbolethForceAuthnMechanismEvidence {
    static final String SCHEMA="samlscope-shibboleth-force-authn-mechanism-v1";
    static final String KIND="native-force-authn-mechanism";
    static final String REASON="idp.force-authn.mechanism-reachability.native-proven";
    static final String NATIVE_CLASSPATH_SHA256="53237205e9eaf6d719d6f8dc4257938880ee0e856b18cf0722014be458f57a18";
    static final String HELPER="0c4b156aca2f5ac3821ed181e9dee00015067e0165ee901e6103dfd71e97aae2";
    static final String CONF="428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba";
    private static final Map<String,String> CLASSES=Map.of(
        "net.shibboleth.idp.saml.profile.impl.InitializeAuthenticationContext","f7292b84b9646d9924fe0a2bd0d6e5abe7c38eb4f3c528cd77a55ae6e6965ac1",
        "net.shibboleth.idp.authn.context.AuthenticationContext","28c9ab22b5ee13cb62b29f9163137ccdec6cc38f61da7cf20d291cd61ce83d99",
        "net.shibboleth.idp.saml.saml2.profile.config.impl.BrowserSSOProfileConfiguration","0f2f7e3a146c0a1fedd7f34f0d1b6b423d7d58de609946722869c5ce2c1c5c31",
        "org.springframework.expression.spel.standard.SpelExpressionParser","7ce9ad2bb208745c36c70e8fe2f7fd4220459a4f60dcd2991b5cffd1aa3959ba",
        "org.opensaml.profile.context.ProfileRequestContext","9761c8144114ba2b04e8a2a6596dee6cb8e72420bcf02986c825110295fbeac5");
    private static final String EXPR="opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext))";
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    ShibbolethForceAuthnMechanismEvidence(Path directory,TranscriptContentReader content,Function<String,byte[]> metadata,SamlDecryptionKeyProvider keys){
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.content=Objects.requireNonNull(content);
        this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    ShibbolethForceAuthnMechanismEvidence withKeys(SamlDecryptionKeyProvider provider){return new ShibbolethForceAuthnMechanismEvidence(directory,content,metadata,provider);}
    boolean exists(String run){return safe(run)&&(Files.exists(receipt(run),LinkOption.NOFOLLOW_LINKS)||Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS));}
    private Path receipt(String run){return directory.resolve(run+".shibboleth-force-authn-mechanism.json");}
    private Path folder(String run){return directory.resolve(run+".shibboleth-force-authn-mechanism");}
    private static boolean safe(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    Optional<CaseOutcome> read(CaseContext context){
        if(!exists(context.runId()))return Optional.empty();String stage="native-originals";
        try{
            require(context.transcriptComplete()&&safe(context.runId())&&!Files.isSymbolicLink(directory));
            var path=receipt(context.runId());require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS));
            byte[] manifestRaw=Files.readAllBytes(path);require(manifestRaw.length<262144);
            var json=new JsonCodec().mapper();var m=json.readTree(manifestRaw);var f=folder(context.runId());
            require(Files.isDirectory(f,LinkOption.NOFOLLOW_LINKS)&&m.path("schema").asText().equals(SCHEMA)
                &&m.path("runId").asText().equals(context.runId())&&hash(metadata.apply(context.runId())).equals(m.path("targetMetadataSha256").asText()));
            stage="original-bound-native-authentication-baseline";
            var baseline=new ShibbolethAuthenticationIdentityEvidenceFile(directory.resolveSibling("authentication-identity-evidence"),content,metadata,keys).evaluate(context);
            require(baseline.outcome()==Outcome.SATISFIED);
            var aeFolder=directory.resolveSibling("authentication-identity-evidence").resolve(context.runId());
            var ae=json.readTree(raw(aeFolder,"manifest.json"));
            stage="native-code-and-selected-flow";
            require(hash(checked(f,m,"helperFile","helperSha256")).equals(HELPER));
            var trace=json.readTree(checked(f,m,"traceFile","traceSha256"));
            require(trace.path("schema").asText().equals("samlscope-shibboleth-forceauthn-native-instrumentation-v1")
                &&trace.path("scope").asText().equals("isolated-native-stock-password-boundary-capability")
                &&trace.path("trueLivePasswordUiExecutionClaimed").isBoolean()&&!trace.path("trueLivePasswordUiExecutionClaimed").asBoolean()
                &&EXPR.equals(trace.path("nativeExpression").asText()));
            var invalidClasspath=guardNativeClasspath(raw(f,"native-classpath-before.json"));if(invalidClasspath.isPresent())return invalidClasspath;
            var nativeClasspath=json.readTree(raw(f,"native-classpath-before.json"));require(Arrays.equals(raw(f,"native-classpath-before.json"),raw(f,"native-classpath-after.json")));
            var cpFields=nativeClasspath.fields();int jarCount=0;while(cpFields.hasNext()){var field=cpFields.next();require(hash(safeFile(f.resolve("native-libs"),field.getKey())).equals(field.getValue().asText()));jarCount++;}require(jarCount==127);
            var origins=trace.path("classes");require(origins.isArray()&&origins.size()==CLASSES.size());var seen=new HashSet<String>();
            for(var origin:origins){String cls=origin.path("class").asText();require(seen.add(cls)&&CLASSES.containsKey(cls));
                var jar=safeFile(f.resolve("native-libs"),origin.path("jarFile").asText());require(hash(jar).equals(origin.path("jarSha256").asText())&&nativeClasspath.path(origin.path("jarFile").asText()).asText().equals(hash(jar)));
                try(var zip=new JarFile(f.resolve("native-libs").resolve(origin.path("jarFile").asText()).toFile())){
                    require(CLASSES.get(cls).equals(origin.path("classSha256").asText()));
                    require(hash(zip.getInputStream(zip.getJarEntry(cls.replace('.','/')+".class")).readAllBytes()).equals(CLASSES.get(cls)));
                }
            }
            byte[] conf=safeFile(f.resolve("native-libs"),"idp-conf-impl-5.2.3.jar");require(hash(conf).equals(CONF));
            try(var jar=new JarFile(f.resolve("native-libs/idp-conf-impl-5.2.3.jar").toFile())){
                byte[] flow=jar.getInputStream(jar.getJarEntry("net/shibboleth/idp/flows/authn/password-authn-flow.xml")).readAllBytes();
                require(hash(flow).equals(trace.path("nativeFlowSha256").asText()));
                var nodes=SecureXml.parse(flow).getElementsByTagNameNS("http://www.springframework.org/schema/webflow","evaluate");int match=0;
                for(int i=0;i<nodes.getLength();i++){var e=(org.w3c.dom.Element)nodes.item(i);if("viewScope.authenticationContext".equals(e.getAttribute("result"))){require(EXPR.equals(e.getAttribute("expression")));match++;}}
                require(match==1);
            }
            stage="same-run-request-bound-instrumented-traces";
            var entries=new HashMap<String,com.samlscope.core.transcript.TranscriptEntry>();
            for(var entry:context.transcript().list(context.runId()))require(context.runId().equals(entry.runId())&&entries.put(entry.id(),entry)==null);
            var normal=entries.get(ae.path("positive").path("requestReference").asText());var forced=entries.get(ae.path("unable").path("requestReference").asText());
            require(normal!=null&&forced!=null);var normalRaw=content.readDecodedSaml(normal);var forcedRaw=content.readDecodedSaml(forced);
            var n=SecureXml.parse(normalRaw).getDocumentElement();var t=SecureXml.parse(forcedRaw).getDocumentElement();
            var rows=trace.path("traces");require(rows.isArray()&&rows.size()==6);
            check(rows.get(0),normalRaw,n,false,false,"none",true);check(rows.get(1),forcedRaw,t,true,true,"none",true);
            var mutants=List.of("strip-input-flag","drop-context","misbound-context","lose-context-flag");
            for(int i=0;i<mutants.size();i++)check(rows.get(i+2),forcedRaw,t,true,true,mutants.get(i),false);
            stage="native-process-and-configuration-epoch";
            var reads=json.readTree(checked(f,m,"readbacksFile","readbacksSha256"));require(reads.path("exitCode").asInt(-1)==0);
            require(Arrays.equals(raw(f,"runtime-before.json"),raw(f,"runtime-after.json")));
            var runtime=json.readTree(raw(f,"runtime-before.json"));require(runtime.path("State").path("Running").asBoolean()
                &&runtime.path("Image").asText().equals("sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a"));
            require(hash(raw(f,"runtime-before.json")).equals(reads.path("before").path("runtimeSha256").asText())
                &&reads.path("before").path("runtimeSha256").equals(reads.path("after").path("runtimeSha256")));
            require(java.time.Instant.parse(reads.path("before").path("recordedAt").asText()).isBefore(java.time.Instant.parse(reads.path("after").path("recordedAt").asText())));
            require(hash(raw(f,"native-classpath-before.json")).equals(reads.path("before").path("nativeClasspathSha256").asText())&&reads.path("before").path("nativeClasspathSha256").equals(reads.path("after").path("nativeClasspathSha256")));
            for(String kind:List.of("authn-properties","global","relying-party","password-validator","custom-flow-inventory","parent-authn.properties","condition-base","condition-locked","condition-expired","condition-expiring")){
                byte[] before=raw(f,"before-"+kind);require(Arrays.equals(before,raw(f,"after-"+kind))
                    &&hash(before).equals(reads.path("before").path("configSha256").path(kind).asText())
                    &&reads.path("before").path("configSha256").path(kind).equals(reads.path("after").path("configSha256").path(kind)));
                if(List.of("authn-properties","global","relying-party").contains(kind)){
                    var row=new ArrayList<JsonNode>();ae.path("configurationFiles").forEach(x->{if(kind.equals(x.path("kind").asText()))row.add(x);});require(row.size()==1);
                    require(Arrays.equals(before,checked(aeFolder,row.getFirst(),"originalFile","originalSha256")));
                }
            }
            var properties=new Properties();properties.load(new java.io.ByteArrayInputStream(raw(f,"before-parent-authn.properties")));require(properties.size()==1&&"Password".equals(properties.getProperty("idp.authn.flows")));
            var allowed=Set.of("/opt/shibboleth-idp/flows/authn/conditions/conditions-flow.xml","/opt/shibboleth-idp/flows/authn/conditions/account-locked/account-locked-flow.xml","/opt/shibboleth-idp/flows/authn/conditions/expired-password/expired-password-flow.xml","/opt/shibboleth-idp/flows/authn/conditions/expiring-password/expiring-password-flow.xml");
            var inventory=new String(raw(f,"before-custom-flow-inventory"),java.nio.charset.StandardCharsets.UTF_8).lines().toList();require(inventory.size()==4&&new HashSet<>(inventory).equals(allowed));
            for(String kind:List.of("condition-base","condition-locked","condition-expired","condition-expiring")){
                var rowsForKind=new ArrayList<JsonNode>();ae.path("configurationFiles").forEach(x->{if(kind.equals(x.path("kind").asText()))rowsForKind.add(x);});require(rowsForKind.size()==1);
                require(Arrays.equals(raw(f,"before-"+kind),checked(aeFolder,rowsForKind.getFirst(),"packagedOriginalFile","packagedOriginalSha256")));
            }
            var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",SCHEMA);details.put("run_id",context.runId());
            details.put("scope","instrumented-selected-stock-password-boundary-capability");details.put("approved_mode","ATTESTED");details.put("attested",false);
            details.put("true_live_password_ui_execution",false);details.put("true_live_no_passive_retained",true);
            details.put("same_native_context_object",true);details.put("native_instrumented_mutants",mutants);details.put("native_configuration_unchanged",true);
            var refs=new ArrayList<>(baseline.evidence());refs.add(new EvidenceRef(KIND,context.runId()+".shibboleth-force-authn-mechanism.json#"+hash(manifestRaw)));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,REASON,REASON,List.copyOf(refs),Map.copyOf(details)));
        }catch(Exception unavailable){return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_mechanism_reachability_unproven","idp.force-authn.mechanism-reachability.unproven","idp.force-authn.mechanism-reachability.unproven",List.of(),Map.of("evidence_adapter",SCHEMA,"stage",stage)));}
    }
    static Optional<CaseOutcome> guardNativeClasspath(byte[] original){
        try{if(NATIVE_CLASSPATH_SHA256.equals(hash(original)))return Optional.empty();}catch(Exception unavailable){/* Same fail-closed outcome. */}
        return Optional.of(new CaseOutcome(Outcome.NOT_VERIFIED,"native_mechanism_reachability_unproven","idp.force-authn.mechanism-reachability.unproven","idp.force-authn.mechanism-reachability.unproven",List.of(),Map.of("evidence_adapter",SCHEMA,"stage","native-whole-classpath-unproven")));
    }
    private static void check(JsonNode row,byte[] raw,org.w3c.dom.Element request,boolean force,boolean passive,String mutant,boolean reachable)throws Exception{
        require(row.path("mutation").asText().equals(mutant)&&hash(raw).equals(row.path("inputSha256").asText())&&request.getAttribute("ID").equals(row.path("requestId").asText()));
        require(row.path("inputForceAuthn").isBoolean()&&row.path("inputForceAuthn").asBoolean()==force&&row.path("inputIsPassive").isBoolean()&&row.path("inputIsPassive").asBoolean()==passive);
        var issuers=request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","Issuer");require(issuers.getLength()==1&&issuers.item(0).getTextContent().equals(row.path("issuer").asText()));
        require(row.path("indicatorReachable").isBoolean()&&row.path("indicatorReachable").asBoolean()==reachable);
        if(reachable)require(row.path("nativeInitializerForceAuthn").isBoolean()&&row.path("nativeInitializerForceAuthn").asBoolean()==force&&row.path("sameNativeContextObject").asBoolean()&&row.path("mechanismContextExists").asBoolean()&&row.path("mechanismForceAuthn").isBoolean()&&row.path("mechanismForceAuthn").asBoolean()==force);
        require(row.path("sameNativeContextObject").isBoolean()&&row.path("mechanismContextExists").isBoolean()&&row.path("nativeInitializerForceAuthn").isBoolean());
        if(!reachable) require(!row.path("sameNativeContextObject").asBoolean()||!row.path("mechanismContextExists").asBoolean()||!row.path("mechanismForceAuthn").asBoolean());
    }
    private static byte[] checked(Path f,JsonNode row,String file,String digest)throws Exception{byte[] raw=raw(f,row.path(file).asText());require(hash(raw).equals(row.path(digest).asText()));return raw;}
    private static byte[] raw(Path f,String name)throws Exception{return safeFile(f,name);}
    private static byte[] safeFile(Path f,String name)throws Exception{
        require(name!=null&&name.matches("[A-Za-z0-9_.-]+")&&!name.equals(".")&&!name.equals("..")&&!Files.isSymbolicLink(f));
        var path=f.resolve(name);require(Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)&&Files.size(path)<67108864);return Files.readAllBytes(path);
    }
    private static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private static void require(boolean condition){if(!condition)throw new IllegalArgumentException("Unproven native mechanism evidence");}
}
