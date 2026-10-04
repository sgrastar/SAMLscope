package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.*;
import java.util.*;
import org.w3c.dom.Element;
import static com.samlscope.runner.cases.DefaultAlgorithmPreventionEvidence.*;

/** Stock POST AuthnRequest processing under the unchanged, undeclared native default policy. */
public final class SimpleSamlPhpDefaultAlgorithmNativeAdapter implements DefaultAlgorithmNativeAdapter {
    public static final String ADAPTER="simplesamlphp-native-default-algorithm-post-consumer-v1";
    public static final String SCOPE="samlscope-ssp-default-algorithm-scope-v1",USE="samlscope-ssp-default-algorithm-use-v1";
    static final String PARSER_SOURCE_SHA="668c0477e07ddd352698c13bd2cb32c2fd19301cf7eee8940e78429387d20e98";
    static final String SCOPE_SOURCE_SHA="904a51a4cf9c1acb79f16cb515c93f7be8e963b71ea8c64a8e20bb4f490835d9";
    static final String DIAGNOSTIC_SOURCE_SHA="1828e33f43095963714934cbb58a19f384ecea0ce28966d0940d69907017ae6c";
    static final String TARGET="http://localhost:18380/idp",CONSUMER="ssp-stock-post-AuthnRequest-Message.validateMessage";
    static final Map<String,String> SOURCES=Map.ofEntries(
        Map.entry("native-idp.php","ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d"),
        Map.entry("native-message.php","ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2"),
        Map.entry("native-legacy-message.php","42334f0f2d0590a82371552bccea01ffc5bb73cc8fe3849a190d62f0809d481e"),
        Map.entry("native-utils.php","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d"),
        Map.entry("native-dsig.php","79597160c501fbdbe19bdca12b6797c06c38c4eae7cad6d0d1dca89301a5734f"),
        Map.entry("native-key.php","6c89ac116aca2c05791712749450be474218fd97cd9a66b7aad9d2ba4e6cba17"),
        Map.entry("native-parser.php","8620bb26fd41d2be29d2611883839a4cfde0b6c8458c274e2d40a002678fd93d"),
        Map.entry("native-handler.php","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040"));
    private final TranscriptContentReader content;private final Path data;
    public SimpleSamlPhpDefaultAlgorithmNativeAdapter(TranscriptContentReader content,Path dataDirectory) {
        this.content=Objects.requireNonNull(content);data=Objects.requireNonNull(dataDirectory).toAbsolutePath().normalize();
    }
    @Override public String adapter(){return ADAPTER;}
    @Override public Optional<Preparation> prepare(CaseContext c,Path folder,JsonNode m,byte[] target,byte[] suite)throws Exception {
        validateFactory(c,folder,m,suite);var state=record(c,m,"before",SCOPE);validateScope(folder,state,"configured",c.runId(),suite);
        return Optional.of(new Preparation(policy(state),false,List.of(reference(m,"before"))));
    }
    @Override public Session open(CaseContext c,Path folder,JsonNode m,byte[] target,byte[] suite)throws Exception {
        validateFactory(c,folder,m,suite);var before=record(c,m,"before",SCOPE);
        var after=record(c,m,"after",SCOPE);var restored=record(c,m,"restored",SCOPE);
        validateScope(folder,before,"configured",c.runId(),suite);validateScope(folder,after,"configured",c.runId(),suite);
        validateScope(folder,restored,"restored",c.runId(),suite);
        require(before.path("runtime").equals(after.path("runtime"))&&before.path("runtime").equals(restored.path("runtime"))
                &&before.path("sourceHashes").equals(after.path("sourceHashes"))&&before.path("sourceHashes").equals(restored.path("sourceHashes"))
                &&before.path("defaultPolicy").equals(after.path("defaultPolicy"))&&before.path("defaultPolicy").equals(restored.path("defaultPolicy"))
                &&before.path("peer").equals(after.path("peer"))&&policy(before).equals(policy(after))&&policy(before).equals(policy(restored)));
        require(Arrays.equals(original(folder,"original-configuration.php"),original(folder,"final-configuration.php"))
                &&hash(original(folder,"original-configuration.php")).equals(text(restored,"remoteConfigurationSha256")));
        var restoration=json(original(folder,"restoration.json"));require(restoration.path("restored").isBoolean()&&restoration.path("restored").booleanValue()
                &&hash(original(folder,"final-configuration.php")).equals(text(restoration,"finalSha256"))
                &&hash(original(folder,"original-configuration.php")).equals(text(restoration,"originalSha256")));
        Instant start=instant(before,"finishedAt"),end=instant(after,"startedAt");require(!end.isBefore(start));
        String entity=SecureXml.parse(suite).getDocumentElement().getAttribute("entityID");
        var evidence=List.of(reference(m,"before"),reference(m,"after"),reference(m,"restored"));
        return (observation,fixture,input,inputBytes,response,name,indexes)-> {
            require(!fixture.endsWith("encrypted-id")&&!fixture.equals("oaep-encrypted-id-control"));
            var use=record(c,observation,"native",USE);require(fixture.equals(text(use,"fixtureId"))&&input.getAttribute("ID").equals(text(use,"requestId"))
                    &&hash(inputBytes).equals(text(use,"requestSha256"))&&observation.path("requestReference").equals(use.path("requestReference"))
                    &&policy(before).equals(text(use,"policyId"))&&CONSUMER.equals(text(use,"consumerId")));
            var http=use.path("nativeHttp");require("POST".equals(text(http,"method"))&&input.getAttribute("Destination").equals(text(http,"requestUrl"))
                    &&text(http,"requestUrl").equals(text(http,"responseUrl"))&&input.getAttribute("ID").equals(text(http,"requestId"))
                    &&hash(inputBytes).equals(text(http,"requestSha256"))&&!instant(http,"startedAt").isBefore(start)
                    &&!instant(http,"finishedAt").isBefore(instant(http,"startedAt"))&&!instant(http,"finishedAt").isAfter(end));
            var diagnostic=json(original(folder,text(use,"diagnosticFile")));require(hash(original(folder,text(use,"diagnosticFile"))).equals(text(use,"diagnosticSha256"))
                    &&c.runId().equals(text(diagnostic,"runId"))&&hash(suite).equals(text(diagnostic,"metadataSha256")));
            var rows=diagnostic.path("rows");require(rows.isArray()&&rows.size()==1);var row=rows.get(0);
            require(hash(inputBytes).equals(text(row,"inputSha256"))&&input.getAttribute("ID").equals(text(row,"requestId"))&&entity.equals(text(row,"issuer")));
            validateDiagnostic(diagnostic,before);
            var invocation=json(original(folder,text(use,"diagnosticInvocationFile")));
            require(hash(original(folder,text(use,"diagnosticInvocationFile"))).equals(text(use,"diagnosticInvocationSha256"))
                    &&invocation.path("exitCode").isInt()&&invocation.path("exitCode").intValue()==0
                    &&hash(original(folder,text(use,"diagnosticFile"))).equals(text(invocation,"stdoutSha256"))
                    &&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".equals(text(invocation,"stderrSha256"))
                    &&hash(original(folder,"native-diagnostic-command.php")).equals(text(invocation,"sourceSha256"))
                    &&DIAGNOSTIC_SOURCE_SHA.equals(text(invocation,"sourceSha256")));
            var diagnosticInput=original(folder,text(invocation,"inputFile"));require(hash(diagnosticInput).equals(text(invocation,"stdinSha256")));
            var inputRecord=json(diagnosticInput);require(c.runId().equals(text(inputRecord,"runId"))
                    &&inputRecord.path("planId").equals(diagnostic.path("planId"))
                    &&Arrays.equals(suite,Base64.getDecoder().decode(text(inputRecord,"metadata")))
                    &&inputRecord.path("inputs").isObject()&&inputRecord.path("inputs").size()==1);
            require(Arrays.equals(inputBytes,Base64.getDecoder().decode(text(inputRecord.path("inputs"),fixture.replace('-','_')))));
            require(!instant(invocation,"startedAt").isBefore(start)&&!instant(invocation,"finishedAt").isBefore(instant(invocation,"startedAt"))
                    &&!instant(invocation,"finishedAt").isAfter(instant(http,"startedAt")));
            Decision decision;
            if(response!=null&&SUCCESS.equals(status(response))) {
                require(http.path("responseStatus").isInt()&&http.path("responseStatus").intValue()==200
                        &&observation.hasNonNull("responseReference")&&observation.path("responseReference").equals(use.path("responseReference")));
                var entry=c.transcript().list(c.runId()).stream().filter(e->text(use,"responseReference").equals(e.id())).toList();require(entry.size()==1);
                require(hash(content.readDecodedSaml(entry.getFirst())).equals(text(http,"responseSamlSha256")));
                decision=successfulSignatureDecision(fixture,row);
            }else {
                require(response==null&&http.path("responseStatus").isInt()&&http.path("responseStatus").intValue()==500
                        &&row.path("constructedSignature").isBoolean()&&row.path("constructedSignature").booleanValue()
                        &&"REJECTED".equals(text(row,"nativeSignatureGate")));
                var body=original(folder,text(http,"responseBodyFile"));require(hash(body).equals(text(http,"responseBodySha256"))
                        &&http.path("responseBodyBytes").canConvertToInt()&&body.length==http.path("responseBodyBytes").intValue()
                        &&SimpleSamlPhpRegisteredSignerEvidence.nativeSignatureRejection(new String(body,java.nio.charset.StandardCharsets.UTF_8),entity));
                require(fixture.equals("invalid-sha256-signature")||fixture.equals("rsa-md5"));
                decision=fixture.equals("invalid-sha256-signature")?Decision.INVALID_SIGNATURE_REJECTION:Decision.ALGORITHM_REJECTION;
            }
            var refs=new ArrayList<>(evidence);refs.add(reference(observation,"native"));return new Use(policy(before),CONSUMER,decision,refs);
        };
    }
    /** A correlated SSO response does not prove use of an ignored optional signature. */
    static Decision successfulSignatureDecision(String fixture,JsonNode row) {
        require(row.path("constructedSignature").isBoolean());
        String gate=text(row,"nativeSignatureGate");
        if(!row.path("constructedSignature").booleanValue()||"SKIPPED".equals(gate))return Decision.UNPROVEN;
        require("sha256-control".equals(fixture)&&"VALIDATED".equals(gate));
        return Decision.CONSUMED_SUCCESS;
    }
    private void validateFactory(CaseContext c,Path folder,JsonNode m,byte[] suite)throws Exception {
        require(PARSER_SOURCE_SHA.equals(hash(original(folder,"native-parser-command.php")))
                &&SCOPE_SOURCE_SHA.equals(hash(original(folder,"native-scope-command.php"))));
        var matches=c.transcript().list(c.runId()).stream().filter(e->text(m,"suiteMetadataReference").equals(e.id())).toList();require(matches.size()==1);
        var entry=matches.get(0);var summary=entry.samlSummary();require("native-default-consumer".equals(summary.get("feed"))
                &&"MetadataService.generateDefaultAlgorithmConsumerMetadata".equals(summary.get("factoryMethod"))
                &&entry.timestamp().equals(Instant.parse((String)summary.get("factoryPreparedAt"))));
        require(hash(original(folder,"metadata-service-source.java")).equals(summary.get("factorySourceSha256"))
                &&classHash(MetadataService.class).equals(summary.get("factoryClassSha256"))
                &&hash(Files.readAllBytes(Path.of(MetadataService.class.getProtectionDomain().getCodeSource().getLocation().toURI()))).equals(summary.get("factoryJarSha256")));
        var bridge=new KeycloakNativeRunEvidenceBridge(data);var key=bridge.key(c.runId(),"control").orElseThrow();TestPlan plan;
        try(var db=DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
                var q=db.prepareStatement("SELECT p.document_json FROM runs r JOIN plans p ON r.plan_id=p.id WHERE r.id=?")) {
            q.setString(1,c.runId());try(var rows=q.executeQuery()){require(rows.next());plan=new JsonCodec().read(rows.getString(1),TestPlan.class);require(!rows.next());}
        }
        require("browser_sso_idp".equals(plan.profile().id())&&TARGET.equals(plan.target().entityId()));
        var service=new MetadataService(URI.create("http://localhost:18080"),null,new XmlSigner(),Clock.fixed(entry.timestamp(),ZoneOffset.UTC));
        require(Arrays.equals(suite,service.generateDefaultAlgorithmConsumerMetadata(plan,c.runId(),key)));
        var role=single(SecureXml.parse(suite).getDocumentElement(),MD,"SPSSODescriptor");require(!role.hasAttribute("AuthnRequestsSigned"));
        var parsed=json(original(folder,"native-parser-output.json"));
        require(hash(suite).equals(text(parsed,"fixtureSha256"))
                &&SecureXml.parse(suite).getDocumentElement().getAttribute("entityID").equals(text(parsed,"entityId")));
        var invocation=json(original(folder,"native-parser-invocation.json"));
        require(invocation.path("exitCode").isInt()&&invocation.path("exitCode").intValue()==0
                &&PARSER_SOURCE_SHA.equals(text(invocation,"sourceSha256"))&&hash(suite).equals(text(invocation,"stdinSha256"))
                &&hash(original(folder,"native-parser-output.json")).equals(text(invocation,"stdoutSha256"))
                &&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".equals(text(invocation,"stderrSha256")));
    }
    private JsonNode record(CaseContext c,JsonNode m,String prefix,String schema)throws Exception {
        String id=text(m,prefix+"Reference");var rows=c.transcript().list(c.runId()).stream().filter(e->id.equals(e.id())).toList();require(rows.size()==1);
        var entry=rows.get(0);require(c.runId().equals(entry.runId())&&entry.direction()==Direction.INBOUND
                &&("transcripts/"+c.runId()+"/"+id+".saml.xml").equals(entry.decodedSamlRef()));
        var raw=content.readDecodedSaml(entry);require(hash(raw).equals(text(m,prefix+"Sha256")));var n=json(raw);
        require(schema.equals(text(n,"schema"))&&c.runId().equals(text(n,"runId"))&&ADAPTER.equals(text(n,"adapter"))
                &&Boolean.FALSE.equals(n.path("counterfactualCalibrationOnly").booleanValue())&&n.path("counterfactualCalibrationOnly").isBoolean());return n;
    }
    private static EvidenceRef reference(JsonNode m,String prefix){return new EvidenceRef("transcript",text(m,prefix+"Reference"));}
    static void validateScope(Path folder,JsonNode n,String phase,String run,byte[] suite)throws Exception {
        require(SCOPE.equals(text(n,"schema"))&&run.equals(text(n,"runId"))&&phase.equals(text(n,"phase"))
                &&!instant(n,"finishedAt").isBefore(instant(n,"startedAt"))&&n.path("runtime").path("running").isBoolean()
                &&n.path("runtime").path("running").booleanValue()&&text(n.path("runtime"),"id").matches("[0-9a-f]{64}")
                &&text(n.path("runtime"),"image").matches("sha256:[0-9a-f]{64}")&&n.path("runtime").path("mounts").isArray()
                &&!text(n.path("runtime"),"startedAt").isBlank());
        validateDefaultPolicy(n.path("defaultPolicy"));
        require(n.path("metadataSources").equals(json("[{\"type\":\"flatfile\"}]".getBytes())));
        for(var source:SOURCES.entrySet())require(source.getValue().equals(text(n.path("sourceHashes"),source.getKey()))
                &&source.getValue().equals(hash(original(folder,"native-source/"+source.getKey()))));
        var peer=n.path("peer");require(peer.isObject()&&peer.path("present").isBoolean());
        if(phase.equals("configured")) {
            require(peer.path("present").booleanValue()&&hash(suite).equals(text(n,"registeredMetadataSha256"))
                    &&hash(original(folder,"configured-configuration.php")).equals(text(n,"remoteConfigurationSha256"))
                    &&peer.has("validateAuthnRequest")&&peer.path("validateAuthnRequest").isNull()
                    &&peer.has("redirectValidate")&&peer.path("redirectValidate").isNull());
            var parsed=json(original(folder,"native-parser-output.json"));require(parsed.path("metadata").equals(peer.path("resolvedMetadata"))
                    &&!parsed.path("metadata").has("validate.authnrequest")&&!parsed.path("metadata").has("redirect.validate"));
            byte[] expected=original(folder,"original-configuration.php"),overlay=text(parsed,"php").getBytes(java.nio.charset.StandardCharsets.UTF_8);
            var combined=new java.io.ByteArrayOutputStream();combined.write(expected);combined.write('\n');combined.write(overlay);combined.write('\n');
            require(Arrays.equals(combined.toByteArray(),original(folder,"configured-configuration.php")));
        }else require(!peer.path("present").booleanValue());
    }
    static void validateDiagnostic(JsonNode n,JsonNode scope) {
        require("samlscope-ssp-default-consumer-native-api-diagnostic-v1".equals(text(n,"schema"))
                &&n.path("nativeParserValidateAuthnRequest").isNull()&&n.has("nativeParserValidateAuthnRequest")
                &&n.path("hostedValidateAuthnRequest").isNull()&&n.has("hostedValidateAuthnRequest")
                &&n.path("nativeParserRedirectValidate").isNull()&&n.has("nativeParserRedirectValidate")
                &&n.path("hostedRedirectValidate").isNull()&&n.has("hostedRedirectValidate")
                &&n.path("configurationWrites").asInt(-1)==0&&n.path("targetHttp").asInt(-1)==0
                &&n.path("actualProductFinding").isBoolean()&&!n.path("actualProductFinding").booleanValue()
                &&n.path("actualMd5CryptoVerificationClaimed").isBoolean()&&!n.path("actualMd5CryptoVerificationClaimed").booleanValue());
        require(n.path("classes").isArray()&&n.path("classes").size()==6);var observed=new HashMap<String,String>();for(var row:n.path("classes"))require(observed.put(text(row,"class"),text(row,"sha256"))==null);
        for(var binding:Map.of("SimpleSAML\\Metadata\\SAMLParser","native-parser.php","SimpleSAML\\Module\\saml\\Message","native-message.php",
                "SAML2\\Message","native-legacy-message.php","SAML2\\Utils","native-utils.php",
                "RobRichards\\XMLSecLibs\\XMLSecurityDSig","native-dsig.php","RobRichards\\XMLSecLibs\\XMLSecurityKey","native-key.php").entrySet())
            require(SOURCES.get(binding.getValue()).equals(observed.get(binding.getKey())));
    }
    static void validateDefaultPolicy(JsonNode policy) {
        require(policy.isObject());
        for(String key:List.of("hostedValidateAuthnRequest","hostedRedirectValidate"))require(policy.has(key)&&policy.path(key).isNull());
        for(String key:List.of("globalConfigurationSha256","hostedConfigurationSha256","authenticationConfigurationSha256"))
            require(text(policy,key).matches("[0-9a-f]{64}"));
        for(String key:List.of("autoPrependFile","autoAppendFile","opcachePreload"))
            require(policy.path(key).isTextual()&&policy.path(key).textValue().isEmpty());
    }
    private static String policy(JsonNode state)throws Exception {
        return "ssp-native-default:"+hash(new JsonCodec().mapper().writeValueAsBytes(Map.of("sourceHashes",state.path("sourceHashes"),"defaultPolicy",state.path("defaultPolicy"))));
    }
    private static String classHash(Class<?> c)throws Exception {try(var input=c.getResourceAsStream("/"+c.getName().replace('.','/')+".class")){require(input!=null);return hash(input.readAllBytes());}}
    private static Instant instant(JsonNode n,String key){return Instant.parse(text(n,key));}
}
