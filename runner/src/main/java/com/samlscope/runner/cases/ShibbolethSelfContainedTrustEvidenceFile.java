package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.function.*;
import java.util.zip.ZipInputStream;
import org.w3c.dom.Element;

/** Same-Run metadata role-key SIG/ENC sufficiency. No TLS or global trust-store claim. */
public final class ShibbolethSelfContainedTrustEvidenceFile {
    public static final String ID="IIP-MD06-c-idp-01", ADAPTER="shibboleth-native-self-contained-trust-v1";
    static final String SCHEMA="samlscope-shibboleth-self-contained-trust-v2";
    static final String PRODUCER="a2e49b1980fa80b576db0156ddb0a91fe2b44d7dcdb5793f77e75f78f00cdc0a";
    static final String KIND="native-self-contained-trust-evidence";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata",S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String PROFILE="http://shibboleth.net/ns/profiles/saml2/sso/browser",ENGINE="shibboleth.ExplicitKeySignatureTrustEngine";
    private static final Map<String,String> JARS=Map.of("idp-conf-impl","428e389d88bb2abcad19d69bcf759af29f7ce6beb776ccfaa5a6ea76751682ba","idp-saml-impl","1a2a9f867d11c50eeaf2a6140bb5de88b0611d694ea6de2bbfe32f72a4a2998b","opensaml-saml-impl","9f04221e172dc426f90fb3873d0148a0744edbf9e7a37de7ee0e6a34f7b74581","opensaml-xmlsec-impl","cc67fc1bd9cb435cdbe7483ef04513c83cc9619a3015c04ad41bb6cc0eb6e68e");
    private static final Map<String,String> CONFIGS=Map.of("global","ca08485a1b5ef8cf0ac1afb80ff066237759e4fb3d884d087f905d8ca0918bcc","services","0c5de788ebc611af60ebb3bf4071dcd23744f599d64d65bdb0744515d11a77c0","relying-party","64e2a04dfbf2ffa2a582b995bcbf121b634ab7c8766cb8f22d3397d541f31bd5");
    private final Path directory,roleDirectory;private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final boolean offlineCalibrationAllowed;
    public ShibbolethSelfContainedTrustEvidenceFile(Path directory,Path roleDirectory,TranscriptContentReader content,Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys){this(directory,roleDirectory,content,metadata,keys,false);}
    /** Explicit developer permission; receipt labels cannot enable diagnostic product findings. */
    ShibbolethSelfContainedTrustEvidenceFile(Path directory,Path roleDirectory,TranscriptContentReader content,Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,boolean permission){
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();this.roleDirectory=Objects.requireNonNull(roleDirectory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);this.offlineCalibrationAllowed=permission;
    }
    public boolean exists(String run){return validRun(run)&&(Files.exists(directory.resolve(run+".shibboleth-trust.json"),LinkOption.NOFOLLOW_LINKS)||Files.exists(directory.resolve(run+".shibboleth-trust"),LinkOption.NOFOLLOW_LINKS));}
    public CaseOutcome evaluate(CaseContext context){try{return proof(context);}catch(Exception unavailable){return pending();}}
    private CaseOutcome proof(CaseContext context)throws Exception {
        String run=context.runId();require(validRun(run)&&context.transcriptComplete()&&exists(run));
        byte[] receipt=original(directory,run+".shibboleth-trust.json");var m=json(receipt);Path folder=directory.resolve(run+".shibboleth-trust");
        require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&ID.equals(text(m,"caseId"))&&run.equals(text(m,"runId"))&&"native-metadata-trust".equals(text(m,"campaignId")));
        boolean calibration=validateSelectedPath(m,offlineCalibrationAllowed);
        var role=roleDirectory.resolve(run);byte[] roleRaw=original(role,"manifest.json");var roles=json(roleRaw);
        require(hash(roleRaw).equals(text(m,"roleReceiptSha256"))&&run.equals(text(roles,"runId"))&&MetadataRoleKeyEvidence.SCHEMA.equals(text(roles,"schema"))&&MetadataRoleKeyEvidence.ADAPTER.equals(text(roles,"adapter")));
        var targetRaw=metadata.apply(run);var target=SecureXml.parse(targetRaw).getDocumentElement();
        require(hash(targetRaw).equals(text(m,"targetMetadataSha256"))&&text(m,"targetMetadataSha256").equals(text(roles,"targetMetadataSha256"))&&target.getAttribute("entityID").equals(text(m,"targetEntityId"))&&text(roles,"entityId").equals(text(m,"peerEntityId")));
        // The existing role contract verifies all four epochs, eleven controls, native rejections and exact restoration.
        var common=new MetadataRoleKeyEvidence(roleDirectory,content,metadata,keys).evaluate(context).orElseThrow();require(common.outcome()==Outcome.SATISFIED);
        var inputRaw=bound(folder,m,"input");var input=json(inputRaw);var outputRaw=bound(folder,m,"nativeOutput");var output=json(outputRaw);
        require(PRODUCER.equals(hash(bound(folder,m,"producer")))&&PRODUCER.equals(text(output,"producerSha256"))&&hash(inputRaw).equals(text(output,"inputSha256")));
        var stockInputRaw=bound(folder,m,"stockInput");var stockOutputRaw=bound(folder,m,"stockOutput");var stockInput=json(stockInputRaw);var stockOutput=json(stockOutputRaw);
        require("samlscope-shibboleth-self-contained-trust-input-v2".equals(text(stockInput,"schema"))&&run.equals(text(stockInput,"runId"))&&stockInput.path("records").equals(input.path("records"))&&"stock-native-signature-encryption".equals(text(stockInput,"selectedPath")));
        require(Arrays.equals(inputRaw,calibration?bound(folder,m,"calibrationInput"):stockInputRaw)&&Arrays.equals(outputRaw,calibration?bound(folder,m,"calibrationOutput"):stockOutputRaw));
        String selectedPath=calibration?"developer-instrumented-additional-anchor":"stock-native-signature-encryption";
        validateDiagnostic(stockOutput,run);validateOutputMode(stockOutput,"stock-native-signature-encryption");validateDiagnostic(output,run);validateOutputMode(output,selectedPath);
        require(hash(stockInputRaw).equals(text(stockOutput,"inputSha256"))&&PRODUCER.equals(text(stockOutput,"producerSha256"))&&selectedPath.equals(text(input,"selectedPath")));
        var costs=json(bound(folder,m,"operations"));validateCosts(costs);var historical=json(original(role,"trust-runtime-final.json"));validateRuntimeEpoch(role);
        validateInvocation(costs,hash(stockInputRaw),hash(stockOutputRaw),historical,"stock-native-signature-encryption");if(calibration)validateInvocation(costs,hash(inputRaw),hash(outputRaw),historical,selectedPath);
        var before=bound(folder,m,"nativeJarBefore");require(Arrays.equals(before,bound(folder,m,"nativeJarAfter")));var inventory=new LinkedHashMap<String,String>();
        for(String line:new String(before,java.nio.charset.StandardCharsets.UTF_8).strip().split("\n")){var pair=line.strip().split("\\s+",2);require(pair.length==2&&pair[0].matches("[a-f0-9]{64}")&&inventory.put(pair[1],pair[0])==null);}require(inventory.size()==3);
        var classpath=json(original(role,"trust-"+MetadataRoleKeyProbeTestCase.VARIANTS.getFirst()+"-before-classpath-sha256.json"));
        for(var e:inventory.entrySet())require(e.getKey().matches("/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-(saml|xmlsec|security)-impl-5\\.2\\.3\\.jar")&&e.getValue().equals(text(classpath,e.getKey())));
        byte[] securityJar=bound(folder,m,"nativeSecurityJar");require(hash(securityJar).equals(inventory.get("/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-security-impl-5.2.3.jar")));validateClassBytes(stockOutput,role,securityJar);validateClassBytes(output,role,securityJar);
        require("samlscope-shibboleth-self-contained-trust-input-v2".equals(text(input,"schema"))&&run.equals(text(input,"runId"))&&input.path("records").isArray()&&input.path("records").size()==4);
        validateNativeBindings(role);var by=history(context,run);int encryptedNormals=0;var seen=new HashSet<String>();
        for(var epoch:roles.path("observations")){
            String variant=text(epoch,"variant");require(seen.add(variant));var normalRows=new ArrayList<JsonNode>();for(var e:epoch.path("exchanges"))if(text(e,"fixtureId").endsWith("-normal"))normalRows.add(e);require(normalRows.size()==1);var normal=normalRows.getFirst();String fixtureId=text(normal,"fixtureId");
            validateTrustScope(role,epoch,text(roles,"entityId"));var in=record(input,fixtureId);var nativeProof=record(output,fixtureId);var stock=record(stockOutput,fixtureId);
            byte[] fixture=original(role,variant+"-fixture.xml");var peer=SecureXml.parse(fixture).getDocumentElement();var request=by.get(text(normal,"requestReference"));byte[] requestRaw=decoded(request);var requestXml=SecureXml.parse(requestRaw).getDocumentElement();
            require(Arrays.equals(fixture,Base64.getDecoder().decode(text(in,"metadataBase64")))&&Arrays.equals(requestRaw,Base64.getDecoder().decode(text(in,"requestBase64"))));
            for(var row:List.of(in,nativeProof,stock))require(variant.equals(text(row,"variant"))&&text(roles,"entityId").equals(text(row,"peerEntityId"))&&request.id().equals(text(row,"requestReference"))&&requestXml.getAttribute("ID").equals(text(row,"requestId"))&&hash(fixture).equals(text(row,"metadataSha256"))&&hash(requestRaw).equals(text(row,"requestSha256")));
            boolean flipped=variant.contains("idp-first"),explicit=variant.contains("explicit");var signing=keys.apply(run,flipped?"three-signing-keys-second":"three-signing-keys-first").orElseThrow();var receiver=keys.apply(run,explicit?"three-signing-keys":flipped?"three-signing-keys-second":"three-signing-keys-first").orElseThrow();var other=keys.apply(run,flipped?"three-signing-keys-first":"three-signing-keys-second").orElseThrow();
            for(var row:List.of(nativeProof,stock))require(hash(signing.certificate().getPublicKey().getEncoded()).equals(text(row,"metadataSigningPublicKeySha256"))&&hash(receiver.certificate().getPublicKey().getEncoded()).equals(text(row,"metadataEncryptionPublicKeySha256")));
            if(calibration)validateNativeControl(nativeProof);var response=by.get(text(normal,"responseReference"));var rspXml=SecureXml.parse(decoded(response)).getDocumentElement();var encrypted=children(rspXml,S,"EncryptedAssertion");require(encrypted.size()==1&&children(rspXml,S,"Assertion").isEmpty());
            VerifiedResponseAssertion.read(rspXml,target.getAttribute("entityID"),MetadataAlgorithmEvidence.signingKeys(target),peer,Optional.of(receiver),requestXml.getAttribute("ID"),requestXml.getAttribute("AssertionConsumerServiceURL"));boolean wrongKeyFailed=false;try{new SamlXmlDecrypter().decrypt(encrypted.getFirst(),other.privateKey());}catch(Exception wrongKey){wrongKeyFailed=true;}require(wrongKeyFailed);encryptedNormals++;
        }
        require(seen.equals(Set.copyOf(MetadataRoleKeyProbeTestCase.VARIANTS))&&encryptedNormals==4&&Arrays.equals(receipt,original(directory,run+".shibboleth-trust.json")));
        var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",ADAPTER);details.put("run_id",run);details.put("counterfactual_calibration_only",calibration);details.put("signature_verification_observed",true);details.put("metadata_key_encryption_decryption_observed",true);details.put("wrong_peer_decryption_rejected",true);details.put("additional_trust_input_required",calibration);details.put("proof_scope",calibration?"developer-instrumented-additional-anchor-fixture":"recorded-native-signature-encryption-flow");details.put("native_originals_verified",true);details.put("restoration_verified",true);details.put("mutant_controls_adopted",false);details.put("private_key_exported",false);details.put("plaintext_persisted",false);details.put("encrypted_response_count",encryptedNormals);details.put("receipt_sha256",hash(receipt));details.put("role_receipt_sha256",hash(roleRaw));details.put("native_diagnostic_sha256",hash(outputRaw));
        var refs=new ArrayList<>(common.evidence());refs.add(new EvidenceRef(KIND,run+".shibboleth-trust.json#"+hash(receipt)));String reason=calibration?"metadata.trust.additional-anchor-required":"metadata.trust.self-contained-native-observed";
        return new CaseOutcome(calibration?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,List.copyOf(refs),Map.copyOf(details));
    }
    private static JsonNode record(JsonNode n,String fixture){var rows=new ArrayList<JsonNode>();for(var r:n.path("records"))if(fixture.equals(r.path("fixtureId").asText()))rows.add(r);require(rows.size()==1);return rows.getFirst();}
    static void validateScopeWindow(JsonNode scope,JsonNode epoch,String phase){var exchanges=epoch.path("exchanges");require(exchanges.isArray()&&!exchanges.isEmpty());Instant start=Instant.parse(text(epoch,"startedAt")),end=Instant.parse(text(epoch,"completedAt")),observed=Instant.parse(text(scope,"recordedAt"));require(!observed.isBefore(start)&&!observed.isAfter(end));Instant boundary=Instant.parse(text(exchanges.get(phase.equals("before")?0:exchanges.size()-1).path("nativeHttp").get(0),phase.equals("before")?"startedAt":"completedAt"));require(phase.equals("before")?!observed.isAfter(boundary):!observed.isBefore(boundary));}
    private static void validateTrustScope(Path role,JsonNode epoch,String entity)throws Exception{
        String variant=text(epoch,"variant");for(var pin:JARS.entrySet())require(pin.getValue().equals(hash(original(role,"native-"+pin.getKey()+".jar"))));
        for(String phase:List.of("before","after")){String prefix="trust-"+variant+"-"+phase+"-";var observed=json(original(role,prefix+"observed.json"));require(entity.equals(text(observed,"entityId"))&&PROFILE.equals(text(observed,"profileId"))&&observed.path("privateFieldsExported").isBoolean()&&!observed.path("privateFieldsExported").asBoolean());validateScopeWindow(observed,epoch,phase);require(observed.path("nativeJars").size()==4);for(var pin:JARS.entrySet())require(pin.getValue().equals(text(observed.path("nativeJars"),pin.getKey())));for(var pin:CONFIGS.entrySet())require(pin.getValue().equals(hash(original(role,prefix+pin.getKey()+".xml"))));
            var classpath=json(original(role,prefix+"classpath-sha256.json"));require("1fcd492d07b1ca59600b763c0cddc3be85dc223841a2298bf3719274b66c4cb3".equals(hash(original(role,prefix+"classpath-sha256.json"))));var overrides=json(original(role,prefix+"override-source-inventory.json"));require(overrides.isArray()&&overrides.isEmpty());validateSelectedProperties(json(original(role,prefix+"selected-properties.json")));var flags=json(original(role,prefix+"process-overrides.json"));require(flags.path("nativeJavaProcessObserved").asBoolean(false)&&!flags.path("trustOverridePresent").asBoolean(true)&&!flags.path("customAgentPresent").asBoolean(true)&&!flags.path("privateFieldsExported").asBoolean(true));ShibbolethSubjectConfirmationEvidence.validateProfile(json(original(role,prefix+"native-effective-profile.json")));
        }
        for(String suffix:List.of("classpath-sha256.json","override-source-inventory.json","selected-properties.json","properties-sha256.json","xml-sha256.json","native-effective-profile.json","process-overrides.json"))require(Arrays.equals(original(role,"trust-"+variant+"-before-"+suffix),original(role,"trust-"+variant+"-after-"+suffix)));
    }
    static void validateSelectedProperties(JsonNode n){require(n.isObject()&&ENGINE.equals(text(n,"idp.trust.signatures")));for(var fields=n.fields();fields.hasNext();){var row=fields.next();require(row.getValue().isTextual()&&((row.getKey().equals("idp.trust.signatures")&&row.getValue().asText().equals(ENGINE))||(row.getKey().equals("idp.security.config")&&row.getValue().asText().equals("shibboleth.DefaultSecurityConfiguration"))||(row.getKey().equals("idp.additionalProperties")&&row.getValue().asText().equals("/credentials/secrets.properties"))));}}
    private static Element bean(Element root,String id){var found=new ArrayList<Element>();var nodes=root.getElementsByTagNameNS("http://www.springframework.org/schema/beans","bean");for(int i=0;i<nodes.getLength();i++){var e=(Element)nodes.item(i);if(id.equals(e.getAttribute("id")))found.add(e);}require(found.size()==1);return found.getFirst();}
    private static void validateNativeBindings(Path role)throws Exception{
        var conf=original(role,"native-idp-conf-impl.jar");var rp=SecureXml.parse(zip(conf,"net/shibboleth/idp/conf/relying-party-system.xml")).getDocumentElement();var explicit=bean(rp,ENGINE);require("org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine".equals(explicit.getAttribute("class"))&&"shibboleth.MetadataCredentialResolver".equals(explicit.getAttributeNS("http://www.springframework.org/schema/c","resolver-ref")));
        var security=SecureXml.parse(zip(conf,"net/shibboleth/idp/conf/security-system.xml")).getDocumentElement();var resolver=bean(security,"shibboleth.MetadataCredentialResolver");require("org.opensaml.saml.security.impl.MetadataCredentialResolver".equals(resolver.getAttribute("class"))&&"shibboleth.RoleDescriptorResolver".equals(resolver.getAttributeNS("http://www.springframework.org/schema/p","roleDescriptorResolver-ref")));
        var encryption=bean(security,"shibboleth.EncryptionParametersResolver");require("org.opensaml.saml.security.impl.SAMLMetadataEncryptionParametersResolver".equals(encryption.getAttribute("class"))&&"shibboleth.MetadataCredentialResolver".equals(encryption.getAttributeNS("http://www.springframework.org/schema/c","resolver-ref")));
        require("9fea07f856dfc05e7490c3dbe3f8aa71db9166c6d85d3f33a909ba2241885410".equals(hash(zip(original(role,"native-opensaml-saml-impl.jar"),"org/opensaml/saml/security/impl/SAMLMetadataEncryptionParametersResolver.class"))));
    }
    private static void validateRuntimeEpoch(Path role)throws Exception {
        var start=json(original(role,"trust-runtime-protocol-start.json"));var end=json(original(role,"trust-runtime-protocol-end.json"));var restored=json(original(role,"trust-runtime-final.json"));
        var counts=json(original(role,"trust-product-counts.json"));var operations=json(original(role,"trust-product-operations.json"));var restoration=json(original(role,"trust-product-restoration.json"));
        require(counts.path("auditChanged").isBoolean());boolean changed=!Arrays.equals(original(role,"original-audit.xml"),original(role,"configured-audit.xml"));require(changed==counts.path("auditChanged").asBoolean());
        validateRuntimeIdentity(start,end,restored,changed);validateRoleRuntime(start,json(original(role,"target-container-inspect-start.json")));validateRoleRuntime(end,json(original(role,"target-container-inspect-end.json")));require(counts.path("restored").asBoolean(false)&&restoration.path("restored").asBoolean(false)&&restoration.path("errors").isArray()&&restoration.path("errors").isEmpty());
        require(counts.path("productRestarts").asInt(-1)==(changed?2:0)&&counts.path("credentialPosts").asInt(-1)==1&&counts.path("protocolSubmissions").asInt(-1)==counts.path("nativeGetAttempts").asInt(-1)+11&&counts.path("nativeGetAttempts").asInt(-1)>=0&&counts.path("nativeGetAttempts").asInt(-1)<=1&&counts.path("ordinaryBaselineSubmissions").asInt(-1)==1&&counts.path("nativePostAttempts").asInt(-1)==11&&counts.path("sameAuthenticatedClient").asBoolean(false)&&counts.path("additionalLoginBlocked").asBoolean(false)&&counts.path("personOperations").asInt(-1)==0);
        require(operations.isArray());int restarts=0;for(var op:operations)if("restart".equals(op.path("operation").asText())){require(op.path("completed").asBoolean(false)&&Set.of("prepare-native-audit","restore-native-settings").contains(text(op,"label")));restarts++;}require(restarts==(changed?2:0));
    }
    static void validateRuntimeIdentity(JsonNode start,JsonNode end,JsonNode restored,boolean auditChanged){
        require(start.isObject()&&start.equals(end)&&start.path("running").isBoolean()&&start.path("running").asBoolean()&&restored.path("running").isBoolean()&&restored.path("running").asBoolean());
        require(start.path("mounts").isArray());for(String key:List.of("id","image","mounts"))require(start.path(key).equals(restored.path(key)));
        var before=Instant.parse(text(start,"startedAt"));var after=Instant.parse(text(restored,"startedAt"));require(auditChanged?after.isAfter(before):after.equals(before));
    }
    static void validateRoleRuntime(JsonNode trustRuntime,JsonNode roleInspect){
        require(roleInspect.isArray()&&roleInspect.size()==1);var nativeRuntime=roleInspect.get(0);require(nativeRuntime.path("State").path("Running").isBoolean()&&trustRuntime.path("running").isBoolean()&&nativeRuntime.path("State").path("Running").asBoolean()==trustRuntime.path("running").asBoolean());
        require(text(trustRuntime,"id").equals(text(nativeRuntime,"Id"))&&text(trustRuntime,"image").equals(text(nativeRuntime,"Image"))&&Instant.parse(text(trustRuntime,"startedAt")).equals(Instant.parse(text(nativeRuntime.path("State"),"StartedAt"))));
    }
    static boolean validateSelectedPath(JsonNode m,boolean permission){String path=text(m,"selectedPath");require(Set.of("stock-native-signature-encryption","developer-instrumented-additional-anchor").contains(path));boolean calibration=path.startsWith("developer-");require(m.path("counterfactualCalibrationOnly").isBoolean()&&m.path("counterfactualCalibrationOnly").asBoolean()==calibration&&(!calibration||permission));return calibration;}
    static void validateNativeControl(JsonNode r){for(var key:List.of("stockNativeSignatureAccepted","samePublicAnchorSuppliedAccepted"))require(r.path(key).isBoolean()&&r.path(key).asBoolean());for(var key:List.of("stockAdditionalTrustInputSupplied","emptyExternalAnchorsAccepted","otherPublicAnchorSuppliedAccepted"))require(r.path(key).isBoolean()&&!r.path(key).asBoolean());}
    static void validateCosts(JsonNode costs){for(var key:List.of("productSettings","protocol","credentialPosts","productRestarts","personOperations"))require(costs.path(key).isIntegralNumber()&&costs.path(key).asInt(-1)==0);require(costs.path("nativeCompilerCalls").asInt(-1)==1&&costs.path("nativePublicJavaCalls").asInt(-1)==2&&costs.path("temporarySourceRemoved").asBoolean(false));}
    static void validateInvocation(JsonNode costs,String inputHash,String outputHash,JsonNode historicalRuntime,String selectedPath){
        var before=costs.path("nativeContainerBefore");require(before.isObject()&&before.equals(costs.path("nativeContainerAfter"))&&before.equals(historicalRuntime)&&before.path("running").asBoolean(false));
        require(costs.path("invocations").isArray()&&costs.path("invocations").size()==2);var rows=new ArrayList<JsonNode>();var modes=new HashSet<String>();for(var n:costs.path("invocations")){require(modes.add(text(n,"selectedPath")));if(selectedPath.equals(text(n,"selectedPath")))rows.add(n);}require(rows.size()==1&&modes.equals(Set.of("stock-native-signature-encryption","developer-instrumented-additional-anchor")));var row=rows.getFirst();require(row.path("exitCode").isIntegralNumber()&&row.path("exitCode").asInt(-1)==0&&PRODUCER.equals(text(row,"sourceSha256"))
                &&inputHash.equals(text(row,"inputSha256"))&&outputHash.equals(text(row,"outputSha256"))
                &&java.time.Instant.parse(text(row,"startedAt")).isBefore(java.time.Instant.parse(text(row,"completedAt"))));
        var command=row.path("command");require(command.isArray()&&command.size()==11&&selectedPath.equals(command.get(10).asText())&&"docker".equals(command.get(0).asText())&&"exec".equals(command.get(1).asText())
                &&"samlscope-reference-shibboleth".equals(command.get(2).asText())&&"java".equals(command.get(3).asText())&&"-cp".equals(command.get(5).asText())&&"ShibbolethSelfContainedTrustProducer".equals(command.get(7).asText()));
        String inputName=selectedPath.startsWith("developer-")?"calibration-input.json":"input.json";String temp=command.get(8).asText().replaceFirst("/"+inputName.replace(".","\\.")+"$","");require(temp.matches("/tmp/shib-self-contained-trust-[a-f0-9]{12}")
                &&(temp+"/"+inputName).equals(command.get(8).asText())&&(temp+"/ShibbolethSelfContainedTrustProducer.java").equals(command.get(9).asText())
                &&("-Dlogback.configurationFile="+temp+"/logback.xml").equals(command.get(4).asText())
                &&(temp+":/usr/local/tomcat/webapps/idp/WEB-INF/lib/*").equals(command.get(6).asText()));
    }
    static void validateOutputMode(JsonNode output,String mode){require(mode.equals(text(output,"selectedPath"))&&output.path("counterfactualCalibrationOnly").isBoolean()&&output.path("counterfactualCalibrationOnly").asBoolean()==mode.startsWith("developer-"));for(var row:output.path("records")){
        var selected=row.path("selectedConsumer");require(mode.equals(text(selected,"path"))&&selected.path("accepted").isBoolean()&&selected.path("additionalTrustInputRequired").isBoolean()&&selected.path("additionalTrustInputSupplied").isBoolean()&&!selected.path("additionalTrustInputSupplied").asBoolean());
        if(mode.startsWith("developer-")){require(!selected.path("accepted").asBoolean()&&selected.path("additionalTrustInputRequired").asBoolean()&&selected.path("acceptedWithSamePublicAnchorSupplied").asBoolean(false)&&selected.path("otherPublicAnchorSuppliedAccepted").isBoolean()&&!selected.path("otherPublicAnchorSuppliedAccepted").asBoolean());validateNativeControl(row);}
        else require(selected.path("accepted").asBoolean()&&!selected.path("additionalTrustInputRequired").asBoolean()&&row.path("emptyExternalAnchorsAccepted").isMissingNode()&&row.path("samePublicAnchorSuppliedAccepted").isMissingNode()&&row.path("otherPublicAnchorSuppliedAccepted").isMissingNode()&&row.path("stockNativeSignatureAccepted").asBoolean(false)&&row.path("stockAdditionalTrustInputSupplied").isBoolean()&&!row.path("stockAdditionalTrustInputSupplied").asBoolean());
    }}
    private static void validateDiagnostic(JsonNode n,String run){require("samlscope-shibboleth-self-contained-trust-diagnostic-v2".equals(text(n,"schema"))&&run.equals(text(n,"runId"))&&"public-native-trust-calibration-only".equals(text(n,"purpose"))&&n.path("records").isArray()&&n.path("records").size()==4);for(var key:List.of("productSettings","protocolOperations","credentialPosts","productRestarts","personOperations"))require(n.path(key).isIntegralNumber()&&n.path(key).asInt(-1)==0);for(var key:List.of("privateKeyRead","nativeControlsAdopted"))require(n.path(key).isBoolean()&&!n.path(key).asBoolean());}
    private static void validateClassBytes(JsonNode n,Path signer,byte[] security)throws Exception{
        var classes=n.path("selectedNativeClassHashes");require(classes.isObject()&&classes.size()==5);
        for(var name:List.of("org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver","org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver","org.opensaml.saml.security.impl.MetadataCredentialResolver","org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine","org.opensaml.security.credential.impl.StaticCredentialResolver")){
            byte[] jar=name.startsWith("org.opensaml.security.")?security:original(signer,name.startsWith("org.opensaml.xmlsec.")?"native-opensaml-xmlsec-impl.jar":"native-opensaml-saml-impl.jar");require(hash(zip(jar,name.replace('.','/')+".class")).equals(text(classes,name)));
        }
    }
    private Map<String,TranscriptEntry> history(CaseContext c,String run){require(validRun(run));var by=new LinkedHashMap<String,TranscriptEntry>();for(var e:c.transcript().list(run)){require(run.equals(e.runId())&&by.put(e.id(),e)==null);if(e.decodedSamlRef()!=null)require(("transcripts/"+run+"/"+e.id()+".saml.xml").equals(e.decodedSamlRef()));}return by;}
    private byte[] decoded(TranscriptEntry e)throws Exception{require(e!=null&&e.decodedSamlRef()!=null);var raw=content.readDecodedSaml(e);require(raw!=null&&raw.length==e.decodedSamlBytes());return raw;}
    private static boolean validRun(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}");}
    private static void require(boolean b){if(!b)throw new IllegalArgumentException("Native metadata trust proof unavailable");}
    private static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw));}
    private static String text(JsonNode n,String key){require(n.path(key).isTextual()&&!n.path(key).asText().isBlank());return n.path(key).asText();}
    private static JsonNode json(byte[] raw)throws Exception{return new JsonCodec().mapper().readTree(raw);}
    private static byte[] original(Path root,String name)throws Exception{require(!name.isBlank()&&!Path.of(name).isAbsolute());var p=root.resolve(name).normalize();require(p.startsWith(root)&&!p.equals(root));for(var parent=p;parent!=null;parent=parent.getParent())require(!Files.isSymbolicLink(parent));require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS));return Files.readAllBytes(p);}
    private static byte[] bound(Path folder,JsonNode m,String key)throws Exception{byte[] raw=original(folder,text(m,key+"File"));require(hash(raw).equals(text(m,key+"Sha256")));return raw;}
    private static byte[] zip(byte[] raw,String name)throws Exception{try(var in=new ZipInputStream(new java.io.ByteArrayInputStream(raw))){for(var entry=in.getNextEntry();entry!=null;entry=in.getNextEntry())if(name.equals(entry.getName()))return in.readAllBytes();}throw new IllegalArgumentException("Native class absent");}
    private static CaseOutcome pending(){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_metadata_trust_unproven","metadata.trust.native-evidence-incomplete","metadata.trust.native-evidence-incomplete",List.of(),Map.of("evidence_adapter",ADAPTER));}
}
