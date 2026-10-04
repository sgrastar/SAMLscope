package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataRoleKeyEvidence.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.*;
import java.util.*;
import java.util.function.*;

/** Metadata-only SIG/ENC trust for the actual recorded SP consumer. No declaration or TLS claim. */
public final class SimpleSamlPhpSelfContainedTrustEvidenceFile {
    public static final String ID="IIP-MD06-c-idp-01", ADAPTER="simplesamlphp-native-self-contained-trust-v1";
    static final String SCHEMA="samlscope-simplesamlphp-self-contained-trust-v1";
    static final String PRODUCER="6dfbf7c49d2135de2d0079352fab3c1153ffeaad05a4c323b45c03319dbc9ec7";
    private final Path directory,roleDirectory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    private final boolean offlineCalibrationAllowed;
    public SimpleSamlPhpSelfContainedTrustEvidenceFile(Path directory,Path roleDirectory,
            TranscriptContentReader content,Function<String,byte[]> metadata,
            BiFunction<String,String,Optional<PlanCredentials>> keys){
        this(directory,roleDirectory,content,metadata,keys,false);
    }
    /** Explicit developer-only detector permission; no receipt can enable it in the registered runtime. */
    SimpleSamlPhpSelfContainedTrustEvidenceFile(Path directory,Path roleDirectory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,boolean offlineCalibrationAllowed){
        this.offlineCalibrationAllowed=offlineCalibrationAllowed;
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.roleDirectory=Objects.requireNonNull(roleDirectory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.keys=Objects.requireNonNull(keys);
    }
    private Path receipt(String run){return directory.resolve(run+".simplesamlphp-trust.json");}
    private Path folder(String run){return directory.resolve(run+".simplesamlphp-trust");}
    public boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
            &&(Files.exists(receipt(run),LinkOption.NOFOLLOW_LINKS)||Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS));}
    public CaseOutcome evaluate(CaseContext context){
        try{return proof(context);}catch(Exception missing){return pending();}
    }
    private CaseOutcome proof(CaseContext context)throws Exception{
        require(context.transcriptComplete()&&exists(context.runId()));String run=context.runId();
        var raw=original(directory,run+".simplesamlphp-trust.json");var m=json(raw);var payload=folder(run);
        require(SCHEMA.equals(text(m,"schema"))&&ADAPTER.equals(text(m,"adapter"))&&ID.equals(text(m,"caseId"))
                &&run.equals(text(m,"runId"))&&"native-metadata-trust".equals(text(m,"campaignId")));
        String selectedPath=text(m,"selectedPath");require(Set.of("stock-native-signature-encryption","developer-instrumented-additional-anchor").contains(selectedPath));
        boolean calibration="developer-instrumented-additional-anchor".equals(selectedPath);
        require(m.path("counterfactualCalibrationOnly").isBoolean()&&m.path("counterfactualCalibrationOnly").asBoolean()==calibration);
        require(!calibration||offlineCalibrationAllowed);
        var role=roleDirectory.resolve(run);var roleRaw=original(role,"manifest.json");var roles=json(roleRaw);
        var targetRaw=metadata.apply(run);var target=SecureXml.parse(targetRaw).getDocumentElement();
        require(hash(targetRaw).equals(text(m,"targetMetadataSha256"))&&target.getAttribute("entityID").equals(text(m,"targetEntityId"))
                &&text(m,"peerEntityId").equals(text(roles,"entityId"))&&hash(roleRaw).equals(text(m,"roleReceiptSha256"))
                &&SimpleSamlPhpMetadataRoleKeyNativeAdapter.ADAPTER.equals(text(roles,"adapter")));
        var common=new MetadataRoleKeyEvidence(roleDirectory,content,metadata,keys,new SimpleSamlPhpMetadataRoleKeyNativeAdapter(content)).evaluate(context).orElseThrow();
        require(common.outcome()==Outcome.SATISFIED);
        var inputRaw=bound(payload,m,"inputFile","inputSha256");var input=json(inputRaw);
        var nativeRaw=bound(payload,m,"nativeOutputFile","nativeOutputSha256");var nativeProof=json(nativeRaw);
        var costs=json(bound(payload,m,"operationsFile","operationsSha256"));
        require(costs.path("nativePhpDiagnosticCalls").asInt(-1)==2&&costs.path("nativeCompilerCalls").asInt(-1)==0&&costs.path("temporarySourceRemoved").asBoolean(false));
        for(String cost:List.of("productSettings","protocol","credentialPosts","productRestarts","personOperations"))require(costs.path(cost).isIntegralNumber()&&costs.path(cost).asInt(-1)==0);
        require(PRODUCER.equals(hash(bound(payload,m,"producerFile","producerSha256")))
                &&PRODUCER.equals(text(nativeProof,"sourceSha256"))&&hash(inputRaw).equals(text(nativeProof,"inputSha256")));
        validateClasses(nativeProof);
        validateInvocation(costs,selectedPath,hash(inputRaw),hash(nativeRaw),roles,role);
        require("samlscope-simplesamlphp-self-contained-trust-input-v1".equals(text(input,"schema"))
                &&"samlscope-simplesamlphp-self-contained-trust-calibration-v1".equals(text(nativeProof,"schema")));
        for(var n:List.of(input,nativeProof))require(run.equals(text(n,"runId"))&&text(m,"peerEntityId").equals(text(n,"peerEntityId"))
                &&text(m,"targetMetadataSha256").equals(text(n,"targetMetadataSha256"))&&selectedPath.equals(text(n,"selectedPath"))&&n.path("records").isArray()&&n.path("records").size()==4);
        require(nativeProof.path("counterfactualCalibrationOnly").isBoolean()&&nativeProof.path("counterfactualCalibrationOnly").asBoolean()==calibration);
        require(nativeProof.path("nativePrivateKeyUsed").isBoolean()&&!nativeProof.path("nativePrivateKeyUsed").asBoolean()
                &&nativeProof.path("mutantControlsAdopted").isBoolean()&&!nativeProof.path("mutantControlsAdopted").asBoolean());
        for(String cost:List.of("productConfigurationWrites","protocolOperations","credentialPosts","productRestarts","humanOperations"))
            require(nativeProof.path(cost).isIntegralNumber()&&nativeProof.path(cost).asInt(-1)==0);
        var by=new HashMap<String,TranscriptEntry>();for(var e:context.transcript().list(run))require(run.equals(e.runId())&&by.put(e.id(),e)==null);
        var seen=new HashSet<String>();
        for(var epoch:roles.path("observations")){
            var normals=new ArrayList<JsonNode>();for(var e:epoch.path("exchanges"))if(text(e,"fixtureId").endsWith("-normal"))normals.add(e);require(normals.size()==1);var exchange=normals.getFirst();String id=text(exchange,"fixtureId");require(seen.add(id));
            var in=record(input,id);var n=record(nativeProof,id);var fixture=original(role,text(epoch,"variant")+"-fixture.xml");
            var request=by.get(text(exchange,"requestReference"));require(request!=null);var requestRaw=content.readDecodedSaml(request);
            require(Arrays.equals(fixture,Base64.getDecoder().decode(text(in,"metadataBase64")))&&Arrays.equals(requestRaw,Base64.getDecoder().decode(text(in,"requestBase64"))));
            for(var row:List.of(in,n))require(hash(fixture).equals(text(row,"fixtureSha256"))&&hash(requestRaw).equals(text(row,"requestSha256"))&&request.id().equals(text(row,"requestReference")));
            var xml=SecureXml.parse(requestRaw).getDocumentElement();require(xml.getAttribute("ID").equals(text(n,"requestId")));
            var nativeSp=json(original(role,text(epoch,"variant")+"-parser-output.json")).path("nativeSpMetadata");validateTrustInputs(nativeSp);
            var signer=single(SecureXml.parse(fixture).getDocumentElement(),"urn:oasis:names:tc:SAML:2.0:metadata","SPSSODescriptor");
            var fingerprints=SimpleSamlPhpMetadataRoleKeyNativeAdapter.certificateKeys(signer,"signing");require(fingerprints.size()==1&&fingerprints.contains(text(n,"metadataSigningCertificateSha256")));
            validateStock(n);validateSelectedConsumer(n,selectedPath,calibration);
        }
        require(seen.size()==4&&hash(raw).equals(hash(original(directory,run+".simplesamlphp-trust.json"))));
        var details=new LinkedHashMap<String,Object>();details.put("evidence_adapter",ADAPTER);details.put("run_id",run);
        details.put("native_originals_verified",true);details.put("restoration_verified",true);details.put("signature_verification_observed",true);
        details.put("metadata_key_encryption_decryption_observed",true);details.put("additional_trust_input_required",calibration);
        details.put("proof_scope",calibration?"developer-instrumented-additional-anchor-fixture":"recorded-native-signature-encryption-flow");
        details.put("counterfactual_calibration_only",calibration);details.put("mutant_controls_adopted",false);
        details.put("receipt_sha256",hash(raw));details.put("role_receipt_sha256",hash(roleRaw));details.put("native_diagnostic_sha256",hash(nativeRaw));
        details.put("private_key_exported",false);details.put("plaintext_persisted",false);
        var refs=new ArrayList<>(common.evidence());refs.add(new EvidenceRef("native-self-contained-trust-evidence",run+".simplesamlphp-trust.json"));
        String reason=calibration?"metadata.trust.additional-anchor-required":"metadata.trust.self-contained-native-observed";
        return new CaseOutcome(calibration?Outcome.VIOLATED:Outcome.SATISFIED,null,reason,reason,List.copyOf(refs),Map.copyOf(details));
    }
    static void validateStock(JsonNode record){require(record.path("stockNativeSignatureAccepted").isBoolean()&&record.path("stockNativeSignatureAccepted").asBoolean()
            &&record.path("stockAdditionalTrustInputSupplied").isBoolean()&&!record.path("stockAdditionalTrustInputSupplied").asBoolean());}
    static void validateAdditionalTrustTrace(JsonNode record){
        var m=record.path("mutant");require(m.path("mathematicalSignatureAccepted").asBoolean(false)&&m.path("additionalTrustInputRequired").asBoolean(false)
                &&m.path("additionalTrustInputSupplied").isBoolean()&&!m.path("additionalTrustInputSupplied").asBoolean()
                &&m.path("rejected").asBoolean(false)&&"RuntimeException".equals(text(m,"exceptionClass"))
                &&("ExternalTrustInputRequired:"+text(record,"metadataSigningCertificateSha256")).equals(text(m,"exceptionMessage"))
                &&m.path("acceptedWithSamePublicAnchorSupplied").asBoolean(false)&&m.path("counterfactualCalibrationOnly").asBoolean(false));
    }
    static void validateSelectedConsumer(JsonNode record,String path,boolean instrumented){
        var selected=record.path("selectedConsumer");require(path.equals(text(selected,"path"))&&selected.path("accepted").isBoolean()
                &&selected.path("additionalTrustInputRequired").isBoolean()&&selected.path("additionalTrustInputSupplied").isBoolean()
                &&!selected.path("additionalTrustInputSupplied").asBoolean());
        if(instrumented){validateAdditionalTrustTrace(record);require(!selected.path("accepted").asBoolean()&&selected.path("additionalTrustInputRequired").asBoolean()
                &&"RuntimeException".equals(text(selected,"exceptionClass"))&&("ExternalTrustInputRequired:"+text(record,"metadataSigningCertificateSha256")).equals(text(selected,"exceptionMessage")));}
        else require(selected.path("accepted").asBoolean()&&!selected.path("additionalTrustInputRequired").asBoolean()&&record.path("mutant").isMissingNode());
    }
    static void validateTrustInputs(JsonNode sp){
        require(sp.isObject());for(var it=sp.fieldNames();it.hasNext();){String key=it.next();String lower=key.toLowerCase(Locale.ROOT);
            require(!Set.of("sharedkey","sharedkey_algorithm","ca","cafile","capath","truststore","certdata","certificate","certfile","remote.trust","signature.key","encryption.key").contains(lower)
                    &&!lower.contains("trust")&&!lower.contains("fingerprint")&&!lower.contains("callback")&&!lower.contains("hmac"));}
        require(sp.path("keys").isArray()&&!sp.path("keys").isEmpty()&&sp.path("validate.authnrequest").asBoolean(false));
    }
    private static JsonNode record(JsonNode n,String fixture){var found=new ArrayList<JsonNode>();for(var r:n.path("records"))if(fixture.equals(r.path("fixtureId").asText()))found.add(r);require(found.size()==1);return found.getFirst();}
    private static byte[] bound(Path folder,JsonNode m,String file,String digest)throws Exception{var bytes=original(folder,text(m,file));require(hash(bytes).equals(text(m,digest)));return bytes;}
    static void validateInvocation(JsonNode costs,String selectedPath,String inputHash,String outputHash,JsonNode roles,Path role)throws Exception{
        var attempts=costs.path("attempts");require(attempts.isArray()&&attempts.size()==2);var selected=new ArrayList<JsonNode>();
        var paths=new HashSet<String>();for(var row:attempts){require(paths.add(text(row,"selectedPath")));if(selectedPath.equals(text(row,"selectedPath")))selected.add(row);}
        require(paths.equals(Set.of("stock-native-signature-encryption","developer-instrumented-additional-anchor"))&&selected.size()==1);var invocation=selected.getFirst();
        require(invocation.path("exitCode").isIntegralNumber()&&invocation.path("exitCode").asInt(-1)==0&&PRODUCER.equals(text(invocation,"sourceSha256"))
                &&inputHash.equals(text(invocation,"inputSha256"))&&outputHash.equals(text(invocation,"outputSha256"))
                &&java.time.Instant.parse(text(invocation,"startedAt")).isBefore(java.time.Instant.parse(text(invocation,"completedAt"))));
        var command=invocation.path("command");require(command.isArray()&&command.size()==6&&"docker".equals(command.get(0).asText())&&"exec".equals(command.get(1).asText())
                &&"-i".equals(command.get(2).asText())&&"samlscope-reference-ssp".equals(command.get(3).asText())&&"php".equals(command.get(4).asText())
                &&command.get(5).asText().matches("/tmp/self-contained-trust-[a-f0-9]{12}\\.php"));
        var before=costs.path("nativeContainerBefore");var after=costs.path("nativeContainerAfter");var old=json(original(role,"target-container-inspect-start.json")).get(0);
        require(before.equals(after)&&before.path("State").path("Running").asBoolean(false)&&text(before,"Id").equals(text(old,"Id"))&&text(before,"Image").equals(text(old,"Image")));
    }
    private static void validateClasses(JsonNode n){
        var rows=n.path("selectedNativeClasses");require(rows.isObject()&&rows.size()==7&&rows.equals(n.path("selectedNativeClassesAfter")));
        for(var name:List.of("native-idp.php","native-message.php","native-configuration.php","native-parser.php","native-signed-helper.php","native-xml-security-key.php","native-xml-security-dsig.php")){
            var r=rows.path(name);require(SimpleSamlPhpMetadataRoleKeyNativeAdapter.SOURCE.get(name).equals(text(r,"sha256"))
                    &&text(r,"file").startsWith("/var/simplesamlphp/")&&!text(r,"file").contains("..")&&!text(r,"class").isBlank());
        }
    }
    private static CaseOutcome pending(){return new CaseOutcome(Outcome.NOT_VERIFIED,"native_metadata_trust_unproven",
            "metadata.trust.native-evidence-incomplete","metadata.trust.native-evidence-incomplete",List.of(),Map.of("evidence_adapter",ADAPTER));}
}
