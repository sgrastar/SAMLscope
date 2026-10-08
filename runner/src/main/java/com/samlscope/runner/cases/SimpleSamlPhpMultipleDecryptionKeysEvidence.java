package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;

/** Two actual native private keys in one applied CONFIG epoch. No logout-use claim. */
public final class SimpleSamlPhpMultipleDecryptionKeysEvidence {
    public static final String CASE="IIP-IDP19-b-idp-01";
    public static final String DIGEST="sha256:f0804b19a640f8dc668635a12630d2ac5dbb50193f04bed346a0e4afcc2ab9a8";
    public static final String SCHEMA="samlscope-simplesamlphp-multiple-decryption-keys-v1";
    public static final String REASON="configuration.multiple-decryption-keys.native-proven";
    public static final String SUFFIX=".simplesamlphp-multiple-decryption-keys";
    private static final String IMAGE="sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa";
    private static final String TARGET="http://localhost:18380/idp";
    private static final String MESSAGE="ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2";
    // Suite-owned program digests are fixed only after collector qualification.
    private static final String HELPER="c99cefabf8f07a3a67c639802b62954c899874e0abe97e92511779c86950fcc0";
    private static final String COLLECTOR="b3e67dcb3a4de36060bbed4a903f7179b47ce75d51cf7b29c0ee639d869a91b5";
    private static final String START="        // load the new private key if it exists\n";
    private static final String END="        /**\n         * find the existing private key\n";
    private static final Map<String,String> SOURCES=Map.ofEntries(
        Map.entry("SimpleSAML\\Module\\saml\\Message",MESSAGE),
        Map.entry("SimpleSAML\\Configuration","53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e"),
        Map.entry("SimpleSAML\\Utils\\Crypto","eedf4f4d133e117235d6829c4e386570c5168ad01afe060b3a31f38d0a1db0f3"),
        Map.entry("SimpleSAML\\Metadata\\MetaDataStorageHandler","43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040"),
        Map.entry("RobRichards\\XMLSecLibs\\XMLSecurityKey","6c89ac116aca2c05791712749450be474218fd97cd9a66b7aad9d2ba4e6cba17"),
        Map.entry("SAML2\\LogoutRequest","c034e1cb690c313b3e86422eb2265a078b4bd7be2bd435dd40a3bbe0b523eb7b"),
        Map.entry("SAML2\\DOMDocumentFactory","0526f34af85b35e79295047b6ff92e195d424cac089fb61ecfef1a7ea5399882"),
        Map.entry("SAML2\\Utils","5845e28158c7641d5ce1e6b9205e8005b6d9c090e1888ea46416abb8fdf0018d"),
        Map.entry("SAML2\\XML\\saml\\NameID","7236266d3d5ca32ca5bd5c3b9ab29c0a512441cac61883b35d3dcf738dd95bef"),
        Map.entry("RobRichards\\XMLSecLibs\\XMLSecEnc","cb6297bb784cf0d806ac720499205e13fc250972e6ac71e6207bd9b3f974fcb3"));
    private final Path directory;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    private final DefaultAlgorithmSourceRunStore store;
    private final ObjectMapper json=new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public SimpleSamlPhpMultipleDecryptionKeysEvidence(Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,DefaultAlgorithmSourceRunStore store) {
        this.directory=Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);this.store=Objects.requireNonNull(store);
        require(CASE.equals(store.approvedCaseId())&&DIGEST.equals(store.approvedCaseDigest()));
    }
    private Path folder(String run){return directory.resolve(run+SUFFIX);}
    public boolean exists(String run){return run!=null&&run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")&&Files.exists(folder(run),LinkOption.NOFOLLOW_LINKS);}
    public Optional<CaseOutcome> read(CaseContext context) {
        return read(context, false, null);
    }

    /** This one CONFIG obligation has a complete zero-protocol native proof.
     * A source binding keeps its actual incomplete Run and does not synthesize a case execution.
     * The caller must independently fence the entire source and completed recipient. */
    Optional<CaseOutcome> readIndependentConfigurationSource(CaseContext context, String expectedManifestSha256) {
        return read(context, true, expectedManifestSha256);
    }

    private Optional<CaseOutcome> read(CaseContext context, boolean independentSource, String expectedManifestSha256) {
        if(!exists(context.runId()))return Optional.empty();String stage="source-run";
        try {
            require(context.targetRole()==TargetRole.IDP
                &&(independentSource?!context.transcriptComplete():context.transcriptComplete()));
            Path f=folder(context.runId());safe(f);byte[] manifestRaw=original(f,"manifest.json");
            if(independentSource)require(expectedManifestSha256!=null&&expectedManifestSha256.matches("[0-9a-f]{64}")&&hash(manifestRaw).equals(expectedManifestSha256));
            var m=json.readTree(manifestRaw);
            require(SCHEMA.equals(text(m,"schema"))&&CASE.equals(text(m,"caseId"))&&DIGEST.equals(text(m,"caseDigest"))
                &&context.runId().equals(text(m,"runId"))&&TARGET.equals(text(m,"targetEntityId"))
                &&"native-multiple-decryption-keys".equals(text(m,"campaignId"))&&!m.path("outcomeAssigned").asBoolean(true));
            var files=m.path("files");require(files.isObject()&&files.size()>15&&files.size()<=600);
            long bytes=0;var names=files.fieldNames();while(names.hasNext()){String name=names.next();byte[] value=checked(f,files,name);bytes+=value.length;require(bytes<=33554432);}
            var source=independentSource?store.planned(context.runId()):store.execution(context.runId());
            if(independentSource) {
                require(source.actions().isEmpty()&&source.snapshot().path("outbox").isArray()
                    &&source.snapshot().path("outbox").isEmpty()
                    &&!source.snapshot().has("caseExecutionSha256")
                    &&source.plan().parameters().equals(context.parameters())
                    &&source.plan().interaction().equals(context.interaction())
                    &&source.run().targetToSuiteReachability()==context.reachability());
            }
            require(TARGET.equals(source.plan().target().entityId())&&"single_logout_idp".equals(source.plan().profile().id())
                &&stable(source.snapshot()).equals(node(f,files,"source-store.json")));
            var entries=context.transcript().list(context.runId());require(store.history(context.runId(),entries,content).equals(node(f,files,"source-history.json")));
            byte[] target=metadata.apply(context.runId());require(target!=null&&Arrays.equals(target,checked(f,files,"target-metadata.xml"))
                &&hash(target).equals(text(m,"targetMetadataSha256")));
            var scope=node(f,files,"scope.json");require(CASE.equals(text(scope,"caseId"))&&DIGEST.equals(text(scope,"caseDigest"))
                &&"single_logout_idp".equals(text(scope,"profile"))&&hash(checked(f,files,"profile.json")).equals(text(scope,"profileSha256")));
            var profile=node(f,files,"profile.json");int count=0;for(var c:profile.path("cases"))if(CASE.equals(c.path("id").asText())){require(DIGEST.equals(text(c,"digest")));count++;}require(count==1);
            String plan=source.plan().id(),peer="http://localhost:18080/p/"+plan;
            var created=node(f,files,"created.json");require(context.runId().equals(created.path("run").path("id").asText())&&plan.equals(created.path("run").path("planId").asText()));
            stage="native-invocation";
            require(HELPER.equals(hash(checked(f,files,"native-probe.php")))&&COLLECTOR.equals(hash(checked(f,files,"collector.py"))));
            var operations=node(f,files,"operations.json");require(operations.isArray()&&operations.size()<=400);
            Instant finished=null;var operationLabels=new HashSet<String>();
            for(var op:operations){require(operationLabels.add(text(op,"label"))&&op.path("command").isArray()
                &&"docker".equals(op.path("command").get(0).asText())&&op.path("exitCode").asInt(-1)==0);
                Instant started=at(op,"startedAt"),ended=at(op,"finishedAt");require(!ended.isBefore(started)&&(finished==null||!started.isBefore(finished)));finished=ended;}
            String helper=text(m,"nativeHelperPath"),key=text(m,"newPrivateKeyPath"),cert=text(m,"newCertificatePath");
            require(helper.matches("/tmp/samlscope-decryption-config-[0-9a-f]{24}\\.php")
                &&key.equals(helper.substring(0,helper.length()-4)+".key.pem")&&cert.equals(helper.substring(0,helper.length()-4)+".cert.pem"));
            var runtime=node(f,files,"runtime-before.json");require(runtime.equals(node(f,files,"runtime-after.json"))&&IMAGE.equals(text(runtime,"imageId"))&&runtime.path("running").asBoolean(false));
            require(text(runtime,"containerId").matches("[0-9a-f]{64}")&&Instant.parse(text(runtime,"startedAt")).isBefore(at(operation(operations,"native-before"),"startedAt")));
            var input=node(f,files,"native-input.json");require(input.size()==5&&context.runId().equals(text(input,"runId"))&&DIGEST.equals(text(input,"caseDigest"))
                &&TARGET.equals(text(input,"targetEntityId"))&&peer.equals(text(input,"peerEntityId"))&&hash(target).equals(text(input,"targetMetadataSha256")));
            var before=node(f,files,"native-before.json");var after=node(f,files,"native-after.json");
            var helperWrite=operation(operations,"native-helper-write");var helperRead=operation(operations,"native-helper-readback");
            require(helperWrite.path("command").equals(json.valueToTree(List.of("docker","exec","--user","33","-i","samlscope-reference-ssp","sh","-c","cat > \"$1\"","sh",helper)))
                &&HELPER.equals(text(helperWrite,"stdinSha256"))&&helperRead.path("command").equals(json.valueToTree(List.of("docker","exec","samlscope-reference-ssp","cat",helper)))
                &&HELPER.equals(text(helperRead,"stdoutSha256"))&&at(helperRead,"finishedAt").isBefore(at(operation(operations,"native-before"),"startedAt")));
            validateObservation(f,files,before,input,m);validateObservation(f,files,after,input,m);
            // Ciphertexts use native random IVs; all stable factory/key/source facts must agree.
            for(String field:List.of("baselineKeys","control","nativeMethod","loadedClasses","dependencies","settingsSha256","keyConfiguration","effectiveUid","phpVersion","opensslVersion","challengeBase64","challengeSha256"))require(before.path(field).equals(after.path(field)));
            for(String phase:List.of("before","after")){
                var op=operation(operations,"native-"+phase);require(op.path("command").equals(json.valueToTree(List.of("docker","exec","--user","33","-i","samlscope-reference-ssp","php",helper)))
                    &&hash(checked(f,files,"native-input.json")).equals(text(op,"stdinSha256"))&&op.path("exitCode").asInt(-1)==0
                    &&hash(checked(f,files,"native-"+phase+".stdout")).equals(text(op,"stdoutSha256"))
                    &&signedObservation(f,files,"native-"+phase+".stdout",2).equals(phase.equals("before")?before:after)
                    &&hash(checked(f,files,"native-"+phase+".stderr")).equals(text(op,"stderrSha256"))
                    &&!at(op,"finishedAt").isBefore(at(op,"startedAt")));
                verifyDecryptionDiagnostics(checked(f,files,"native-"+phase+".stderr"),phase.equals("before")?before:after);}
            require(at(operation(operations,"native-before"),"finishedAt").isBefore(at(operation(operations,"native-after"),"startedAt")));
            stage="configuration-restoration";
            for(String name:List.of("hosted","remote"))require(Arrays.equals(checked(f,files,name+"-original.php"),checked(f,files,name+"-final.php")));
            var restoration=node(f,files,"restoration.json");for(String name:List.of("hosted","remote"))require(restoration.path(name).path("restored").asBoolean(false)
                &&hash(checked(f,files,name+"-original.php")).equals(text(restoration.path(name),"original_sha256"))
                &&hash(checked(f,files,name+"-final.php")).equals(text(restoration.path(name),"final_sha256")));
            byte[] host=checked(f,files,"hosted-original.php");String overlay="$metadata['"+TARGET+"']['new_privatekey']='"+key+"';\n$metadata['"+TARGET+"']['new_certificate']='"+cert+"';";
            require(Arrays.equals(concat(host,("\n"+overlay+"\n").getBytes(StandardCharsets.UTF_8)),checked(f,files,"hosted-configured.php")));
            var parser=json.readTree(checked(f,files,"native-peer-parser.stdout"));require(peer.equals(text(parser,"entity_id")));
            require(Arrays.equals(concat(checked(f,files,"remote-original.php"),("\n"+text(parser,"php")+"\n").getBytes(StandardCharsets.UTF_8)),checked(f,files,"remote-configured.php")));
            var remove=operation(operations,"native-files-remove");var absence=operation(operations,"native-paths-after");
            require(remove.path("exitCode").asInt(-1)==0&&absence.path("exitCode").asInt(-1)==0&&at(remove,"startedAt").isAfter(at(operation(operations,"native-after"),"finishedAt"))
                &&at(absence,"startedAt").isAfter(at(remove,"finishedAt"))
                &&remove.path("command").equals(json.valueToTree(List.of("docker","exec","--user","33","samlscope-reference-ssp","php","-r",
                    "foreach(array_slice($argv,1) as $p){if(is_link($p))throw new RuntimeException(\"Unexpected link\");if(file_exists($p)&&!unlink($p))throw new RuntimeException(\"Removal failed\");}",key,cert,helper)))
                &&absence.path("command").equals(json.valueToTree(List.of("docker","exec","samlscope-reference-ssp","php","-r",
                    "foreach(array_slice($argv,1) as $p)if(file_exists($p)||is_link($p))throw new RuntimeException(\"Cleanup incomplete\");",key,cert,helper))));
            var restored=signedObservation(f,files,"native-restored.stdout",1);require(restored.equals(node(f,files,"native-restored.json"))
                &&"samlscope-native-decryption-keys-restored-v1".equals(text(restored,"schema"))&&context.runId().equals(text(restored,"runId"))
                &&DIGEST.equals(text(restored,"caseDigest"))&&TARGET.equals(text(restored,"targetEntityId"))&&peer.equals(text(restored,"peerEntityId"))
                &&restored.path("effectiveUid").asInt(-1)==33&&restored.path("newPrivateKey").isNull()&&MESSAGE.equals(text(restored,"sourceSha256"))
                &&restored.path("challengeBase64").equals(before.path("challengeBase64"))&&!restored.path("privateMaterialPersisted").asBoolean(true)
                &&verifiedKeys(restored.path("keys"),Base64.getDecoder().decode(text(restored,"challengeBase64"))).equals(List.of(text(before.path("baselineKeys").get(1),"spkiSha256"))));
            var restoredOp=operation(operations,"native-restored");require(restoredOp.path("exitCode").asInt(-1)==0
                &&restoredOp.path("command").equals(json.valueToTree(List.of("docker","exec","--user","33","-i","samlscope-reference-ssp","php",helper)))
                &&hash(checked(f,files,"native-restored.stdout")).equals(text(restoredOp,"stdoutSha256"))
                &&hash(checked(f,files,"native-restored-input.json")).equals(text(restoredOp,"stdinSha256"))
                &&at(restoredOp,"startedAt").isAfter(at(operation(operations,"native-after"),"finishedAt"))&&at(restoredOp,"finishedAt").isBefore(at(remove,"startedAt")));
            require(hash(checked(f,files,"native-restored.stderr")).equals(text(restoredOp,"stderrSha256")));
            verifyExpiredMetadataWarnings(checked(f,files,"native-restored.stderr"),checked(f,files,"remote-original.php"),at(restoredOp,"finishedAt"));
            var restoredInput=((ObjectNode)input).deepCopy();restoredInput.put("mode","restored");require(restoredInput.equals(node(f,files,"native-restored-input.json")));
            var counts=node(f,files,"operation-counts.json");require(counts.path("restored").asBoolean(false)&&counts.path("nativeObservationInvocations").asInt(-1)==2
                &&counts.path("credentialPosts").asInt(-1)==0&&counts.path("samlProtocolOperations").asInt(-1)==0&&counts.path("humanOperations").asInt(-1)==0);
            stage="own-transcript";
            byte[] sp=Base64.getDecoder().decode(text(parser,"inputXmlBase64"));require(hash(sp).equals(text(parser,"inputSha256"))
                &&peer.equals(SecureXml.parse(sp).getDocumentElement().getAttribute("entityID")));
            var selected=new ArrayList<TranscriptEntry>();for(var e:entries)if("MetadataPrepared".equals(e.samlSummary().get("type"))&&Arrays.equals(sp,content.readDecodedSaml(e)))selected.add(e);
            require(selected.size()==1);var prepared=selected.getFirst();require(prepared.direction()==Direction.OUTBOUND&&"live".equals(prepared.samlSummary().get("feed"))
                &&hash(sp).equals(prepared.samlSummary().get("metadataSha256")));
            String fetch=String.valueOf(prepared.samlSummary().get("fetchTranscriptId"));var fetched=entries.stream().filter(e->fetch.equals(e.id())).toList();
            require(fetched.size()==1&&fetched.getFirst().direction()==Direction.INBOUND&&"MetadataFetch".equals(fetched.getFirst().samlSummary().get("type"))
                &&fetched.getFirst().timestamp().isBefore(prepared.timestamp())&&prepared.timestamp().isBefore(at(operation(operations,"native-before"),"startedAt")));
            var refs=List.of(new EvidenceRef("transcript",fetch),new EvidenceRef("transcript",prepared.id()),
                new EvidenceRef("native-multiple-decryption-keys",context.runId()+SUFFIX+"/manifest.json"));
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,REASON,REASON,refs,
                Map.of("evidence_adapter",SCHEMA,"run_id",context.runId(),"case_digest",DIGEST,"native_evidence_adapter","simplesamlphp-two-decryption-keys","distinct_usable_native_private_keys",2,
                    "capability_removal_control_verified",true,"configuration_restored",true,"logout_decryption_claimed",false,"attested",false,"native_manifest_sha256",hash(manifestRaw))));
        }catch(Exception unproven){return Optional.of(CaseOutcome.notVerified("native-multiple-decryption-keys."+stage,"configuration.multiple-decryption-keys.native-unproven"));}
    }

    private void validateObservation(Path f,JsonNode files,JsonNode r,JsonNode input,JsonNode m)throws Exception {
        require("samlscope-native-multiple-decryption-keys-observation-v1".equals(text(r,"schema"))&&CASE.equals(text(r,"caseId"))&&DIGEST.equals(text(r,"caseDigest"))
            &&r.path("effectiveUid").asInt(-1)==33&&!r.path("privateMaterialPersisted").asBoolean(true));
        for(String field:List.of("runId","targetEntityId","peerEntityId","targetMetadataSha256"))require(r.path(field).equals(input.path(field)));
        String challenge="SAMLscope-native-two-decryption-keys-v1\n"+text(input,"runId")+"\n"+DIGEST+"\n"+TARGET+"\n"+text(input,"peerEntityId")+"\n"+text(input,"targetMetadataSha256")+"\n";
        byte[] data=challenge.getBytes(StandardCharsets.UTF_8);require(Arrays.equals(data,Base64.getDecoder().decode(text(r,"challengeBase64")))&&hash(data).equals(text(r,"challengeSha256")));
        var actual=verifiedKeys(r.path("baselineKeys"),data);var removed=verifiedKeys(r.path("control").path("keys"),data);
        require(compareKeyCapability(actual.size(),false)==Outcome.SATISFIED&&actual.size()==2&&removed.size()==1&&removed.getFirst().equals(actual.get(1)));
        var configured=r.path("keyConfiguration");require(text(m,"newPrivateKeyPath").equals(text(configured,"newPrivateKey"))
            &&text(m,"newCertificatePath").equals(text(configured,"newCertificate"))&&!text(configured,"existingPrivateKey").isBlank()&&!configured.path("sharedKeySelected").asBoolean(true));
        var generated=certificate(checked(f,files,"new-public-certificate.pem"));require(actual.getFirst().equals(hash(generated.getPublicKey().getEncoded())));
        var target=new TargetMetadataParser().parse(checked(f,files,"target-metadata.xml"),TARGET);
        require(target.signingCertificates().stream().anyMatch(c->actual.get(1).equals(hash(c.getPublicKey().getEncoded()))));
        var classes=r.path("loadedClasses");require(classes.isArray()&&classes.size()==10);var seen=new HashSet<String>();
        for(var c:classes){String name=text(c,"class"),sha=text(c,"sha256"),path=text(c,"file");require(seen.add(name)&&path.matches("/var/simplesamlphp/(src|modules|vendor)/[A-Za-z0-9_./-]+\\.php")&&!path.contains("/.."));
            require(SOURCES.containsKey(name)&&SOURCES.get(name).equals(sha));
            require(hash(checked(f,files,"native-dependencies/"+sha+".php")).equals(sha));}
        require(seen.containsAll(SOURCES.keySet()));
        var dependencies=r.path("dependencies");require(dependencies.isArray()&&dependencies.size()>10&&dependencies.size()<=256);var paths=new HashSet<String>();String previous="";
        for(var dep:dependencies){String path=text(dep,"file"),sha=text(dep,"sha256");require(paths.add(path)&&path.compareTo(previous)>0&&path.matches("/var/simplesamlphp/(src|vendor|modules|lib)/[A-Za-z0-9_./-]+\\.php")&&!path.contains("/.."));previous=path;
            byte[] bytes=checked(f,files,"native-dependencies/"+sha+".php");require(bytes.length==dep.path("bytes").asInt(-1)&&hash(bytes).equals(sha));}
        for(var c:classes)require(paths.contains(text(c,"file")));
        byte[] nativeSource=checked(f,files,"native-dependencies/"+MESSAGE+".php");var control=r.path("control");
        require("SAMLscopeDiagnostic".equals(text(control,"namespace"))&&hash(capabilityRemovedSource(nativeSource)).equals(text(control,"sourceSha256"))
            &&compareKeyCapability(removed.size(),true)==Outcome.VIOLATED);
        String nativeText=new String(nativeSource,StandardCharsets.UTF_8);require(control.path("removedStartOffset").asInt(-1)==nativeText.indexOf(START)
            &&control.path("removedEndOffset").asInt(-1)==nativeText.indexOf(END));
        var method=r.path("nativeMethod");require("SimpleSAML\\Module\\saml\\Message".equals(text(method,"class"))&&"getDecryptionKeys".equals(text(method,"method"))
            &&MESSAGE.equals(text(method,"sha256"))&&method.path("startLine").asInt(-1)==271&&method.path("endLine").asInt(-1)==327);
        for(String name:List.of("hosted","remote"))require(hash(checked(f,files,name+"-configured.php")).equals(text(r.path("settingsSha256"),name)));
        require(hash(checked(f,files,"override-original.php")).equals(text(r.path("settingsSha256"),"override")));
        validateDecryptControls(r,hash(data));
    }
    static Outcome compareKeyCapability(int usableDistinctKeys,boolean sourceClosedOneKeyEngine) {
        if(usableDistinctKeys>=2)return sourceClosedOneKeyEngine?Outcome.NOT_VERIFIED:Outcome.SATISFIED;
        return sourceClosedOneKeyEngine&&usableDistinctKeys==1?Outcome.VIOLATED:Outcome.NOT_VERIFIED;
    }
    static byte[] capabilityRemovedSource(byte[] nativeSource) {
        require(MESSAGE.equals(hash(nativeSource)));String source=new String(nativeSource,StandardCharsets.UTF_8);
        int from=source.indexOf(START),to=source.indexOf(END);require(from>=0&&to>from&&source.indexOf(START,from+1)<0&&source.indexOf(END,to+1)<0);
        String namespace="namespace SimpleSAML\\Module\\saml;";require(source.indexOf(namespace)==source.lastIndexOf(namespace));
        return (source.substring(0,from)+source.substring(to)).replace(namespace,"namespace SAMLscopeDiagnostic;").getBytes(StandardCharsets.UTF_8);
    }
    private List<String> verifiedKeys(JsonNode rows,byte[] challenge)throws Exception {
        require(rows.isArray()&&rows.size()<=2);var hashes=new ArrayList<String>();
        for(int i=0;i<rows.size();i++){var row=rows.get(i);require(row.path("index").asInt(-1)==i&&"RobRichards\\XMLSecLibs\\XMLSecurityKey".equals(text(row,"class")));
            byte[] spki=Base64.getDecoder().decode(text(row,"spkiBase64"));String sha=hash(spki);require(sha.equals(text(row,"spkiSha256"))&&!hashes.contains(sha));
            var key=KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));var verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(key);verifier.update(challenge);
            require(verifier.verify(Base64.getDecoder().decode(text(row,"signatureBase64"))));hashes.add(sha);}
        return hashes;
    }
    private JsonNode signedObservation(Path f,JsonNode files,String file,int count)throws Exception {
        var envelope=node(f,files,file);require(envelope.size()==4&&"samlscope-native-key-observation-signed-v1".equals(text(envelope,"schema")));
        byte[] payload=Base64.getDecoder().decode(text(envelope,"payloadBase64"));require(payload.length<=1048576&&hash(payload).equals(text(envelope,"payloadSha256")));
        var report=json.readTree(payload);var signatures=envelope.path("signatures");require(signatures.isArray()&&signatures.size()==count);
        var oldKeys=new TargetMetadataParser().parse(checked(f,files,"target-metadata.xml"),TARGET).signingCertificates();
        var generated=certificate(checked(f,files,"new-public-certificate.pem"));
        var selected=new ArrayList<PublicKey>();
        for(int index=0;index<count;index++){var signature=signatures.get(index);require(signature.path("keyIndex").asInt(-1)==index);String sha=text(signature,"spkiSha256");
            PublicKey key;
            if(count==2&&index==0){key=generated.getPublicKey();require(hash(key.getEncoded()).equals(sha));}
            else {var matches=oldKeys.stream().filter(k->sha.equals(hash(k.getPublicKey().getEncoded()))).toList();require(matches.size()==1);key=matches.getFirst().getPublicKey();}
            selected.add(key);}
        verifyPayloadSignatures(payload,report,signatures,selected);
        return report;
    }
    static void verifyPayloadSignatures(byte[] payload,JsonNode report,JsonNode signatures,List<PublicKey> selected)throws Exception {
        var rows=report.path(selected.size()==2?"baselineKeys":"keys");
        verifyPayloadSignaturesWithRows(payload,rows,signatures,selected);
    }
    static void verifyPayloadSignaturesWithRows(byte[] payload,JsonNode rows,JsonNode signatures,List<PublicKey> selected)throws Exception {
        require(rows.isArray()&&rows.size()==selected.size()&&signatures.size()==selected.size());
        var seen=new HashSet<String>();
        for(int index=0;index<selected.size();index++){
            var signature=signatures.get(index);String sha=text(signature,"spkiSha256");
            require(signature.path("keyIndex").asInt(-1)==index&&sha.equals(text(rows.get(index),"spkiSha256"))
                &&sha.equals(hash(selected.get(index).getEncoded()))&&seen.add(sha));
            var verifier=Signature.getInstance("SHA256withRSA");verifier.initVerify(selected.get(index));verifier.update(payload);
            require(verifier.verify(Base64.getDecoder().decode(text(signature,"signatureBase64"))));
        }
    }
    private void validateDecryptControls(JsonNode report,String challengeSha) {
        var controls=report.path("decryptionControls");require(controls.isArray()&&controls.size()==2);
        for(int index=0;index<2;index++){var row=controls.get(index);require(row.path("encryptionKeyIndex").asInt(-1)==index);
            byte[] xml=Base64.getDecoder().decode(text(row,"encryptedRequestBase64"));require(hash(xml).equals(text(row,"encryptedRequestSha256")));
            var root=SecureXml.parse(xml).getDocumentElement();require("LogoutRequest".equals(root.getLocalName())&&"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                &&root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","EncryptedID").getLength()==1
                &&root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion","NameID").getLength()==0);
            var attempts=row.path("attempts");require(attempts.isArray()&&attempts.size()==3);var labels=new HashSet<String>();
            for(var attempt:attempts){String engine=text(attempt,"engine");int key=attempt.path("keyIndex").asInt(-1);require(labels.add(engine+":"+key));
                boolean success=engine.equals("baseline")?key==index:engine.equals("capability-removed")&&index==1&&key==0;
                require(attempt.path("decrypted").isBoolean()&&attempt.path("decrypted").booleanValue()==success);
                if(success)require(("urn:samlscope:configuration-key-control:"+challengeSha).equals(text(attempt,"nameId"))&&"urn:oasis:names:tc:SAML:2.0:nameid-format:transient".equals(text(attempt,"format")));
                else require(attempt.path("exceptionClass").isTextual()&&!attempt.has("nameId"));}
            require(labels.equals(Set.of("baseline:0","baseline:1","capability-removed:0")));}
    }
    public static JsonNode stable(JsonNode snapshot){var copy=((ObjectNode)snapshot).deepCopy();copy.remove(List.of("runDocumentSha256","caseExecutionSha256"));return copy;}
    static Map<String,String> nativeClassDigests(){return SOURCES;}
    /** Expected failed native decryptions log diagnostics. They do not supply the oracle:
     * the signed, independently verified success/failure matrix remains authoritative. */
    static void verifyDecryptionDiagnostics(byte[] raw,JsonNode report) {
        int failures=0,successes=0;
        var controls=report.path("decryptionControls");require(controls.isArray()&&controls.size()==2);
        for(var control:controls)for(var attempt:control.path("attempts")) {
            require(attempt.path("decrypted").isBoolean());
            if(attempt.path("decrypted").booleanValue())successes++;else failures++;
        }
        require(failures==3&&successes==3&&raw.length<=16384);
        String value=new String(raw,StandardCharsets.UTF_8);require(Arrays.equals(raw,value.getBytes(StandardCharsets.UTF_8)));
        var lines=value.lines().toList();require(lines.size()==failures*3);
        String correlation=null;
        var first=java.util.regex.Pattern.compile("%date\\{M j H:i:s\\} simplesamlphp ERR \\[([A-Za-z0-9]+)\\] Failed to decrypt symmetric key: Failure decrypting Data \\(openssl private\\) - error:(?:02000079:rsa routines::oaep decoding error|0200006C:rsa routines::data greater than mod len)");
        for(int i=0;i<failures;i++) {
            var match=first.matcher(lines.get(i*3));require(match.matches()&&match.group(1).matches("CL[0-9a-f]{8}"));
            if(correlation==null)correlation=match.group(1);require(correlation.equals(match.group(1)));
            String parser=lines.get(i*3+1),prefix="%date{M j H:i:s} simplesamlphp ERR ["+correlation+"] Decryption failed: Unable to parse XML - ";
            require(parser.startsWith(prefix));String diagnostic=parser.substring(prefix.length());
            require(diagnostic.equals("\"FATAL[77]\": \"Premature end of data in tag root line 1")
                ||diagnostic.matches("\"FATAL\\[9\\]\": \"PCDATA invalid Char value (?:19|27)"));
            var location=java.util.regex.Pattern.compile("\" in \"\\(string\\)\" at line ([12]) on column ([1-9][0-9]*)\"").matcher(lines.get(i*3+2));
            require(location.matches());
        }
    }
    /** Only expiry diagnostics for literal Suite-owned peers in the restored native file qualify. */
    static void verifyExpiredMetadataWarnings(byte[] raw,byte[] remoteOriginal,Instant observedAt) {
        require(raw.length<=65536);String value=new String(raw,StandardCharsets.UTF_8);
        require(Arrays.equals(raw,value.getBytes(StandardCharsets.UTF_8)));if(value.isEmpty())return;
        String configuration=new String(remoteOriginal,StandardCharsets.UTF_8);
        var declaration=java.util.regex.Pattern.compile("(?m)^(?:\\$metadata\\[|  )'([^'\\r\\n]+)'(?:\\]\\s*=|\\s*=>)\\s*array\\s*\\(");
        var declarations=new ArrayList<java.util.regex.MatchResult>();var matcher=declaration.matcher(configuration);
        while(matcher.find())declarations.add(matcher.toMatchResult());
        var expiries=new HashMap<String,Instant>();
        for(int i=0;i<declarations.size();i++) {
            var match=declarations.get(i);String block=configuration.substring(match.end(),i+1<declarations.size()?declarations.get(i+1).start():configuration.length());
            if(!match.group(1).matches("http://localhost:18080/p/plan_[0-9A-HJKMNP-TV-Z]{26}(?:/[A-Za-z0-9_/-]+)?"))continue;
            var expiration=java.util.regex.Pattern.compile("'expire'\\s*=>\\s*([0-9]+)").matcher(block);
            if(expiration.find()){Instant at=Instant.ofEpochSecond(Long.parseLong(expiration.group(1)));require(!expiration.find()&&expiries.put(match.group(1),at)==null);}
        }
        var warning=java.util.regex.Pattern.compile("%date\\{M j H:i:s\\} simplesamlphp WARNING \\[CL[0-9a-f]{8}\\] Dropping metadata entity '([^']+)', expired ([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z)\\.");
        var seen=new HashSet<String>();
        for(String line:value.lines().toList()) {
            var match=warning.matcher(line);require(match.matches());Instant expired=Instant.parse(match.group(2));
            require(seen.add(match.group(1))&&expired.equals(expiries.get(match.group(1)))&&!expired.isAfter(observedAt));
        }
    }
    private static JsonNode operation(JsonNode operations,String label){JsonNode found=null;for(var op:operations)if(label.equals(op.path("label").asText())){require(found==null);found=op;}require(found!=null);return found;}
    private JsonNode node(Path f,JsonNode files,String name)throws Exception{return json.readTree(checked(f,files,name));}
    private byte[] checked(Path f,JsonNode files,String name)throws Exception{byte[] raw=original(f,name);require(hash(raw).equals(text(files,name)));return raw;}
    private byte[] original(Path f,String name)throws Exception{require(name.matches("[A-Za-z0-9_./-]+")&&!name.contains("..")&&!name.startsWith("/"));Path p=f.resolve(name).normalize();require(p.startsWith(f)&&!p.equals(f));safe(p);require(Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)&&Files.size(p)<=8388608);return Files.readAllBytes(p);}
    private static void safe(Path p){for(Path a=p;a!=null;a=a.getParent())require(!Files.isSymbolicLink(a));}
    private static String text(JsonNode value,String name){var v=value.get(name);require(v!=null&&v.isTextual()&&!v.asText().isBlank());return v.asText();}
    private static String hash(byte[] raw){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}catch(Exception impossible){throw new IllegalArgumentException(impossible);}}
    private static X509Certificate certificate(byte[] raw)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(raw));}
    private static Instant at(JsonNode v,String field){return Instant.parse(text(v,field));}
    private static byte[] concat(byte[] a,byte[] b){byte[] result=Arrays.copyOf(a,a.length+b.length);System.arraycopy(b,0,result,a.length,b.length);return result;}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native multiple-decryption-key capability unproven");}
}
