package com.samlscope.runner.cases;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.X509EncodedKeySpec;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** Explicit independent CONFIG completion for the one approved zero-protocol native obligation.
 * The source remains incomplete and read only; the actual recipient must already be complete.
 * No stored result, incomplete transcript flag, or manual declaration supplies native proof. */
public final class NativeConfigurationSourceRunEvidence {
    public static final String SCHEMA = "samlscope-native-configuration-source-run-v1";
    public static final String SCOPE = "independent-multiple-decryption-key-configuration";
    public static final String REASON = "configuration.multiple-decryption-keys.source-run-native-proven";
    static final String TARGET_IDENTITY_RULE = "idp19b-generated-key-rotation-and-same-url-post-v1";
    private static final String CURRENT_TIME_SOURCE="/var/simplesamlphp/src/SimpleSAML/Utils/Time.php";
    private static final String CURRENT_TIME_SHA="875c9d6d4d1eb88382427551d8e227d508495994d6f9ecd49bae694859c51614";
    static final String CURRENT_HELPER_SHA = "f04858bcb9b310467169ca12efadd68ca2e5e61b9a82acf22e5d4af890ff1851";
    private static final String CASE = SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE;
    private static final String DIGEST = SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST;
    private final Path data, directory, sourceDirectory;
    private final DefaultAlgorithmSourceRunStore store;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final SimpleSamlPhpMultipleDecryptionKeysEvidence sourceReader;
    private final ObjectMapper json = new JsonCodec().mapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public NativeConfigurationSourceRunEvidence(Path data, Path directory, Path sourceDirectory,
            TranscriptContentReader content, Function<String, byte[]> metadata) {
        this.data = Objects.requireNonNull(data).toAbsolutePath().normalize();
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        this.sourceDirectory = Objects.requireNonNull(sourceDirectory).toAbsolutePath().normalize();
        this.content = Objects.requireNonNull(content); this.metadata = Objects.requireNonNull(metadata);
        store = new DefaultAlgorithmSourceRunStore(this.data, CASE, DIGEST);
        sourceReader = new SimpleSamlPhpMultipleDecryptionKeysEvidence(this.sourceDirectory, content, metadata, store);
    }

    public boolean exists(String run) {
        return run != null && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.exists(directory.resolve(run), LinkOption.NOFOLLOW_LINKS);
    }

    public Optional<CaseOutcome> read(CaseContext recipient) {
        if (!exists(recipient.runId())) return Optional.empty();
        try { return Optional.of(verified(recipient)); }
        catch (Exception unproven) { return Optional.of(CaseOutcome.notVerified(
                "native_configuration_source_binding_unproven", "configuration.source-run.native-unproven")); }
    }

    CaseOutcome verified(CaseContext recipient) throws Exception {
        require(recipient.transcriptComplete() && recipient.targetRole() == TargetRole.IDP);
        Path folder = directory.resolve(recipient.runId()); byte[] raw = original(folder, "manifest.json");
        JsonNode m = json.readTree(raw);
        require(SCHEMA.equals(text(m, "schema")) && SCOPE.equals(text(m, "scope"))
                && CASE.equals(text(m, "caseId")) && DIGEST.equals(text(m, "caseDigest"))
                && recipient.runId().equals(text(m, "runId"))
                && "single_logout_idp".equals(text(m, "profile"))
                && "single_logout_idp".equals(text(m, "sourceProfile"))
                && Boolean.FALSE.equals(m.path("sourceTranscriptComplete").booleanValue())
                && m.path("sourceTranscriptComplete").isBoolean()
                && m.path("recipientProtocolOperationsClaimed").isInt()
                && m.path("recipientProtocolOperationsClaimed").intValue() == 0);
        String sourceRun = text(m, "sourceRunId");
        require(sourceRun.matches("run_[0-9A-HJKMNP-TV-Z]{26}") && !sourceRun.equals(recipient.runId()));
        var current = store.execution(recipient.runId()); var source = store.planned(sourceRun);
        require(current.run().status() == RunStatus.COMPLETED && source.run().status() == RunStatus.RUNNING
                && !source.snapshot().has("caseExecutionSha256")
                && current.plan().profile().id().equals(text(m, "profile"))
                && source.plan().profile().id().equals(text(m, "sourceProfile"))
                && current.plan().id().equals(text(m, "planId"))
                && source.plan().id().equals(text(m, "sourcePlanId"))
                && current.plan().parameters().equals(recipient.parameters())
                && current.plan().interaction().equals(recipient.interaction())
                && current.run().targetToSuiteReachability() == recipient.reachability()
                && current.plan().target().entityId().equals(text(m, "targetEntityId"))
                && source.plan().target().entityId().equals(text(m, "targetEntityId")));
        var files = m.path("files"); require(files.isObject() && files.size() >= 8 && files.size() <= 32);
        var names = files.fieldNames(); long total = 0;
        while (names.hasNext()) { String name = names.next(); byte[] bytes = checked(folder, files, name);
            total += bytes.length; require(total <= 16_777_216); }
        byte[] sourceTarget = metadata.apply(sourceRun), currentTarget = metadata.apply(recipient.runId());
        require(sourceTarget != null && currentTarget != null
                && Arrays.equals(sourceTarget, checked(folder, files, "source-target-metadata.xml"))
                && Arrays.equals(currentTarget, checked(folder, files, "target-metadata.xml"))
                && hash(sourceTarget).equals(text(m, "targetMetadataSha256"))
                && hash(currentTarget).equals(text(m, "recipientTargetMetadataSha256"))
                && text(m, "targetEntityId").equals(SecureXml.parse(sourceTarget).getDocumentElement().getAttribute("entityID")));
        Path sourceFolder = sourceDirectory.resolve(sourceRun + SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX);
        byte[] sourceManifest = original(sourceFolder, "manifest.json");
        require(hash(sourceManifest).equals(text(m, "sourceManifestSha256")));
        var sourceFiles = json.readTree(sourceManifest).path("files"); require(sourceFiles.isObject());
        var sourceHistory = recipient.transcript().listBounded(sourceRun, 10_000);
        var recipientHistory = recipient.transcript().listBounded(recipient.runId(), 10_000);
        require(sourceHistory.size() == 2 && sourceHistory.stream().allMatch(e ->
                Set.of("MetadataFetch", "MetadataPrepared").contains(e.samlSummary().get("type"))));
        var fence = json.readTree(checked(folder, files, "binding-fence.json"));
        require(fence.path("sourceExecutions").isObject()&&fence.path("sourceExecutions").isEmpty()
                &&fence.equals(fence(source, current, sourceHistory, recipientHistory)));
        var sourceRecorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) { require(sourceRun.equals(id)); return List.copyOf(sourceHistory); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException("Source originals are read only"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                throw new UnsupportedOperationException("Source originals are read only"); }
        };
        var sourceContext = new DefaultCaseContext(sourceRun, source.plan().profile().role(), recipient.clock(),
                source.plan().parameters(), source.plan().interaction(), source.run().targetToSuiteReachability(),
                sourceRecorder, false);
        // This invokes every original native signature, source, control, restoration and history check.
        var observed = sourceReader.readIndependentConfigurationSource(sourceContext,hash(sourceManifest)).orElseThrow();
        require(observed.outcome() == Outcome.SATISFIED && SimpleSamlPhpMultipleDecryptionKeysEvidence.REASON.equals(observed.reasonCode())
                && sourceRun.equals(observed.details().get("run_id"))
                && hash(sourceManifest).equals(observed.details().get("native_manifest_sha256"))
                && Boolean.TRUE.equals(observed.details().get("capability_removal_control_verified"))
                && Boolean.TRUE.equals(observed.details().get("configuration_restored")));
        var identity = targetIdentity(sourceTarget, currentTarget, checked(sourceFolder, sourceFiles, "new-public-certificate.pem"),
                json.readTree(checked(sourceFolder, sourceFiles, "native-before.json")),
                json.readTree(checked(sourceFolder, sourceFiles, "native-restored.json")));
        require(identity.equals(json.readTree(checked(folder, files, "target-identity.json")))
                && hash(checked(folder, files, "target-identity.json")).equals(text(m, "targetIdentitySha256")));
        var recipientIdentity=recipientIdentityOriginals(current,recipientHistory,currentTarget);
        var live = currentReadback(folder, files, m, sourceFolder, sourceFiles, identity, fence, source.plan().id());
        var counts = json.readTree(checked(sourceFolder, sourceFiles, "operation-counts.json"));
        var refs = new ArrayList<EvidenceRef>();
        refs.add(new EvidenceRef("native-configuration-source-run", recipient.runId() + "/manifest.json#sha256=" + hash(raw)));
        for(var entry:recipientIdentity)refs.add(new EvidenceRef("transcript",entry.id()));
        for (var ref : observed.evidence()) refs.add(new EvidenceRef("source-run-" + ref.kind(),
                ref.reference().startsWith(sourceRun) ? ref.reference() : sourceRun + "/" + ref.reference()));
        var details = new LinkedHashMap<>(observed.details());
        details.put("source_run_id", sourceRun); details.put("source_plan_id", source.plan().id());
        details.put("adoption_run_id", recipient.runId()); details.put("adoption_plan_id", current.plan().id());
        details.put("binding_scope", SCOPE); details.put("binding_sha256", hash(raw));
        details.put("source_transcript_complete", false); details.put("independent_configuration_completion", true);
        details.put("source_manifest_sha256", hash(sourceManifest)); details.put("source_operation_counts", json.convertValue(counts, Map.class));
        details.put("source_target_metadata_sha256", hash(sourceTarget)); details.put("recipient_target_metadata_sha256", hash(currentTarget));
        details.put("recipient_identity_original_kind","signed-normal-sso-response");
        details.put("recipient_identity_original_references",recipientIdentity.stream().map(TranscriptEntry::id).toList());
        details.put("recipient_identity_is_configuration_or_consumption_oracle",false);
        details.put("target_identity", json.convertValue(identity, Map.class));
        details.put("current_native_runtime_epoch", json.convertValue(live, Map.class));
        details.put("current_only_dependency_supplement",Map.of("file",CURRENT_TIME_SOURCE,"sha256",CURRENT_TIME_SHA,
                "bytes",5460,"purpose","Native expired-metadata warning timestamp formatting; not historical source closure"));
        details.put("new_login_operations", 0); details.put("recipient_protocol_operations_claimed", 0);
        var sourceNames=sourceFiles.fieldNames();while(sourceNames.hasNext())checked(sourceFolder,sourceFiles,sourceNames.next());
        require(Arrays.equals(sourceManifest,original(sourceFolder,"manifest.json"))
                &&Arrays.equals(raw, original(folder, "manifest.json"))
                && fence.equals(fence(store.planned(sourceRun), store.execution(recipient.runId()),
                        recipient.transcript().listBounded(sourceRun, 10_000),
                        recipient.transcript().listBounded(recipient.runId(), 10_000))));
        return new CaseOutcome(Outcome.SATISFIED, null, REASON, REASON, List.copyOf(refs), details);
    }

    List<TranscriptEntry> recipientIdentityOriginals(DefaultAlgorithmSourceRunStore.Binding recipient,
            List<TranscriptEntry> history,byte[] target)throws Exception {
        final String protocol="urn:oasis:names:tc:SAML:2.0:protocol",assertion="urn:oasis:names:tc:SAML:2.0:assertion";
        String run=recipient.run().id(),peer="http://localhost:18080/p/"+recipient.plan().id(),acs=peer+"/sp/acs/0";
        var targetRoot=SecureXml.parse(target).getDocumentElement();var descriptor=elements(targetRoot).getFirst();
        byte[] der=keyCertificate(elements(descriptor).getFirst(),"signing","http://www.w3.org/2000/09/xmldsig#");
        var certificate=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(der));
        var candidates=new ArrayList<List<TranscriptEntry>>();
        for(var response:history)if(run.equals(response.runId())&&response.direction()==Direction.INBOUND
                &&"POST".equals(response.method())&&acs.equals(response.url())&&"Response".equals(response.samlSummary().get("type"))
                &&Boolean.TRUE.equals(response.samlSummary().get("normalFlowAccepted"))) {
            var root=SecureXml.parse(content.readDecodedSaml(response)).getDocumentElement();
            require(name(root).equals("{"+protocol+"}Response")&&"2.0".equals(root.getAttribute("Version"))
                    &&root.getAttribute("ID").equals(response.samlSummary().get("id"))
                    &&acs.equals(root.getAttribute("Destination"))&&recipient.plan().target().entityId().equals(direct(root,assertion,"Issuer").getTextContent())
                    &&"urn:oasis:names:tc:SAML:2.0:status:Success".equals(direct(direct(root,protocol,"Status"),protocol,"StatusCode").getAttribute("Value"))
                    &&com.samlscope.saml.normal.SamlSchemaValidation.isValid(root,com.samlscope.saml.normal.SamlSchemaValidation.SchemaKind.PROTOCOL)
                    &&direct(root,"http://www.w3.org/2000/09/xmldsig#","Signature")!=null
                    &&new com.samlscope.saml.crypto.XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(root)
                    &&new com.samlscope.saml.crypto.XmlSignatureVerifier().hasValidEnvelopedSignature(root,certificate));
            String requestId=root.getAttribute("InResponseTo");require(!requestId.isBlank()&&requestId.equals(response.correlationId()));
            var requests=history.stream().filter(e->run.equals(e.runId())&&e.direction()==Direction.OUTBOUND
                    &&"AuthnRequest".equals(e.samlSummary().get("type"))&&requestId.equals(e.correlationId())
                    &&requestId.equals(e.samlSummary().get("id"))).toList();require(requests.size()==1);
            var request=requests.getFirst();byte[] requestBytes=content.readDecodedSaml(request);var requestRoot=SecureXml.parse(requestBytes).getDocumentElement();
            String destination=requestRoot.getAttribute("Destination");
            require(name(requestRoot).equals("{"+protocol+"}AuthnRequest")&&"2.0".equals(requestRoot.getAttribute("Version"))
                    &&requestId.equals(requestRoot.getAttribute("ID"))&&peer.equals(direct(requestRoot,assertion,"Issuer").getTextContent())
                    &&acs.equals(requestRoot.getAttribute("AssertionConsumerServiceURL"))
                    &&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(requestRoot.getAttribute("ProtocolBinding"))
                    &&request.timestamp().isBefore(response.timestamp())
                    &&com.samlscope.saml.normal.SamlSchemaValidation.isValid(requestRoot,com.samlscope.saml.normal.SamlSchemaValidation.SchemaKind.PROTOCOL)
                    &&new com.samlscope.saml.metadata.TargetMetadataParser().parse(target,recipient.plan().target().entityId()).singleSignOnServices().stream()
                        .anyMatch(e->e.location().toString().equals(destination)&&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(e.binding()))
                    &&"GET".equals(request.method())&&request.url().startsWith(destination+"?")
                    &&new com.samlscope.saml.binding.RedirectSignatureVerifier().matchesMessage(java.net.URI.create(request.url()).getRawQuery(),requestBytes));
            candidates.add(List.of(request,response));
        }
        require(candidates.size()==1);return candidates.getFirst();
    }
    private static Element direct(Element parent,String namespace,String local) {
        var children=elements(parent).stream().filter(e->namespace.equals(e.getNamespaceURI())&&local.equals(e.getLocalName())).toList();
        require(children.size()==1);return children.getFirst();
    }

    /** Whole source and recipient history. Only the recipient's own case result may advance. */
    public JsonNode fence(DefaultAlgorithmSourceRunStore.Binding source, DefaultAlgorithmSourceRunStore.Binding recipient,
            List<TranscriptEntry> sourceHistory, List<TranscriptEntry> recipientHistory) throws Exception {
        var result = json.createObjectNode(); result.set("sourceStore", source.snapshot());
        var destination = ((ObjectNode)recipient.snapshot()).deepCopy(); destination.remove("caseExecutionSha256");
        result.set("recipientStore", destination);
        result.set("sourceHistory", store.history(source.run().id(), sourceHistory, content));
        result.set("recipientHistory", store.history(recipient.run().id(), recipientHistory, content));
        result.set("sourceExecutions", executions(source.run().id(), null));
        result.set("recipientOtherExecutions", executions(recipient.run().id(), CASE));
        byte[] sourceMetadata=metadata.apply(source.run().id()),recipientMetadata=metadata.apply(recipient.run().id());
        require(sourceMetadata!=null&&recipientMetadata!=null);
        result.put("sourceTargetMetadataSha256",hash(sourceMetadata));
        result.put("recipientTargetMetadataSha256",hash(recipientMetadata));
        return result;
    }

    private JsonNode executions(String run, String excluded) throws Exception {
        var result = json.createObjectNode();
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + data.resolve("samlscope.db") + "?mode=ro");
                var query = connection.prepareStatement("SELECT case_id,revision,status,document_json FROM case_executions WHERE run_id=? ORDER BY case_id")) {
            query.setString(1, run); try (var rows = query.executeQuery()) {
                while (rows.next()) {
                    String id = rows.getString(1), raw = rows.getString(4); var execution = json.readValue(raw, CaseExecution.class);
                    require(run.equals(execution.runId()) && id.equals(execution.caseId())
                            && execution.revision() == rows.getLong(2) && execution.status().name().equals(rows.getString(3)));
                    if (!id.equals(excluded)) { require(!result.has(id)); result.put(id, hash(raw.getBytes(StandardCharsets.UTF_8))); }
                }
            }
        }
        return result;
    }

    private JsonNode currentReadback(Path folder, JsonNode files, JsonNode manifest, Path sourceFolder,
            JsonNode sourceFiles, JsonNode identity, JsonNode fence, String sourcePlan) throws Exception {
        byte[] helper = checked(folder, files, "current-helper.php"); require(CURRENT_HELPER_SHA.equals(hash(helper)));
        byte[] inputBytes = checked(folder, files, "current-input.json"); var input = json.readTree(inputBytes);
        var expected = json.createObjectNode();
        expected.put("sourceRunId", text(manifest, "sourceRunId")); expected.put("recipientRunId", text(manifest, "runId"));
        expected.put("caseDigest", DIGEST); expected.put("targetEntityId", text(manifest, "targetEntityId"));
        expected.put("sourcePeerEntityId", "http://localhost:18080/p/" + sourcePlan);
        expected.put("sourceTargetMetadataSha256", text(manifest, "targetMetadataSha256"));
        expected.put("recipientTargetMetadataSha256", text(manifest, "recipientTargetMetadataSha256"));
        expected.put("targetIdentitySha256", text(manifest, "targetIdentitySha256"));
        expected.put("sourceManifestSha256", text(manifest, "sourceManifestSha256"));
        expected.put("bindingFenceSha256", hash(checked(folder, files, "binding-fence.json"))); require(expected.equals(input));
        byte[] envelopeBytes = checked(folder, files, "current-envelope.json"); var envelope = json.readTree(envelopeBytes);
        require("samlscope-native-key-observation-signed-v1".equals(text(envelope, "schema")));
        byte[] payload = Base64.getDecoder().decode(text(envelope, "payloadBase64")); require(hash(payload).equals(text(envelope, "payloadSha256")));
        var report = json.readTree(payload);
        require("samlscope-native-configuration-source-current-v1".equals(text(report, "schema"))
                && input.equals(report.path("input")) && hash(inputBytes).equals(text(report, "inputSha256"))
                && report.path("effectiveUid").asInt(-1) == 33
                && report.path("sourcePeerPresent").isBoolean() && !report.path("sourcePeerPresent").booleanValue()
                && report.path("newPrivateKey").isNull() && report.path("newCertificate").isNull()
                && report.path("privateMaterialPersisted").isBoolean() && !report.path("privateMaterialPersisted").booleanValue()
                && "SimpleSAML\\Module\\saml\\Message::getDecryptionKeys".equals(text(report, "nativeMethod")));
        var before = json.readTree(checked(sourceFolder, sourceFiles, "native-before.json"));
        require(before.path("loadedClasses").equals(report.path("loadedClasses")));
        require(before.path("phpVersion").equals(report.path("phpVersion"))
                && before.path("opensslVersion").equals(report.path("opensslVersion"))
                && report.path("metadataSources").equals(json.readTree("[{\"type\":\"flatfile\"}]")));
        var historicalDependencies = new HashMap<String,JsonNode>();
        for(var dependency:before.path("dependencies")) require(historicalDependencies.put(text(dependency,"file"),dependency)==null);
        var currentDependencies=report.path("dependencies");require(currentDependencies.isArray()&&currentDependencies.size()>10&&currentDependencies.size()<=256);
        String previous="";var included=new HashSet<String>();boolean currentTime=false;
        for(var dependency:currentDependencies) {
            String path=text(dependency,"file"),sha=text(dependency,"sha256");
            require(path.compareTo(previous)>0&&included.add(path));previous=path;byte[] bytes;
            if(historicalDependencies.containsKey(path)) {
                require(dependency.equals(historicalDependencies.get(path)));
                bytes=checked(sourceFolder,sourceFiles,"native-dependencies/"+sha+".php");
            } else {
                require(!currentTime&&CURRENT_TIME_SOURCE.equals(path)&&CURRENT_TIME_SHA.equals(sha)
                        &&dependency.path("bytes").asInt(-1)==5460&&dependency.size()==3);
                currentTime=true;bytes=checked(folder,files,"current-time-source.php");
            }
            require(hash(bytes).equals(sha)&&bytes.length==dependency.path("bytes").asInt(-1));
        }
        require(currentTime);
        for(var c:report.path("loadedClasses"))require(included.contains(text(c,"file")));
        for (String name : List.of("hosted", "remote", "override")) {
            String original = name.equals("override") ? "override-original.php" : name + "-original.php";
            require(hash(checked(sourceFolder, sourceFiles, original)).equals(text(report.path("settingsSha256"), name)));
        }
        var rows = report.path("baselineKeys"); require(rows.isArray() && rows.size() == 1 && rows.get(0).path("index").asInt(-1) == 0);
        byte[] spki = Base64.getDecoder().decode(text(rows.get(0), "spkiBase64"));
        var key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
        require(hash(spki).equals(text(rows.get(0), "spkiSha256"))
                && text(before.path("baselineKeys").get(1), "spkiSha256").equals(hash(spki)));
        byte[] certificateBytes = Base64.getDecoder().decode(text(report, "certificateDerBase64"));
        var certificate = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(certificateBytes));
        require(Arrays.equals(certificate.getEncoded(), certificateBytes)
                && hash(certificateBytes).equals(text(report, "certificateSha256"))
                && hash(certificateBytes).equals(text(identity, "restoredCertificateSha256"))
                && Arrays.equals(certificate.getPublicKey().getEncoded(), spki));
        SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignaturesWithRows(payload, rows, envelope.path("signatures"), List.of(key));
        var currentBefore = json.readTree(checked(folder, files, "current-runtime-before.json"));
        var currentAfter = json.readTree(checked(folder, files, "current-runtime-after.json"));
        var historical = json.readTree(checked(sourceFolder, sourceFiles, "runtime-before.json"));
        require(normalizedRuntime(currentBefore).equals(normalizedRuntime(currentAfter)) && historical.path("imageId").equals(currentBefore.path("imageId"))
                && currentBefore.path("running").isBoolean() && currentBefore.path("running").booleanValue()
                && text(currentBefore, "containerId").matches("[0-9a-f]{64}")
                && currentBefore.path("mounts").isArray()
                && Instant.parse(text(currentBefore, "startedAt")).isBefore(numberTime(report.path("nativeStartedAt"))));
        var mountDestinations=new HashSet<String>();
        for(var mount:currentBefore.path("mounts")) {
            require(mount.isObject()&&Set.of("bind","volume","tmpfs").contains(text(mount,"Type"))
                    &&text(mount,"Destination").startsWith("/")&&mountDestinations.add(text(mount,"Destination")));
            String destination=text(mount,"Destination");
            for(String namespace:List.of("/var/simplesamlphp/src","/var/simplesamlphp/vendor","/var/simplesamlphp/modules","/var/simplesamlphp/lib"))
                require(!destination.equals(namespace)&&!destination.startsWith(namespace+"/")&&!namespace.startsWith(destination.endsWith("/")?destination:destination+"/"));
        }
        validateCurrentOperations(json.readTree(checked(folder, files, "current-operations.json")), helper, inputBytes,
                envelopeBytes, report, currentBefore, currentAfter, folder, files, sourceFiles);
        validateCurrentTimeSupplement(folder,files,currentBefore,numberTime(report.path("nativeFinishedAt")));
        return currentBefore;
    }

    private void validateCurrentTimeSupplement(Path folder,JsonNode files,JsonNode runtime,Instant nativeFinished)throws Exception {
        byte[] source=checked(folder,files,"current-time-source.php");require(source.length==5460&&hash(source).equals(CURRENT_TIME_SHA));
        var operations=json.readTree(checked(folder,files,"current-time-source-operations.json"));
        require(operations.isArray()&&operations.size()==3);Instant last=nativeFinished;
        for(int i=0;i<3;i++) {
            var op=operations.get(i);String label=i==1?"public-time-source":i==0?"runtime-before":"runtime-after";
            require(label.equals(text(op,"label"))&&op.path("exitCode").asInt(-1)==0
                    &&hash(new byte[0]).equals(text(op,"stderrSha256")));
            Instant start=Instant.parse(text(op,"startedAt")),end=Instant.parse(text(op,"finishedAt"));
            require(!start.isBefore(last)&&!end.isBefore(start));last=end;
            if(i==1)require(strings(op.path("command")).equals(List.of("docker","exec","samlscope-reference-ssp","cat",CURRENT_TIME_SOURCE))
                    &&CURRENT_TIME_SHA.equals(text(op,"stdoutSha256")));
            else {
                require(strings(op.path("command")).equals(List.of("docker","inspect","--format","{\"containerId\":{{json .Id}},\"imageId\":{{json .Image}},\"startedAt\":{{json .State.StartedAt}},\"running\":{{json .State.Running}},\"mounts\":{{json .Mounts}}}","samlscope-reference-ssp")));
                byte[] raw=checked(folder,files,"current-time-source-"+label+".stdout");
                require(hash(raw).equals(text(op,"stdoutSha256"))&&normalizedRuntime(runtime).equals(normalizedRuntime(json.readTree(raw))));
            }
        }
    }

    private void validateCurrentOperations(JsonNode ops, byte[] helper, byte[] input, byte[] envelope, JsonNode report,
            JsonNode runtimeBefore, JsonNode runtimeAfter, Path folder, JsonNode files, JsonNode sourceFiles) throws Exception {
        require(ops.isArray() && ops.size() == 6); var expected = List.of("runtime-before", "helper-write", "helper-readback", "native-readback", "helper-remove", "runtime-after");
        Instant last = null; String helperPath = null;
        for (int i = 0; i < expected.size(); i++) {
            var op = ops.get(i); require(expected.get(i).equals(text(op, "label")) && op.path("exitCode").asInt(-1) == 0);
            if(i!=3)require(hash(new byte[0]).equals(text(op,"stderrSha256")));
            Instant start = Instant.parse(text(op, "startedAt")), end = Instant.parse(text(op, "finishedAt"));
            require(!end.isBefore(start) && (last == null || !start.isBefore(last))); last = end;
            List<String> command = strings(op.path("command"));
            if (i == 1) { helperPath = command.getLast(); require(helperPath.matches("/tmp/samlscope-configuration-source-[0-9a-f]{24}\\.php")); }
            if (i == 0 || i == 5) {
                require(command.equals(List.of("docker", "inspect", "--format", "{\"containerId\":{{json .Id}},\"imageId\":{{json .Image}},\"startedAt\":{{json .State.StartedAt}},\"running\":{{json .State.Running}},\"mounts\":{{json .Mounts}}}", "samlscope-reference-ssp")));
                byte[] stdout = checked(folder, files, i == 0 ? "current-runtime-before.stdout" : "current-runtime-after.stdout");
                require(hash(stdout).equals(text(op, "stdoutSha256")) && (i == 0 ? runtimeBefore : runtimeAfter).equals(json.readTree(stdout)));
            } else if (i == 1) {
                require(command.equals(List.of("docker", "exec", "--user", "33", "-i", "samlscope-reference-ssp", "sh", "-c", "set -C; umask 077; test ! -e \"$1\" && test ! -L \"$1\" && cat > \"$1\"", "sh", helperPath))
                        && hash(helper).equals(text(op, "stdinSha256")));
            } else if (i == 2) {
                require(command.equals(List.of("docker", "exec", "samlscope-reference-ssp", "cat", helperPath)) && hash(helper).equals(text(op, "stdoutSha256")));
            } else if (i == 3) {
                require(command.equals(List.of("docker", "exec", "--user", "33", "-i", "samlscope-reference-ssp", "php", helperPath))
                        && hash(input).equals(text(op, "stdinSha256")) && hash(envelope).equals(text(op, "stdoutSha256"))
                        && hash(checked(folder,files,"current-native.stderr")).equals(text(op, "stderrSha256"))
                        && !numberTime(report.path("nativeStartedAt")).isBefore(start)
                        && !numberTime(report.path("nativeFinishedAt")).isBefore(numberTime(report.path("nativeStartedAt")))
                        && !numberTime(report.path("nativeFinishedAt")).isAfter(end));
                String sourceRun=report.path("input").path("sourceRunId").asText();
                SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyExpiredMetadataWarnings(checked(folder,files,"current-native.stderr"),
                        checked(sourceDirectory.resolve(sourceRun+SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX),sourceFiles,"remote-original.php"),end);
            } else {
                require(command.equals(List.of("docker", "exec", "--user", "33", "samlscope-reference-ssp", "php", "-r",
                        "if(is_link($argv[1])||!is_file($argv[1])||!unlink($argv[1])||file_exists($argv[1]))throw new RuntimeException(\"Helper cleanup failed\");", helperPath)));
            }
        }
    }

    /** Only the two independently reviewed differences of this CONFIG campaign are supported.
     * Raw metadata remains bound separately; this does not assert protocol consumption. */
    static JsonNode targetIdentity(byte[] source, byte[] recipient, byte[] generatedCertificate,
            JsonNode nativeBefore, JsonNode nativeRestored) throws Exception {
        final String md="urn:oasis:names:tc:SAML:2.0:metadata", ds="http://www.w3.org/2000/09/xmldsig#";
        var sourceRoot=SecureXml.parse(source).getDocumentElement();var recipientRoot=SecureXml.parse(recipient).getDocumentElement();
        require(name(sourceRoot).equals("{"+md+"}EntityDescriptor") && name(sourceRoot).equals(name(recipientRoot))
                && attributes(sourceRoot).equals(attributes(recipientRoot))
                && "http://localhost:18380/idp".equals(sourceRoot.getAttribute("entityID")));
        var sourceRootChildren=elements(sourceRoot);var recipientRootChildren=elements(recipientRoot);
        require(sourceRootChildren.size()==1&&recipientRootChildren.size()==1);
        var a=sourceRootChildren.getFirst();var b=recipientRootChildren.getFirst();
        require(name(a).equals("{"+md+"}IDPSSODescriptor")&&name(a).equals(name(b))&&attributes(a).equals(attributes(b)));
        var ac=elements(a);var bc=elements(b);require(ac.size()==bc.size()&&ac.size()>4);
        for(int i=0;i<3;i++)require(name(ac.get(i)).equals("{"+md+"}KeyDescriptor"));
        for(int i=0;i<2;i++)require(name(bc.get(i)).equals("{"+md+"}KeyDescriptor"));
        require(name(ac.get(3)).equals("{"+md+"}SingleLogoutService")
                &&name(bc.get(2)).equals("{"+md+"}SingleLogoutService")&&name(bc.get(3)).equals("{"+md+"}SingleLogoutService"));
        var generated=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(generatedCertificate));
        byte[] newDer=generated.getEncoded(),oldDer=keyCertificate(ac.get(2),"signing",ds);
        var old=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(oldDer));
        require(Arrays.equals(keyCertificate(ac.get(0),"signing",ds),newDer)
                &&Arrays.equals(keyCertificate(ac.get(1),"encryption",ds),newDer)
                &&Arrays.equals(keyCertificate(bc.get(0),"signing",ds),oldDer)
                &&Arrays.equals(keyCertificate(bc.get(1),"encryption",ds),oldDer)
                &&!Arrays.equals(newDer,oldDer));
        String newSpki=hash(generated.getPublicKey().getEncoded()),oldSpki=hash(old.getPublicKey().getEncoded());
        require(!newSpki.equals(oldSpki)&&nativeBefore.path("baselineKeys").size()==2&&nativeRestored.path("keys").size()==1
                &&newSpki.equals(text(nativeBefore.path("baselineKeys").get(0),"spkiSha256"))
                &&oldSpki.equals(text(nativeBefore.path("baselineKeys").get(1),"spkiSha256"))
                &&oldSpki.equals(text(nativeRestored.path("keys").get(0),"spkiSha256")));
        String location="http://localhost:18380/simplesaml/module.php/saml/idp/singleLogout";
        service(ac.get(3),"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",location);
        service(bc.get(2),"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",location);
        service(bc.get(3),"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",location);
        for(int i=4;i<ac.size();i++)require(!Set.of("{"+md+"}KeyDescriptor","{"+md+"}SingleLogoutService").contains(name(ac.get(i)))
                &&facts(ac.get(i)).equals(facts(bc.get(i))));
        require(meaningfulText(sourceRoot).isEmpty()&&meaningfulText(recipientRoot).isEmpty()
                &&meaningfulText(a).isEmpty()&&meaningfulText(b).isEmpty());
        var result=new JsonCodec().mapper().createObjectNode();result.put("rule",TARGET_IDENTITY_RULE);
        result.put("sourceTargetMetadataSha256",hash(source));result.put("recipientTargetMetadataSha256",hash(recipient));
        result.put("generatedCertificateSha256",hash(newDer));result.put("generatedSpkiSha256",newSpki);
        result.put("restoredCertificateSha256",hash(oldDer));result.put("restoredSpkiSha256",oldSpki);
        result.put("nativeConfigurationOnly",true);result.put("metadataConsumptionClaimed",false);
        return result;
    }
    private static String name(Element element) { return "{"+Objects.toString(element.getNamespaceURI(),"")+"}"+element.getLocalName(); }
    private static Map<String,String> attributes(Element element) {
        var result=new TreeMap<String,String>();var attrs=element.getAttributes();
        for(int i=0;i<attrs.getLength();i++){var a=attrs.item(i);String key="{"+Objects.toString(a.getNamespaceURI(),"")+"}"+Objects.toString(a.getLocalName(),a.getNodeName());require(result.put(key,a.getNodeValue())==null);}
        return result;
    }
    private static List<Element> elements(Element parent) {
        var result=new ArrayList<Element>();
        for(Node child=parent.getFirstChild();child!=null;child=child.getNextSibling()) {
            if(child.getNodeType()==Node.ELEMENT_NODE)result.add((Element)child);
            else require(child.getNodeType()==Node.TEXT_NODE);
        }
        return result;
    }
    private static List<String> meaningfulText(Element parent) {
        var result=new ArrayList<String>();
        for(Node child=parent.getFirstChild();child!=null;child=child.getNextSibling())
            if(child.getNodeType()==Node.TEXT_NODE&&!child.getNodeValue().isBlank())result.add(child.getNodeValue());
        return result;
    }
    private static Object facts(Element element) {
        var children=new ArrayList<Object>();
        for(Node child=element.getFirstChild();child!=null;child=child.getNextSibling()) {
            if(child.getNodeType()==Node.ELEMENT_NODE)children.add(facts((Element)child));
            else {require(child.getNodeType()==Node.TEXT_NODE);if(!child.getNodeValue().isBlank())children.add(child.getNodeValue());}
        }
        return List.of(name(element),attributes(element),children);
    }
    private static byte[] keyCertificate(Element descriptor,String use,String ds)throws Exception {
        require(attributes(descriptor).equals(Map.of("{}use",use))&&meaningfulText(descriptor).isEmpty());
        var children=elements(descriptor);require(children.size()==1);var info=children.getFirst();
        require(name(info).equals("{"+ds+"}KeyInfo")&&attributes(info).equals(Map.of("{http://www.w3.org/2000/xmlns/}ds",ds))&&meaningfulText(info).isEmpty());
        children=elements(info);require(children.size()==1);var data=children.getFirst();
        require(name(data).equals("{"+ds+"}X509Data")&&attributes(data).isEmpty()&&meaningfulText(data).isEmpty());
        children=elements(data);require(children.size()==1);var cert=children.getFirst();
        require(name(cert).equals("{"+ds+"}X509Certificate")&&attributes(cert).isEmpty()&&elements(cert).isEmpty());
        String encoded=cert.getTextContent();require(encoded.matches("[A-Za-z0-9+/=\\s]+"));
        byte[] der=Base64.getDecoder().decode(encoded.replaceAll("\\s",""));
        var parsed=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(der));
        require(Arrays.equals(parsed.getEncoded(),der));return der;
    }
    private static void service(Element element,String binding,String location) {
        require(attributes(element).equals(Map.of("{}Binding",binding,"{}Location",location))
                &&elements(element).isEmpty()&&meaningfulText(element).isEmpty());
    }

    static JsonNode normalizedRuntime(JsonNode runtime) {
        require(runtime.isObject() && runtime.path("mounts").isArray());
        var copy = (com.fasterxml.jackson.databind.node.ObjectNode) runtime.deepCopy();
        var mounts = new TreeMap<String, JsonNode>();
        for (var mount : runtime.path("mounts")) {
            require(mount.isObject() && mounts.put(text(mount, "Destination"), mount) == null);
        }
        var sorted = copy.putArray("mounts");
        mounts.values().forEach(sorted::add);
        return copy;
    }

    private static Instant numberTime(JsonNode node) {
        require(node.isNumber()); var value = node.decimalValue(); long seconds = value.longValue();
        return Instant.ofEpochSecond(seconds, value.subtract(java.math.BigDecimal.valueOf(seconds)).movePointRight(9).longValue());
    }
    private static List<String> strings(JsonNode rows) {
        require(rows.isArray()); var values = new ArrayList<String>(); for (var value : rows) { require(value.isTextual()); values.add(value.textValue()); } return values;
    }
    private byte[] checked(Path folder, JsonNode files, String name) throws Exception {
        byte[] bytes = original(folder, name); require(hash(bytes).equals(text(files, name))); return bytes;
    }
    static byte[] original(Path folder, String name) throws Exception {
        require(name.matches("[A-Za-z0-9_./-]+") && !name.startsWith("/") && !name.contains(".."));
        Path path = folder.resolve(name).normalize(); require(path.startsWith(folder) && !path.equals(folder));
        DefaultAlgorithmPreventionEvidence.safeParents(path); require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 8_388_608);
        return Files.readAllBytes(path);
    }
    static String hash(byte[] raw) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
    static String text(JsonNode node, String name) { var value = node.get(name); require(value != null && value.isTextual() && !value.textValue().isBlank()); return value.textValue(); }
    static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Independent native configuration source unproven"); }
}
