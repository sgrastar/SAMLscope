package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.store.JsonCodec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataRefreshConfigurationTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String ENTITY = "https://suite.example/p/" + PLAN;
    private static final String TARGET = "https://idp.example/sso";
    private static final String VARIANT_B = "no-valid-until";
    private static final int WAIT = 5;
    private static final Instant NOW = Instant.parse("2026-09-30T02:00:00Z");
    private static final String CONFIG = "<?php\n$config = [];\n";
    private static final String OVERLAY = "\n$config['metadata.sources'] = [['type'=>'flatfile'], "
            + "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>5]];\n";

    @TempDir Path temp;
    private final JsonCodec json = new JsonCodec();
    private final List<TranscriptEntry> entries = new ArrayList<>();
    private final Map<String, byte[]> bodies = new HashMap<>();
    private Path receipt;
    private ObjectNode manifest;
    private byte[] metadataA;
    private byte[] metadataB;

    @BeforeEach
    void setUp() throws Exception {
        var keys = new FilePlanKeyStore(temp.resolve("keys"), Clock.fixed(NOW, ZoneOffset.UTC));
        var keyA = keys.getOrCreate(PLAN, "refresh-a");
        var keyB = keys.getOrCreate(PLAN, "refresh-b");
        metadataA = metadata(keyA);
        metadataB = metadata(keyB);
        receipt = temp.resolve("evidence").resolve(RUN + ".refresh");
        Files.createDirectories(receipt);
        write("original-config.php", CONFIG.getBytes(StandardCharsets.UTF_8));
        write("configured-config.php", (CONFIG + OVERLAY).getBytes(StandardCharsets.UTF_8));
        write("final-config.php", CONFIG.getBytes(StandardCharsets.UTF_8));
        write("metadata-a.xml", metadataA);
        write("metadata-b.xml", metadataB);
        var rejection = "<html><body>SimpleSAML Error {\"errorCode\":\"NOTVALIDCERTSIGNATURE\","
                + "\"%ELEMENT%\":\"SAML2 XML samlp AuthnRequest\"}</body></html>";
        write("signature-control-response.html", rejection.getBytes(StandardCharsets.UTF_8));
        write("effective-source.json", jsonBytes(List.of(Map.of("type", "flatfile"),
                Map.of("type", "mdq", "server", "http://127.0.0.1:8081", "cachelength", WAIT))));
        write("operation-counts.json", jsonBytes(Map.of(
                "restored", true, "product_configuration_writes", 2,
                "restoration_writes", 1, "product_restarts", 0, "human_operations", 0)));
        runtime("start");
        runtime("end");
        addPhase(0, "control", keyA, metadataA, NOW);
        addPhase(1, VARIANT_B, keyB, metadataB, NOW.plusSeconds(2 + WAIT));
        var control = entries.stream().filter(value -> "control-b".equals(value.id())).findFirst().orElseThrow();
        write("signature-control.json", jsonBytes(Map.ofEntries(
                Map.entry("request_id", control.correlationId()),
                Map.entry("request_sha256", sha(bodies.get("control-b"))),
                Map.entry("request_url", TARGET), Map.entry("response_url", TARGET),
                Map.entry("response_url_exact_match", true), Map.entry("response_status", 500),
                Map.entry("response_body_sha256", sha(rejection.getBytes(StandardCharsets.UTF_8))),
                Map.entry("observed_at", NOW.plusSeconds(2 + WAIT).plusMillis(700).toString()),
                Map.entry("native_signature_rejection", "signature-value-invalid"),
                Map.entry("saml_response_form_present", false))));
        var proxy = (proxyLine("control", metadataA, NOW.plusMillis(500)) + "\n"
                + proxyLine(VARIANT_B, metadataB, NOW.plusSeconds(2 + WAIT).plusMillis(500)) + "\n")
                .getBytes(StandardCharsets.UTF_8);
        write("proxy-requests.jsonl", proxy);
        manifest = json.mapper().createObjectNode();
        manifest.put("schema", "samlscope-native-metadata-refresh-v1");
        manifest.put("runId", RUN);
        manifest.put("adapter", "simplesamlphp-native-mdq-refresh-v1");
        manifest.put("entityId", ENTITY);
        manifest.put("variantB", VARIANT_B);
        manifest.put("refreshWaitSeconds", WAIT);
        hashField("originalConfigSha256", "original-config.php");
        hashField("configuredConfigSha256", "configured-config.php");
        hashField("finalConfigSha256", "final-config.php");
        hashField("operationCountsSha256", "operation-counts.json");
        hashField("effectiveSourceSha256", "effective-source.json");
        hashField("targetRuntimeStartSha256", "target-runtime-start.json");
        hashField("targetRuntimeEndSha256", "target-runtime-end.json");
        hashField("metadataASha256", "metadata-a.xml");
        hashField("metadataBSha256", "metadata-b.xml");
        hashField("signatureControlSha256", "signature-control.json");
        hashField("signatureControlResponseSha256", "signature-control-response.html");
        hashField("proxyRequestsSha256", "proxy-requests.jsonl");
        manifest.set("phaseA", phase("control", 0));
        manifest.set("phaseB", phase(VARIANT_B, 1));
        saveManifest();
    }

    @Test
    void acceptsOnlyARefreshThatUsesTheChangedSigningKeyAfterTheApprovedWait() {
        var result = configure(testCase());
        assertEquals(Outcome.SATISFIED, result.outcome(), result.details().toString());
        assertEquals(true, result.details().get("changed_signing_key_used"));
        assertEquals(10, result.evidence().size());
    }

    @Test
    void rejectsAnEarlySecondFetchEvenWhenBothFlowsSucceed() throws Exception {
        var original = entries.stream().filter(value -> "control-b".equals(value.id())).findFirst().orElseThrow();
        entries.set(entries.indexOf(original), replaceTime(original, NOW.plusSeconds(WAIT)));
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());
    }

    @Test
    void rejectsASecondRequestThatStillUsesTheFirstMetadataKey() {
        bodies.put("request-b", bodies.get("request-a"));
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());
    }

    @Test
    void rejectsChangedRestorationAndRelayClaimsEvenWhenTheirHashesAreUpdated() throws Exception {
        write("final-config.php", "changed".getBytes(StandardCharsets.UTF_8));
        hashField("finalConfigSha256", "final-config.php");
        saveManifest();
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());

        write("final-config.php", CONFIG.getBytes(StandardCharsets.UTF_8));
        hashField("finalConfigSha256", "final-config.php");
        write("proxy-requests.jsonl", (proxyLine("control", metadataA, NOW.plusMillis(500)) + "\n"
                + proxyLine(VARIANT_B, metadataA, NOW.plusSeconds(2 + WAIT).plusMillis(500)) + "\n")
                .getBytes(StandardCharsets.UTF_8));
        hashField("proxyRequestsSha256", "proxy-requests.jsonl");
        saveManifest();
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());
    }

    @Test
    void rejectsRuntimeReplacementAndPreparedBodyTampering() throws Exception {
        var end = (ObjectNode) json.mapper().readTree(Files.readAllBytes(receipt.resolve("target-runtime-end.json")));
        end.withObject("/binding").put("container_id", "b".repeat(64));
        write("target-runtime-end.json", json.mapper().writeValueAsBytes(end));
        hashField("targetRuntimeEndSha256", "target-runtime-end.json");
        saveManifest();
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());

        runtime("end");
        hashField("targetRuntimeEndSha256", "target-runtime-end.json");
        saveManifest();
        bodies.put("metadata-b", metadataA);
        assertEquals(Outcome.NOT_VERIFIED, configure(testCase()).outcome());
    }

    @Test
    void normativeCapabilityAbsenceRemainsAProductViolationWithoutAReceipt() throws Exception {
        Files.delete(receipt.resolve("manifest.json"));
        var test = testCase();
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context(), waiting.next(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "No refresh source")));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    private MetadataRefreshConfigurationTestCase testCase() {
        var evidence = new AttestedOutcomeTestCase(MetadataRefreshConfigurationTestCase.ID, TargetRole.IDP,
                "metadata refresh", "Review evidence", Duration.ofDays(1),
                List.of(AttestationOption.notVerified("unknown", "unknown", "unknown")));
        var fallback = new ConfigurationGateTestCase(evidence, "metadata-refresh", "Configure recurring refresh",
                Duration.ofDays(1), ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        return new MetadataRefreshConfigurationTestCase(fallback,
                entry -> bodies.get(entry.decodedSamlRef()), temp.resolve("evidence"));
    }

    private com.samlscope.core.evaluation.CaseOutcome configure(MetadataRefreshConfigurationTestCase test) {
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        return assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), waiting.next(), new CaseEvent.ConfigConfirmed())).outcome();
    }

    private void addPhase(int index, String variant, PlanCredentials key, byte[] metadata, Instant start) {
        var suffix = index == 0 ? "a" : "b";
        var requestId = "_request-" + suffix;
        var destination = "https://suite.example/sp/acs/0?mdv=" + variant + "&run=" + RUN;
        var request = new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.VALID, requestId,
                URI.create(TARGET), ENTITY, URI.create(destination), start.plusSeconds(1), key);
        var response = ("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "ID='_response-" + suffix + "' Version='2.0' InResponseTo='" + requestId
                + "' Destination='" + destination.replace("&", "&amp;")
                + "'><samlp:Status><samlp:StatusCode Value='"
                + "urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status></samlp:Response>")
                .getBytes(StandardCharsets.UTF_8);
        bodies.put("metadata-" + suffix, metadata);
        bodies.put("request-" + suffix, request);
        bodies.put("response-" + suffix, response);
        if (index == 1) {
            var controlId = "_control-" + suffix;
            var invalid = new SamlSignedRequestFactory().build(SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE,
                    controlId, URI.create(TARGET), ENTITY, URI.create(destination), start, key);
            bodies.put("control-" + suffix, invalid);
            entries.add(entry("control-" + suffix, Direction.OUTBOUND, start, controlId, "POST", TARGET, null,
                    "control-" + suffix, invalid.length,
                    Map.of("type", "AuthnRequest", "campaign", "metadata-polling", "variant", variant,
                            "metadataSignatureControl", "invalid", "id", controlId)));
        }
        entries.add(entry("fetch-" + suffix, Direction.INBOUND, start.plusMillis(300), "fetch-" + suffix, "GET",
                "https://suite.example/metadata/live", null, null, 0,
                Map.of("type", "MetadataFetch", "feed", "live", "variant", variant)));
        entries.add(entry("prepared-" + suffix, Direction.OUTBOUND, start.plusMillis(400), "fetch-" + suffix,
                "GET", "https://suite.example/metadata/live", null, "metadata-" + suffix, metadata.length,
                Map.of("type", "MetadataPrepared", "sourceType", "MetadataFetch",
                        "fetchTranscriptId", "fetch-" + suffix, "feed", "live", "variant", variant,
                        "metadataSha256", sha(metadata))));
        entries.add(entry("request-" + suffix, Direction.OUTBOUND,
                index == 0 ? start : start.plusMillis(800), requestId, "POST",
                TARGET, null, "request-" + suffix, request.length,
                Map.of("type", "AuthnRequest", "campaign", "metadata-polling", "variant", variant,
                        "metadataSignatureControl", "valid", "id", requestId)));
        entries.add(entry("response-" + suffix, Direction.INBOUND,
                index == 0 ? start.plusSeconds(1) : start.plusMillis(1500), requestId, "POST",
                destination, 200, "response-" + suffix, response.length,
                Map.of("type", "Response", "metadataProbeAccepted", true,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success",
                        "inResponseTo", requestId)));
    }

    private ObjectNode phase(String variant, int index) {
        var suffix = index == 0 ? "a" : "b";
        var phase = json.mapper().createObjectNode();
        phase.put("variant", variant);
        phase.put("fetchReference", "fetch-" + suffix);
        phase.put("preparedReference", "prepared-" + suffix);
        phase.put("requestReference", "request-" + suffix);
        phase.put("responseReference", "response-" + suffix);
        if (index == 1) phase.put("controlRequestReference", "control-b");
        return phase;
    }

    private String proxyLine(String variant, byte[] metadata, Instant observed) throws Exception {
        return json.mapper().writeValueAsString(Map.of("entityId", ENTITY, "variant", variant,
                "responseSha256", sha(metadata), "httpStatus", 200, "observedAt", observed.toString()));
    }

    private void runtime(String phase) throws Exception {
        var inspect = json.mapper().createArrayNode();
        var item = inspect.addObject();
        item.put("Id", "a".repeat(64));
        item.put("Image", "sha256:" + "1".repeat(64));
        item.putObject("Config").put("Image", "samlscope-reference-ssp:2.5.0");
        item.putObject("State").put("StartedAt", "2026-09-30T01:00:00Z").put("Running", true);
        var inspectRaw = json.mapper().writeValueAsBytes(inspect);
        var imageRaw = "[{}]".getBytes(StandardCharsets.UTF_8);
        var versionRaw = "2.5.0\n".getBytes(StandardCharsets.UTF_8);
        var sourceRaw = "public const string VERSION = '2.5.0';\n".getBytes(StandardCharsets.UTF_8);
        write("target-container-inspect-" + phase + ".json", inspectRaw);
        write("target-image-inspect-" + phase + ".json", imageRaw);
        write("target-version-runtime-" + phase + ".txt", versionRaw);
        write("target-version-source-" + phase + ".txt", sourceRaw);
        var summary = json.mapper().createObjectNode();
        summary.put("schema", "samlscope-terminal-http-target-runtime-v1");
        summary.put("product", "simplesamlphp");
        summary.put("phase", phase);
        var binding = summary.putObject("binding");
        binding.put("container_id", "a".repeat(64));
        binding.put("image_id", "sha256:" + "1".repeat(64));
        binding.put("configured_image", "samlscope-reference-ssp:2.5.0");
        binding.put("container_started_at", "2026-09-30T01:00:00Z");
        binding.put("running_at_capture", true);
        binding.put("host_port_bound", true);
        binding.put("host_port", 18380);
        binding.put("container_port", "80/tcp");
        summary.put("docker_inspect_sha256", sha(inspectRaw));
        summary.put("image_inspect_sha256", sha(imageRaw));
        var runtime = summary.putObject("runtime_version");
        runtime.put("file", "target-version-runtime-" + phase + ".txt");
        runtime.put("sha256", sha(versionRaw));
        runtime.put("value", "2.5.0");
        var source = summary.putObject("version_source");
        source.put("file", "target-version-source-" + phase + ".txt");
        source.put("sha256", sha(sourceRaw));
        source.put("value", "2.5.0");
        write("target-runtime-" + phase + ".json", json.mapper().writeValueAsBytes(summary));
    }

    private byte[] metadata(PlanCredentials key) {
        var certificate = Base64.getEncoder().encodeToString(encoded(key));
        return ("<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='" + ENTITY + "'>"
                + "<md:SPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "<md:AssertionConsumerService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' "
                + "Location='https://suite.example/sp/acs/0' index='0'/></md:SPSSODescriptor>"
                + "</md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
    }

    private byte[] encoded(PlanCredentials key) {
        try { return key.certificate().getEncoded(); }
        catch (Exception error) { throw new IllegalStateException(error); }
    }

    private TranscriptEntry entry(String id, Direction direction, Instant time, String correlation,
            String method, String url, Integer status, String decoded, int size, Map<String, Object> summary) {
        return new TranscriptEntry(id, RUN, direction, time, correlation, method, url, status, Map.of(),
                null, 0, decoded, size, "application/xml", null, summary);
    }

    private TranscriptEntry replaceTime(TranscriptEntry value, Instant time) {
        return new TranscriptEntry(value.id(), value.runId(), value.direction(), time, value.correlationId(),
                value.method(), value.url(), value.status(), value.headers(), value.bodyRef(), value.bodyBytes(),
                value.decodedSamlRef(), value.decodedSamlBytes(), value.contentType(), value.rawQuery(),
                value.samlSummary());
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return RUN; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW.plusSeconds(30), ZoneOffset.UTC); }
            @Override public TestPlan.Parameters parameters() {
                return new TestPlan.Parameters(180, WAIT, "", TestPlan.RequestSigningMode.REQUIRED);
            }
            @Override public TestPlan.Interaction interaction() { return TestPlan.Interaction.defaults(); }
            @Override public Reachability reachability() { return Reachability.CONFIRMED; }
            @Override public TranscriptRecorder transcript() {
                return new TranscriptRecorder() {
                    @Override public TranscriptEntry record(TranscriptInput input) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public TranscriptEntry updateSamlAnalysis(
                            String id, String correlation, Map<String, Object> summary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return List.copyOf(entries); }
                };
            }
            @Override public boolean transcriptComplete() { return true; }
        };
    }

    private byte[] jsonBytes(Object value) throws Exception { return json.mapper().writeValueAsBytes(value); }
    private void write(String name, byte[] raw) throws Exception { Files.write(receipt.resolve(name), raw); }
    private void hashField(String field, String name) throws Exception {
        manifest.put(field, sha(Files.readAllBytes(receipt.resolve(name))));
    }
    private void saveManifest() throws Exception {
        Files.write(receipt.resolve("manifest.json"), json.mapper().writeValueAsBytes(manifest));
    }
    private String sha(byte[] raw) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw)); }
        catch (Exception error) { throw new IllegalStateException(error); }
    }
}
