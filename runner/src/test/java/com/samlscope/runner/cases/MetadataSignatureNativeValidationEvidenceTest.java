package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.CAMPAIGN_ID;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.FIXTURE;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.RUN;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.TARGET;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.TARGET_ENTITY_ID;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.correlationEntries;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.sha;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.tx;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Native-v4 controls are bound to raw product configuration, sources and validation originals. */
class MetadataSignatureNativeValidationEvidenceTest {
    @TempDir Path directory;
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] PARSER = ("class SAMLParser { public function validateSignature(array $certificates): bool { "
            + "$certData=$cryptoUtils->retrieveCertificate($certLocation); if ($validator->validate($key)) return true; "
            + "Logger::debug('Could not validate signature'); return false; }}").getBytes(StandardCharsets.UTF_8);
    private static final byte[] MDQ = ("class MDQ { private ?array $validateCertificate = null; "
            + "if (!$entity->validateSignature($this->validateCertificate)) throw new Exception("
            + "'could not verify signature for entity'); }").getBytes(StandardCharsets.UTF_8);
    private static final byte[] METALOADER = ("class MetaLoader { private function processCertificates() { "
            + "array_key_exists('certificates', $source); $entity->validateSignature($source['certificates']); }}")
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] CONFIGURATION = "class Configuration { public const string VERSION = '2.5.0'; }"
            .getBytes(StandardCharsets.UTF_8);
    private static final byte[] ADAPTER = ("MetaDataStorageSource::getSource validateCertificate postOriginal "
            + "metadata-signature-native-validation").getBytes(StandardCharsets.UTF_8);
    private static final byte[] OOB_PEM = resource("rsa-sha1/wrong-certificate.pem");
    private static final byte[] EMBEDDED_PEM = resource("native-v4/embedded-certificate.pem");
    private static final byte[] OOB_DER = certificateDer(OOB_PEM);
    private static final byte[] EMBEDDED_DER = certificateDer(EMBEDDED_PEM);
    private static final byte[] ORIGINAL_CONFIG = ("<?php\n$config['metadata.sources'] = [[\n"
            + "  'type' => 'flatfile',\n]];\n").getBytes(StandardCharsets.UTF_8);

    @Test
    void nativeValidationAndTwoNativeRejectionsAreAccepted() throws Exception {
        var evidence = evidence(value -> {});
        var proof = new MetadataSignatureVerificationEvidenceFile(directory)
                .verify(context(evidence.entries()), TARGET, evidence.content(), CAMPAIGN_ID);
        assertEquals("simplesamlphp-runtime", proof.adapter());
        assertEquals(sha(OOB_DER), proof.anchorCertificateSha256());
    }

    @Test
    void genericParserResultIsRejected() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value.path("positiveNative"))
                .put("genericParserOnly", true)));
    }

    @Test
    void acceptedBadSignatureControlIsRejected() throws Exception {
        rejected(evidence(value -> {
            ((ObjectNode) value.path("invalidNative")).put("outcome", "accepted");
            ((ObjectNode) value.path("invalidNative")).put("signatureVerified", true);
            ((ObjectNode) value.path("invalidNative")).putNull("exception");
        }));
    }

    @Test
    void validControlWithFalseSignatureResultIsRejected() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value.path("positiveNative"))
                .put("signatureVerified", false)));
    }

    @Test
    void changedProductSourceIsRejectedEvenWhenAllReportedHashesMatch() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value.path("sourceText"))
                .put("mdq", "generic parser only")));
    }

    @Test
    void selfReportedEnabledJsonCannotReplaceRawPhpConfiguration() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value)
                .put("positiveConfiguration", "{\"signatureVerification\":\"enabled\"}")));
    }

    @Test
    void effectiveConfigurationMustShowTheExactMdqValidationAnchor() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value)
                .put("positiveEffective", "[{\"type\":\"flatfile\"}]")));
    }

    @Test
    void restorationBeforeTheLastNativeRejectionIsRejected() throws Exception {
        rejected(evidence(value -> ((ObjectNode) value).put("earlyRestoration", true)));
    }

    private void rejected(Evidence evidence) {
        assertThrows(IllegalArgumentException.class, () -> new MetadataSignatureVerificationEvidenceFile(directory)
                .verify(context(evidence.entries()), TARGET, evidence.content(), CAMPAIGN_ID));
    }

    private record Evidence(List<TranscriptEntry> entries, TranscriptContentReader content) {}

    private Evidence evidence(Consumer<ObjectNode> mutate) throws Exception {
        var state = JSON.createObjectNode();
        state.set("positiveNative", nativeRecord(FIXTURE, OOB_DER, true));
        state.set("invalidNative", nativeRecord("bad-signature", EMBEDDED_DER, false));
        state.set("embeddedNative", nativeRecord(FIXTURE, EMBEDDED_DER, false));
        var sourceText = state.putObject("sourceText");
        sourceText.put("parser", new String(PARSER, StandardCharsets.UTF_8));
        sourceText.put("mdq", new String(MDQ, StandardCharsets.UTF_8));
        sourceText.put("metaLoader", new String(METALOADER, StandardCharsets.UTF_8));
        sourceText.put("configuration", new String(CONFIGURATION, StandardCharsets.UTF_8));
        sourceText.put("adapter", new String(ADAPTER, StandardCharsets.UTF_8));
        state.put("positiveConfiguration", configured("oob.pem"));
        state.put("positiveEffective", effective("oob.pem"));
        state.put("controlConfiguration", configured("embedded.pem"));
        state.put("controlEffective", effective("embedded.pem"));
        mutate.accept(state);

        var bytes = new HashMap<String, byte[]>();
        bytes.put("native-parser", utf8(state.path("sourceText").path("parser").asText()));
        bytes.put("native-mdq", utf8(state.path("sourceText").path("mdq").asText()));
        bytes.put("native-metaloader", utf8(state.path("sourceText").path("metaLoader").asText()));
        bytes.put("native-configuration", utf8(state.path("sourceText").path("configuration").asText()));
        bytes.put("native-adapter", utf8(state.path("sourceText").path("adapter").asText()));
        bytes.put("actual-config-before", ORIGINAL_CONFIG);
        bytes.put("actual-config-positive", utf8(state.path("positiveConfiguration").asText()));
        bytes.put("effective-config-positive", utf8(state.path("positiveEffective").asText()));
        bytes.put("anchor-oob", OOB_PEM);
        bytes.put("actual-config-control", utf8(state.path("controlConfiguration").asText()));
        bytes.put("effective-config-control", utf8(state.path("controlEffective").asText()));
        bytes.put("anchor-embedded", EMBEDDED_PEM);
        bytes.put("actual-config-final", ORIGINAL_CONFIG);
        bytes.put("fixture-" + FIXTURE, fixtureBytes(FIXTURE));
        bytes.put("fixture-bad-signature", fixtureBytes("bad-signature"));

        bindNative((ObjectNode) state.path("positiveNative"), bytes, tx(70), tx(71), "oob.pem");
        bindNative((ObjectNode) state.path("invalidNative"), bytes, tx(73), tx(74), "embedded.pem");
        bindNative((ObjectNode) state.path("embeddedNative"), bytes, tx(73), tx(74), "embedded.pem");
        bytes.put("native-positive", JSON.writeValueAsBytes(state.path("positiveNative")));
        bytes.put("native-invalid", JSON.writeValueAsBytes(state.path("invalidNative")));
        bytes.put("native-embedded", JSON.writeValueAsBytes(state.path("embeddedNative")));

        var entries = new ArrayList<>(correlationEntries());
        entries.add(entry(60, "native-parser", bytes.get("native-parser")));
        entries.add(entry(61, "native-mdq", bytes.get("native-mdq")));
        entries.add(entry(62, "native-metaloader", bytes.get("native-metaloader")));
        entries.add(entry(63, "native-configuration", bytes.get("native-configuration")));
        entries.add(entry(64, "native-adapter", bytes.get("native-adapter")));
        entries.add(entry(65, "actual-config-before", ORIGINAL_CONFIG));
        entries.add(entry(70, "actual-config-positive", bytes.get("actual-config-positive")));
        entries.add(entry(71, "effective-config-positive", bytes.get("effective-config-positive")));
        entries.add(entry(72, "anchor-oob", OOB_PEM));
        entries.add(entry(73, "actual-config-control", bytes.get("actual-config-control")));
        entries.add(entry(74, "effective-config-control", bytes.get("effective-config-control")));
        entries.add(entry(75, "anchor-embedded", EMBEDDED_PEM));
        entries.add(prepared(106, "bad-signature", bytes.get("fixture-bad-signature")));
        entries.add(entry(112, "native-positive", bytes.get("native-positive")));
        entries.add(entry(125, "native-invalid", bytes.get("native-invalid")));
        entries.add(entry(135, "native-embedded", bytes.get("native-embedded")));
        var finalSequence = state.path("earlyRestoration").asBoolean(false) ? 115 : 160;
        entries.add(entry(finalSequence, "actual-config-final", ORIGINAL_CONFIG));

        var receipt = (ObjectNode) JSON.readTree(MetadataSignatureVerificationTestSupport.receipt());
        receipt.put("schema", "samlscope-metadata-signature-verification-receipt-v4");
        receipt.put("evidenceAdapter", "simplesamlphp-runtime");
        var nativeSources = receipt.putObject("nativeSources");
        sourceRef(nativeSources.putObject("samlParser"), 60, bytes.get("native-parser"));
        sourceRef(nativeSources.putObject("mdq"), 61, bytes.get("native-mdq"));
        sourceRef(nativeSources.putObject("metaLoader"), 62, bytes.get("native-metaloader"));
        sourceRef(nativeSources.putObject("configuration"), 63, bytes.get("native-configuration"));
        sourceRef(nativeSources.putObject("adapter"), 64, bytes.get("native-adapter"));
        configurationRef(receipt.putObject("configurationReadBack"), 70, 71, 72,
                "actual-config-positive", "effective-config-positive", "anchor-oob", OOB_DER, "oob.pem", bytes);
        var restoration = receipt.putObject("restorationReadBack");
        restoration.put("originalReference", tx(65));
        restoration.put("originalSha256", sha(ORIGINAL_CONFIG));
        restoration.put("finalReference", tx(finalSequence));
        restoration.put("finalSha256", sha(ORIGINAL_CONFIG));
        var positive = (ObjectNode) receipt.path("positive");
        positive.put("embeddedKeyInfoCertificateSha256", sha(EMBEDDED_DER));
        positive.put("nativeValidationReference", tx(112));
        positive.put("nativeValidationSha256", sha(bytes.get("native-positive")));
        for (var controlNode : receipt.path("negativeControls")) {
            var control = (ObjectNode) controlNode;
            if ("invalid-signature".equals(control.path("kind").asText())) {
                control.put("variant", "bad-signature");
                control.put("nativeRejectionReference", tx(125));
                control.put("nativeRejectionSha256", sha(bytes.get("native-invalid")));
            } else {
                control.put("variant", FIXTURE);
                control.put("nativeRejectionReference", tx(135));
                control.put("nativeRejectionSha256", sha(bytes.get("native-embedded")));
            }
            configurationRef(control.putObject("configurationReadBack"), 73, 74, 75,
                    "actual-config-control", "effective-config-control", "anchor-embedded",
                    EMBEDDED_DER, "embedded.pem", bytes);
        }
        Files.write(directory.resolve(RUN + ".signature-verification.json"), JSON.writeValueAsBytes(receipt));
        return new Evidence(entries, MetadataSignatureVerificationTestSupport.content(RUN, bytes));
    }

    private static ObjectNode nativeRecord(String variant, byte[] anchor, boolean accepted) {
        var record = JSON.createObjectNode();
        record.put("schema", "samlscope-simplesamlphp-metadata-signature-validation-v1");
        record.put("artifact", "metadata-signature-native-validation");
        record.put("runId", RUN);
        record.put("campaignId", CAMPAIGN_ID);
        record.put("targetEntityId", TARGET_ENTITY_ID);
        record.put("variant", variant);
        record.put("product", "simplesamlphp");
        record.put("productVersion", "2.5.0");
        record.put("fixtureSha256", sha(fixtureBytes(variant)));
        record.put("metadataEntityId", "https://suite.example/" + variant);
        record.put("entryPoint", "SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData");
        record.put("verifier", "SimpleSAML\\Metadata\\SAMLParser::validateSignature");
        record.put("genericParserOnly", false);
        record.put("validationCallCount", 1);
        record.put("trustAnchorCertificateSha256", sha(anchor));
        record.put("parserAccepted", true);
        record.put("signatureVerified", accepted);
        record.put("outcome", accepted ? "accepted" : "rejected");
        var path = record.putArray("callPath");
        path.add("SimpleSAML\\Metadata\\Sources\\MDQ::getMetaData");
        path.add("SimpleSAML\\Metadata\\SAMLParser::parseString");
        path.add("SimpleSAML\\Metadata\\SAMLParser::validateSignature");
        if (accepted) record.putNull("exception");
        else {
            var exception = record.putObject("exception");
            exception.put("class", "Exception");
            exception.put("message", "SimpleSAML\\Metadata\\Sources\\MDQ: error, could not verify signature for entity: https://suite.example/" + variant + "\".");
        }
        return record;
    }

    private static void bindNative(ObjectNode record, Map<String, byte[]> bytes,
            String configurationReference, String effectiveReference, String location) {
        record.put("configurationReference", configurationReference);
        record.put("effectiveConfigurationReference", effectiveReference);
        record.put("configurationSha256", sha(bytes.get(location.equals("oob.pem")
                ? "actual-config-positive" : "actual-config-control")));
        record.put("certificateLocation", location);
        var hashes = record.putObject("sourceSha256");
        hashes.put("samlParser", sha(bytes.get("native-parser")));
        hashes.put("mdq", sha(bytes.get("native-mdq")));
        hashes.put("metaLoader", sha(bytes.get("native-metaloader")));
        hashes.put("configuration", sha(bytes.get("native-configuration")));
        hashes.put("adapter", sha(bytes.get("native-adapter")));
    }

    private static void configurationRef(ObjectNode ref, int configSequence, int effectiveSequence,
            int anchorSequence, String configKey, String effectiveKey, String anchorKey, byte[] certificateDer,
            String location, Map<String, byte[]> bytes) {
        ref.put("reference", tx(configSequence));
        ref.put("sha256", sha(bytes.get(configKey)));
        ref.put("effectiveReference", tx(effectiveSequence));
        ref.put("effectiveSha256", sha(bytes.get(effectiveKey)));
        ref.put("trustAnchorReference", tx(anchorSequence));
        ref.put("trustAnchorOriginalSha256", sha(bytes.get(anchorKey)));
        ref.put("trustAnchorCertificateSha256", sha(certificateDer));
        ref.put("certificateLocation", location);
    }

    private static byte[] fixtureBytes(String variant) {
        var xml = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
                + "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://suite.example/"
                + variant + "\"><ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + Base64.getEncoder().encodeToString(EMBEDDED_DER)
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></md:EntityDescriptor>";
        return utf8(xml);
    }

    private static String configured(String location) {
        return "<?php\n$config['metadata.sources'] = [[\n  'type' => 'flatfile',\n], [\n"
                + "  'type' => 'mdq',\n  'server' => 'http://127.0.0.1:8081',\n"
                + "  'cachelength' => 0,\n  'validateCertificate' => ['" + location + "'],\n]];\n";
    }

    private static String effective(String location) {
        return "[{\"type\":\"flatfile\"},{\"type\":\"mdq\",\"server\":\"http://127.0.0.1:8081\","
                + "\"cachelength\":0,\"validateCertificate\":[\"" + location + "\"]}]";
    }

    private static byte[] resource(String name) {
        try (var in = MetadataSignatureNativeValidationEvidenceTest.class.getResourceAsStream(name)) {
            if (in == null) throw new IllegalStateException("missing resource " + name);
            return in.readAllBytes();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static byte[] certificateDer(byte[] pem) {
        try {
            return CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem)).getEncoded();
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }

    private static byte[] utf8(String value) { return value.getBytes(StandardCharsets.UTF_8); }

    private static void sourceRef(ObjectNode target, int sequence, byte[] bytes) {
        target.put("reference", tx(sequence));
        target.put("sha256", sha(bytes));
    }

    private static TranscriptEntry entry(int sequence, String ref, byte[] raw) {
        return new TranscriptEntry(tx(sequence), RUN, Direction.INBOUND,
                MetadataSignatureVerificationTestSupport.NOW.plusSeconds(sequence), "native", "POST",
                "https://suite.example/p/plan_0123456789ABCDEFGHJKMNPQRS/sp/paos?run=" + RUN,
                204, Map.of(), null, 0, ref, raw.length, "application/octet-stream", null,
                Map.of("type", "EcpPaosResponse"));
    }

    private static TranscriptEntry prepared(int sequence, String variant, byte[] raw) {
        return new TranscriptEntry(tx(sequence), RUN, Direction.OUTBOUND,
                MetadataSignatureVerificationTestSupport.NOW.plusSeconds(sequence), "fetch", "GET",
                "/metadata/live", 200, Map.of(), null, 0, "fixture-" + variant, raw.length,
                "application/samlmetadata+xml", null,
                Map.of("type", "MetadataPrepared", "variant", variant));
    }

    private static CaseContext context(List<TranscriptEntry> entries) {
        return new CaseContext() {
            @Override public String runId() { return RUN; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() {
                return Clock.fixed(MetadataSignatureVerificationTestSupport.NOW, ZoneOffset.UTC);
            }
            @Override public com.samlscope.core.plan.TestPlan.Parameters parameters() { return null; }
            @Override public com.samlscope.core.plan.TestPlan.Interaction interaction() { return null; }
            @Override public com.samlscope.core.run.Reachability reachability() {
                return com.samlscope.core.run.Reachability.CONFIRMED;
            }
            @Override public TranscriptRecorder transcript() {
                return new TranscriptRecorder() {
                    @Override public TranscriptEntry record(TranscriptInput input) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public TranscriptEntry updateSamlAnalysis(
                            String entryId, String correlationId, Map<String, Object> summary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return entries; }
                };
            }
            @Override public boolean transcriptComplete() { return true; }
        };
    }
}
