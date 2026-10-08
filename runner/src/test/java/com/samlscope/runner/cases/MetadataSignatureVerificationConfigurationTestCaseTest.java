package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.EMBEDDED_DER;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.ANCHOR_DER;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.FIXTURE;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.RUN;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.TARGET;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.configurationArtifact;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.correlationEntries;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.requestId;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.sha;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.tx;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.writeReceipt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

/**
 * Regression for MD03.b: a product that accepts a signed fixture without verifying the metadata
 * document signature must stay NOT_VERIFIED. Only a fully correlated Run-scoped receipt whose
 * referenced originals are readable and semantically valid permits a conclusive outcome.
 */
class MetadataSignatureVerificationConfigurationTestCaseTest {
    @TempDir Path directory;
    private static final Instant NOW = MetadataSignatureVerificationTestSupport.NOW;

    @Test
    void acceptingTheFixtureWithoutSignatureVerificationStaysNotVerified() throws Exception {
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), false, receipt -> receipt, Map.of()));
    }

    @Test
    void completeSignatureVerificationEvidencePermitsSatisfied() throws Exception {
        assertEquals(Outcome.SATISFIED, evaluate(entries(), true, receipt -> receipt, Map.of()));
    }

    @Test
    void restoringAnOriginalNonemptyAnchorSetPermitsSatisfiedAfterAlternateKeyControl() throws Exception {
        assertEquals(Outcome.SATISFIED, evaluatePretrusted(entries(), receipt -> receipt,
                restoredConfiguration(ANCHOR_DER), Map.of()));
    }

    @Test
    void pretrustedConfigurationStillRequiresTheAlternateKeyConfigurationOriginal() throws Exception {
        var entries = new ArrayList<>(entries());
        entries.removeIf(entry -> entry.id().equals(tx(130)));
        assertEquals(Outcome.NOT_VERIFIED, evaluatePretrusted(entries, receipt -> receipt,
                restoredConfiguration(ANCHOR_DER), Map.of()));
    }

    @Test
    void pretrustedConfigurationWithNoOpAlternateKeyConfigurationStaysNotVerified() throws Exception {
        var noOp = configurationArtifact(ANCHOR_DER).getBytes(StandardCharsets.UTF_8);
        // Rebind the receipt to the actual no-op bytes: rejection must come from the control's
        // trust-source semantics, rather than a stale SHA-256.
        assertEquals(Outcome.NOT_VERIFIED, evaluatePretrusted(entries(), receipt -> receipt.replace(
                sha(configurationArtifact(EMBEDDED_DER).getBytes(StandardCharsets.UTF_8)), sha(noOp)),
                restoredConfiguration(ANCHOR_DER), Map.of("config-embedded", noOp)));
    }

    @Test
    void pretrustedAlternateControlThatRetainsThePositiveAnchorStaysNotVerified() throws Exception {
        var overlapping = configurationArtifact(EMBEDDED_DER).replace("\"]}", "\",\""
                + Base64.getEncoder().encodeToString(ANCHOR_DER) + "\"]}")
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(Outcome.NOT_VERIFIED, evaluatePretrusted(entries(), receipt -> receipt.replace(
                sha(configurationArtifact(EMBEDDED_DER).getBytes(StandardCharsets.UTF_8)), sha(overlapping)),
                restoredConfiguration(ANCHOR_DER), Map.of("config-embedded", overlapping)));
    }

    @Test
    void malformedNonemptyRestorationAnchorStaysNotVerifiedEvenWithTruthfulHashes() throws Exception {
        var malformed = new String(restoredConfiguration(ANCHOR_DER), StandardCharsets.UTF_8)
                .replace(Base64.getEncoder().encodeToString(ANCHOR_DER), "invalid-base64!")
                .getBytes(StandardCharsets.UTF_8);
        assertEquals(Outcome.NOT_VERIFIED, evaluateRestoration(entries(), receipt -> receipt,
                malformed, malformed, Map.of()));
    }

    @Test
    void restoringADifferentValidNonemptyAnchorSetStaysNotVerified() throws Exception {
        // Both restoration originals have truthful hashes and valid anchor arrays, but their
        // bytes differ. A successful control cannot replace exact restoration of the baseline.
        assertEquals(Outcome.NOT_VERIFIED, evaluatePretrusted(entries(), receipt -> receipt,
                restoredConfiguration(EMBEDDED_DER), Map.of()));
    }

    @Test
    void trustAnchorAbsentFromTheReadBackConfigurationStaysNotVerified() throws Exception {
        // The declared anchor fingerprint does not match any certificate the product read back.
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true,
                receipt -> receipt.replace("\"trustAnchorCertificateSha256\":\""
                        + sha(MetadataSignatureVerificationTestSupport.ANCHOR_DER) + "\"",
                        "\"trustAnchorCertificateSha256\":\"" + sha(EMBEDDED_DER) + "\""), Map.of()));
    }

    @Test
    void missingOriginalReferenceStaysNotVerified() throws Exception {
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt ->
                receipt.replace("\"reference\":\"" + tx(101) + "\"", "\"reference\":\"" + tx(999) + "\""),
                Map.of()));
    }

    @Test
    void originalBoundToAnotherTargetStaysNotVerified() throws Exception {
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt ->
                receipt.replace("\"targetEntityId\":\"" + MetadataSignatureVerificationTestSupport.TARGET_ENTITY_ID + "\"",
                        "\"targetEntityId\":\"https://elsewhere.example/idp\""), Map.of()));
    }

    @Test
    void receiptFromAnotherRunStaysNotVerified() throws Exception {
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt ->
                receipt.replace("\"runId\":\"" + RUN + "\"", "\"runId\":\"run_00000000000000000000000000\""),
                Map.of()));
    }

    @Test
    void originalFromAnotherRunStaysNotVerified() throws Exception {
        var overrides = new HashMap<String, byte[]>();
        overrides.put("config-out-of-band", configurationArtifact("run_00000000000000000000000000",
                MetadataSignatureVerificationTestSupport.ANCHOR_DER).getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt -> receipt, overrides));
    }

    @Test
    void originalBoundToAnotherTargetEntityStaysNotVerified() throws Exception {
        var overrides = new HashMap<String, byte[]>();
        overrides.put("config-out-of-band", configurationArtifact(
                MetadataSignatureVerificationTestSupport.ANCHOR_DER)
                .replace(MetadataSignatureVerificationTestSupport.TARGET_ENTITY_ID, "https://elsewhere.example/idp")
                .getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt -> receipt, overrides));
    }

    @Test
    void wrongEmbeddedKeyInfoFingerprintStaysNotVerified() throws Exception {
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt ->
                receipt.replace("\"embeddedKeyInfoCertificateSha256\":\"" + sha(EMBEDDED_DER) + "\"",
                        "\"embeddedKeyInfoCertificateSha256\":\"" + "c".repeat(64) + "\""), Map.of()));
    }

    @Test
    void rejectionRecordUnrelatedToTheFixtureStaysNotVerified() throws Exception {
        // The rejection reference points at the positive Success response, not a product refusal.
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt ->
                receipt.replace("\"rejectionReference\":\"" + tx(121) + "\"",
                        "\"rejectionReference\":\"" + tx(111) + "\""), Map.of()));
    }

    @Test
    void restoredConfigurationDifferentFromTheOriginalStaysNotVerified() throws Exception {
        var overrides = new HashMap<String, byte[]>();
        overrides.put("config-final", "different-restored-configuration".getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt -> receipt, overrides));
    }

    @Test
    void embeddedAnchorConfigurationThatStillTrustsTheOutOfBandAnchorStaysNotVerified() throws Exception {
        var overrides = new HashMap<String, byte[]>();
        overrides.put("config-embedded",
                configurationArtifact(MetadataSignatureVerificationTestSupport.ANCHOR_DER)
                        .getBytes(StandardCharsets.UTF_8));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries(), true, receipt -> receipt, overrides));
    }

    @Test
    void noResponseToTheValidDocumentStaysNotVerified() throws Exception {
        var entries = new ArrayList<>(entries());
        entries.removeIf(entry -> entry.id().equals(tx(111)));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries, true, receipt -> receipt, Map.of()));
    }

    @Test
    void acceptingTheInvalidSignatureControlStaysNotVerified() throws Exception {
        var entries = new ArrayList<>(entries());
        entries.add(entry(90, Direction.INBOUND, "https://suite.example/sp/acs/0", "resp-extra",
                MetadataSignatureVerificationTestSupport.SUCCESS_RESPONSE,
                Map.of("type", "Response", "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success",
                        "inResponseTo", requestId(5))));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(entries, true, receipt -> receipt, Map.of()));
    }

    @Test
    void recordedEvidenceReevaluationAlsoRequiresSignatureVerification() throws Exception {
        var fixtureObserver = new MetadataFixtureObservationTestCase("IIP-MD03-b-idp-01", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(FIXTURE,
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "configured key")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var testCase = new MetadataSignatureVerificationConfigurationTestCase(
                fixtureObserver, MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
        var previous = new com.samlscope.core.evaluation.CaseOutcome(Outcome.NOT_VERIFIED,
                "metadata_fixture_probe_incomplete", "metadata.fixture-probe.incomplete",
                "metadata.fixture-probe.incomplete", List.of(), Map.of());
        assertTrue(testCase.supportsRecordedEvidenceReevaluation(previous));
        assertEquals(Outcome.NOT_VERIFIED, testCase.reevaluateRecordedEvidence(context(entries()), previous)
                .orElseThrow().outcome());
        writeReceipt(directory, receipt -> receipt);
        assertEquals(Outcome.SATISFIED, testCase.reevaluateRecordedEvidence(context(entries()), previous)
                .orElseThrow().outcome());
    }

    @Test
    void absentNormativeCapabilityStaysViolatedWithoutSignatureVerification() throws Exception {
        // The approved configuration-failure semantics must survive: an absent normative capability
        // is a target violation even when the signature verification receipt is absent.
        var fixtureObserver = new MetadataFixtureObservationTestCase("IIP-MD03-b-idp-01", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(FIXTURE,
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "configured key")),
                ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        var testCase = new MetadataSignatureVerificationConfigurationTestCase(
                fixtureObserver, MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
        var context = context(entries());
        var start = (CaseStep.AwaitConfig) testCase.start(context);
        var finish = (CaseStep.Finish) testCase.resume(context, start.next(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "no filter"));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
        assertEquals("capability_absent", finish.outcome().reasonCode());
    }

    private Outcome evaluate(List<TranscriptEntry> entries, boolean withReceipt,
            UnaryOperator<String> mutate, Map<String, byte[]> contentOverrides) throws Exception {
        if (withReceipt) writeReceipt(directory, mutate);
        TranscriptContentReader content = MetadataSignatureVerificationTestSupport.content(RUN, contentOverrides);
        var fixtureObserver = new MetadataFixtureObservationTestCase("IIP-MD03-b-idp-01", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(FIXTURE,
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "configured key")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var testCase = new MetadataSignatureVerificationConfigurationTestCase(
                fixtureObserver, content, runId -> TARGET, directory);
        var context = context(entries);
        var start = (CaseStep.AwaitConfig) testCase.start(context);
        return ((CaseStep.Finish) testCase.resume(
                context, start.next(), new CaseEvent.ConfigConfirmed())).outcome().outcome();
    }

    private Outcome evaluatePretrusted(List<TranscriptEntry> entries, UnaryOperator<String> mutate,
            byte[] restoredFinal, Map<String, byte[]> overrides) throws Exception {
        return evaluateRestoration(entries, mutate, restoredConfiguration(ANCHOR_DER), restoredFinal, overrides);
    }

    private Outcome evaluateRestoration(List<TranscriptEntry> entries, UnaryOperator<String> mutate,
            byte[] restoredOriginal, byte[] restoredFinal, Map<String, byte[]> overrides) throws Exception {
        var content = new HashMap<>(overrides);
        content.put("config-original", restoredOriginal);
        content.put("config-final", restoredFinal);
        var originals = entries.stream().map(entry -> {
            var bytes = content.get(entry.decodedSamlRef());
            return bytes == null ? entry : new TranscriptEntry(entry.id(), entry.runId(), entry.direction(),
                    entry.timestamp(), entry.correlationId(), entry.method(), entry.url(), entry.status(),
                    entry.headers(), entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(), bytes.length,
                    entry.contentType(), entry.rawQuery(), entry.samlSummary());
        }).toList();
        return evaluate(originals, true, receipt -> {
            var json = new com.fasterxml.jackson.databind.ObjectMapper();
            try {
                var root = json.readTree(receipt);
                var restoration = (com.fasterxml.jackson.databind.node.ObjectNode) root.path("restorationReadBack");
                restoration.put("originalSha256", sha(restoredOriginal));
                restoration.put("finalSha256", sha(restoredFinal));
                return mutate.apply(json.writeValueAsString(root));
            } catch (java.io.IOException failure) {
                throw new IllegalArgumentException(failure);
            }
        }, content);
    }

    private static byte[] restoredConfiguration(byte[] anchor) {
        return MetadataSignatureVerificationTestSupport.restorationArtifact().replace(
                "\"trustAnchorCertificates\":[]", "\"trustAnchorCertificates\":[\""
                        + Base64.getEncoder().encodeToString(anchor) + "\"]")
                .getBytes(StandardCharsets.UTF_8);
    }

    private List<TranscriptEntry> entries() {
        var entries = new ArrayList<TranscriptEntry>();
        entries.add(fetch("control", 901));
        entries.add(use("control", 902));
        entries.add(fetch(FIXTURE, 903));
        entries.add(use(FIXTURE, 904));
        entries.addAll(correlationEntries());
        return entries;
    }

    private CaseContext context(List<TranscriptEntry> entries) {
        return new CaseContext() {
            @Override public String runId() { return RUN; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
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
                            String entryId, String correlationId, Map<String, Object> samlSummary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return entries; }
                };
            }
            @Override public boolean transcriptComplete() { return true; }
        };
    }

    private TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, Direction.INBOUND, "/metadata/live", "fetch-" + sequence, new byte[0],
                Map.of("type", "MetadataFetch", "variant", variant, "feed", "live"));
    }

    private TranscriptEntry use(String variant, int sequence) {
        return entry(sequence, Direction.INBOUND,
                "https://suite.example/p/plan/sp/acs/0?mdv=" + variant + "&run=" + RUN,
                "use-" + sequence, "probe".getBytes(StandardCharsets.UTF_8),
                Map.of("type", "SAMLResponse", "metadataProbeAccepted", true,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success"));
    }

    private TranscriptEntry entry(int sequence, Direction direction, String url, String decodedRef,
            byte[] body, Map<String, Object> summary) {
        return new TranscriptEntry(
                tx(sequence), RUN, direction, NOW.plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedRef, body.length, null, null, summary);
    }
}
