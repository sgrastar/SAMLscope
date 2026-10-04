package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.RUN;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.TARGET;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.correlationEntries;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.fixtureBytes;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.sha;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.tx;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.writeReceipt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

/**
 * MD03.a must not conclude through the recorded-evidence re-evaluation path unless the Run also
 * proves the target verifies document signatures. A native rejection receipt alone is not enough.
 */
class MetadataRejectionConfigurationTestCaseTest {
    @TempDir Path directory;
    private static final Instant NOW = MetadataSignatureVerificationTestSupport.NOW;
    private static final List<String> REJECTS = List.of("unsigned", "bad-signature", "signed-other-key");

    @Test
    void nativeRejectionWithoutSignatureVerificationStaysNotVerified() throws Exception {
        Files.writeString(directory.resolve(RUN + ".json"), rejectionReceipt());
        assertEquals(java.util.Optional.empty(), reevaluate());
    }

    @Test
    void nativeRejectionWithCompleteSignatureVerificationPermitsSatisfied() throws Exception {
        Files.writeString(directory.resolve(RUN + ".json"), rejectionReceipt());
        writeReceipt(directory, receipt -> receipt);
        assertEquals(Outcome.SATISFIED, reevaluate().orElseThrow().outcome());
    }

    @Test
    void verifiedExtraCampaignVariantDoesNotPreventTheCompleteCaseSubset() throws Exception {
        var variants = new ArrayList<>(REJECTS);
        variants.add("xpath-identity");
        Files.writeString(directory.resolve(RUN + ".json"), rejectionReceipt(variants));
        writeReceipt(directory, receipt -> receipt);
        var outcome = reevaluate().orElseThrow();
        assertEquals(Outcome.SATISFIED, outcome.outcome());
        assertEquals(REJECTS, outcome.details().get("rejected_variants"));
        assertEquals(Map.of("unsigned", "shibboleth-idp", "bad-signature", "shibboleth-idp",
                "signed-other-key", "shibboleth-idp"), outcome.details().get("native_rejections"));
    }

    @Test
    void extraVariantCannotReplaceAMissingRequiredRefusal() throws Exception {
        Files.writeString(directory.resolve(RUN + ".json"), rejectionReceipt(
                List.of("unsigned", "bad-signature", "xpath-identity")));
        writeReceipt(directory, receipt -> receipt);
        assertEquals(java.util.Optional.empty(), reevaluate());
    }

    private java.util.Optional<CaseOutcome> reevaluate() {
        var fallback = new MetadataFixtureObservationTestCase("IIP-MD03-a-idp-01", TargetRole.IDP,
                REJECTS.stream().map(variant -> new MetadataFixtureObservationTestCase.Fixture(
                        variant, MetadataFixtureObservationTestCase.Behavior.REJECT, "reject " + variant)).toList(),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var testCase = new MetadataRejectionConfigurationTestCase(fallback,
                MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
        var previous = new CaseOutcome(Outcome.NOT_VERIFIED, "metadata_fixture_probe_incomplete",
                "metadata.fixture-probe.incomplete", "metadata.fixture-probe.incomplete", List.of(),
                Map.of("missing_fetches", List.of(), "missing_acceptance", List.of(),
                        "unresolved_rejection", REJECTS));
        assertTrue(testCase.supportsRecordedEvidenceReevaluation(previous));
        return testCase.reevaluateRecordedEvidence(context(entries()), previous);
    }

    private String rejectionReceipt() {
        return rejectionReceipt(REJECTS);
    }

    private String rejectionReceipt(List<String> variants) {
        var raw = new ArrayList<String>();
        var rejections = new ArrayList<String>();
        for (var variant : variants) {
            var index = REJECTS.contains(variant) ? REJECTS.indexOf(variant) : 3;
            raw.add("{\"reference\":\"" + tx(200 + index) + "\",\"sha256\":\"" + sha(fixtureBytes(variant)) + "\"}");
            rejections.add("{\"variant\":\"" + variant + "\",\"fixtureSha256\":\"" + sha(fixtureBytes(variant))
                    + "\",\"nativeRejection\":{\"source\":\"shibboleth-idp\",\"detailSha256\":\""
                    + sha(("detail-" + variant).getBytes(StandardCharsets.UTF_8)) + "\"}}");
        }
        return "{\"schema\":\"samlscope-native-metadata-rejection-receipt-v1\""
                + ",\"runId\":\"" + RUN + "\""
                + ",\"restored\":true"
                + ",\"targetMetadataSha256\":\"" + sha(TARGET) + "\""
                + ",\"evidenceAdapter\":\"shibboleth-idp\""
                + ",\"rawEvidence\":[" + String.join(",", raw) + "]"
                + ",\"rejections\":[" + String.join(",", rejections) + "]}";
    }

    private List<TranscriptEntry> entries() {
        var entries = new ArrayList<TranscriptEntry>();
        for (int index = 0; index < REJECTS.size(); index++) {
            entries.add(prepared(200 + index, REJECTS.get(index)));
        }
        entries.add(prepared(203, "xpath-identity"));
        entries.addAll(correlationEntries());
        return entries;
    }

    private TranscriptEntry prepared(int sequence, String variant) {
        return new TranscriptEntry(tx(sequence), RUN, Direction.OUTBOUND, NOW.plusSeconds(sequence), "corr",
                "GET", "/metadata/live", 200, Map.of(), null, 0, "fixture-" + variant, 20, null, null,
                Map.of("type", "MetadataPrepared", "variant", variant));
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
}
