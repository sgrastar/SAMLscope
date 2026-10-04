package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.RUN;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.TARGET;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.fixtureBytes;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.sha;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.tx;
import static com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport.writeReceipt;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Evaluator;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.evaluation.Verdict;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

class MetadataConsumerObservationTestCaseTest {
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path directory;
    private static final List<String> EXCLUDED = List.of(
            "xpath-exclude-role-descriptors", "xpath-exclude-endpoints", "xpath-exclude-key-descriptors");

    @Test
    void silenceRemainsUnverifiedAndAcceptanceOfExcludedContentIsDetected() throws Exception {
        var safe = new ArrayList<TranscriptEntry>();
        safe.add(fetch("control", 1));
        safe.add(use("control", 2));
        var sequence = 3;
        for (var variant : EXCLUDED) safe.add(fetch(variant, sequence++));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT, safe));

        safe.add(use("xpath-exclude-endpoints", sequence));
        assertEquals(Outcome.VIOLATED, evaluate(
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT, safe));
    }

    @Test
    void omittedKeyInfoRequiresAWorkingControlAndObservedVariantUse() throws Exception {
        var complete = List.of(fetch("control", 1), use("control", 2),
                fetch("no-key-info", 3), use("no-key-info", 4));
        assertEquals(Outcome.SATISFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO, complete));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO,
                complete.subList(0, 3)));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO,
                List.of(fetch("no-key-info", 1), use("no-key-info", 2))));
    }

    @Test
    void permittedUnauthorizedTransformRecordsEitherChoiceWithoutInventingViolation() throws Exception {
        var rejected = List.of(fetch("control", 1), use("control", 2), fetch("xpath-identity", 3));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM, rejected));
        var accepted = new ArrayList<>(rejected);
        accepted.add(use("xpath-identity", 4));
        assertEquals(Outcome.SATISFIED_WITH_NOTE, evaluate(
                MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM, accepted));
    }

    @Test
    void acceptanceWithoutDocumentSignatureVerificationStaysNotVerified() throws Exception {
        var entries = List.of(fetch("control", 1), use("control", 2),
                fetch("no-key-info", 3), use("no-key-info", 4));
        var guarded = new MetadataConsumerObservationTestCase("IIP-MD05-ao-idp-01", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO,
                entry -> new byte[0], runId -> TARGET, directory);
        var start = (CaseStep.AwaitConfig) guarded.start(context(entries));
        var finish = (CaseStep.Finish) guarded.resume(
                context(entries), start.next(), new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("metadata.signature-verification.unproven", finish.outcome().reasonCode());
    }

    @Test
    void nativeRejectionReevaluationWithoutSignatureVerificationStaysUnresolved() throws Exception {
        Files.writeString(directory.resolve(RUN + ".json"), rejectionReceipt());
        var previous = new CaseOutcome(Outcome.NOT_VERIFIED, "metadata_consumer_probe_incomplete",
                "metadata.consumer-probe.incomplete", "metadata.consumer-probe.incomplete", List.of(),
                Map.of("missing_fetches", List.of()));
        // The native rejection receipt alone must not resolve MD05.am/an: the transform rules are only
        // decidable once the target is proven to verify document signatures.
        assertTrue(reevaluate(previous).isEmpty());
        writeReceipt(directory, receipt -> receipt);
        assertEquals(Outcome.SATISFIED, reevaluate(previous).orElseThrow().outcome());
    }

    @Test
    void lateSignatureOriginalsResolveAllThreeGateBlockedCasesWithoutRepeatingTheProbe() throws Exception {
        for (var rule : MetadataConsumerObservationTestCase.Rule.values()) {
            Files.deleteIfExists(directory.resolve(RUN + ".signature-verification.json"));
            var testCase = consumer(rule);
            var probeEntries = completeProbe(rule);
            var start = (CaseStep.AwaitConfig) testCase.start(context(probeEntries));
            var previous = ((CaseStep.Finish) testCase.resume(context(probeEntries), start.next(),
                    new CaseEvent.ConfigConfirmed())).outcome();
            assertEquals(Outcome.NOT_VERIFIED, previous.outcome());
            assertEquals("metadata.signature-verification.unproven", previous.reasonCode());
            assertTrue(testCase.supportsRecordedEvidenceReevaluation(previous));
            var originalEntries = MetadataSignatureVerificationTestSupport.withCorrelation(probeEntries);
            assertTrue(testCase.reevaluateRecordedEvidence(context(originalEntries), previous).isEmpty());
            // A late receipt missing its rejection original still does not prove the prerequisite.
            writeReceipt(directory, receipt -> receipt.replace(tx(121), tx(999)));
            assertTrue(testCase.reevaluateRecordedEvidence(context(originalEntries), previous).isEmpty());
            writeReceipt(directory, receipt -> receipt);
            var next = testCase.reevaluateRecordedEvidence(context(originalEntries), previous).orElseThrow();
            var expected = switch (rule) {
                case PERMITTED_IDENTITY_TRANSFORM -> Outcome.SATISFIED_WITH_NOTE;
                case EXCLUDED_CONTENT -> Outcome.VIOLATED;
                case OMITTED_KEY_INFO -> Outcome.SATISFIED;
            };
            assertEquals(expected, next.outcome());
            assertEquals(previous.details(), next.details());
            assertTrue(next.evidence().contains(new EvidenceRef("transcript", "transcript:" + tx(101))));
            assertTrue(next.evidence().contains(new EvidenceRef("transcript", "transcript:" + tx(121))));
            assertTrue(com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, next).isPresent());
            assertEquals(switch (rule) {
                case PERMITTED_IDENTITY_TRANSFORM -> Verdict.WARNING;
                case EXCLUDED_CONTENT -> Verdict.FAIL;
                case OMITTED_KEY_INFO -> Verdict.PASS;
            }, Evaluator.toVerdict(rule == MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT
                    ? Rfc2119Level.MUST : Rfc2119Level.MAY, next));
            assertTrue(testCase.reevaluateRecordedEvidence(context(originalEntries), next).isEmpty());
        }
    }

    @Test
    void lateSignatureProofCannotReplaceMissingVariantOrIncompleteTranscript() throws Exception {
        var rule = MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO;
        var testCase = consumer(rule);
        var probes = completeProbe(rule);
        var start = (CaseStep.AwaitConfig) testCase.start(context(probes));
        var previous = ((CaseStep.Finish) testCase.resume(context(probes), start.next(),
                new CaseEvent.ConfigConfirmed())).outcome();
        writeReceipt(directory, receipt -> receipt);
        var originals = MetadataSignatureVerificationTestSupport.withCorrelation(probes);
        assertTrue(testCase.reevaluateRecordedEvidence(context(originals, false), previous).isEmpty());
        var missingVariant = MetadataSignatureVerificationTestSupport.withCorrelation(probes.subList(0, 3));
        assertTrue(testCase.reevaluateRecordedEvidence(context(missingVariant), previous).isEmpty());
    }

    @Test
    void lateSignatureProofDoesNotReinterpretConfigurationUnavailableOrOtherReasons() throws Exception {
        var testCase = consumer(MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO);
        var originals = MetadataSignatureVerificationTestSupport.withCorrelation(
                completeProbe(MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO));
        writeReceipt(directory, receipt -> receipt);
        for (var issue : CaseEvent.ConfigurationIssue.values()) {
            var start = (CaseStep.AwaitConfig) testCase.start(context(originals));
            var unavailable = ((CaseStep.Finish) testCase.resume(context(originals), start.next(),
                    new CaseEvent.ConfigUnavailable(issue, "native configuration unavailable"))).outcome();
            assertEquals(Outcome.NOT_VERIFIED, unavailable.outcome());
            assertEquals("metadata.consumer-probe.unavailable", unavailable.reasonCode());
            assertEquals(issue.name().toLowerCase(java.util.Locale.ROOT),
                    unavailable.details().get("configuration_issue"));
            assertTrue(!testCase.supportsRecordedEvidenceReevaluation(unavailable));
            assertTrue(testCase.reevaluateRecordedEvidence(context(originals), unavailable).isEmpty());
        }
        assertTrue(!testCase.supportsRecordedEvidenceReevaluation(
                CaseOutcome.of(Outcome.VIOLATED, "capability_absent", List.of())));
        assertTrue(!testCase.supportsRecordedEvidenceReevaluation(
                CaseOutcome.notVerified("configuration_missing", "capability_undetermined")));
    }

    private MetadataConsumerObservationTestCase consumer(MetadataConsumerObservationTestCase.Rule rule) {
        var caseId = switch (rule) {
            case PERMITTED_IDENTITY_TRANSFORM -> "IIP-MD05-am-idp-01";
            case EXCLUDED_CONTENT -> "IIP-MD05-an-idp-01";
            case OMITTED_KEY_INFO -> "IIP-MD05-ao-idp-01";
        };
        return new MetadataConsumerObservationTestCase(caseId, TargetRole.IDP, rule,
                MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
    }

    private List<TranscriptEntry> completeProbe(MetadataConsumerObservationTestCase.Rule rule) {
        var entries = new ArrayList<TranscriptEntry>(List.of(fetch("control", 1), use("control", 2)));
        var variants = switch (rule) {
            case PERMITTED_IDENTITY_TRANSFORM -> List.of("xpath-identity");
            case EXCLUDED_CONTENT -> EXCLUDED;
            case OMITTED_KEY_INFO -> List.of("no-key-info");
        };
        int sequence = 3;
        for (var variant : variants) entries.add(fetch(variant, sequence++));
        entries.add(use(variants.getFirst(), sequence));
        return entries;
    }

    private java.util.Optional<CaseOutcome> reevaluate(CaseOutcome previous) {
        var testCase = new MetadataConsumerObservationTestCase("IIP-MD05-am-idp-01", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT,
                MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
        var entries = new ArrayList<TranscriptEntry>();
        for (int index = 0; index < EXCLUDED.size(); index++) entries.add(prepared(200 + index, EXCLUDED.get(index)));
        entries.addAll(MetadataSignatureVerificationTestSupport.correlationEntries());
        return testCase.reevaluateRecordedEvidence(context(entries), previous);
    }

    private String rejectionReceipt() {
        var raw = new ArrayList<String>();
        var rejections = new ArrayList<String>();
        for (int index = 0; index < EXCLUDED.size(); index++) {
            var variant = EXCLUDED.get(index);
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

    private Outcome evaluate(
            MetadataConsumerObservationTestCase.Rule rule, List<TranscriptEntry> entries) throws Exception {
        writeReceipt(directory, receipt -> receipt);
        var all = MetadataSignatureVerificationTestSupport.withCorrelation(entries);
        var testCase = new MetadataConsumerObservationTestCase(
                "IIP-MD05-test-sp-01", TargetRole.SP, rule,
                MetadataSignatureVerificationTestSupport.content(), runId -> TARGET, directory);
        var start = (CaseStep.AwaitConfig) testCase.start(context(all));
        var finish = (CaseStep.Finish) testCase.resume(
                context(all), start.next(), new CaseEvent.ConfigConfirmed());
        return finish.outcome().outcome();
    }

    private CaseContext context(List<TranscriptEntry> entries) {
        return context(entries, true);
    }

    private CaseContext context(List<TranscriptEntry> entries, boolean complete) {
        return new CaseContext() {
            @Override public String runId() { return RUN; }
            @Override public TargetRole targetRole() { return TargetRole.SP; }
            @Override public Clock clock() {
                return Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
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
                            String entryId, String correlationId, Map<String, Object> samlSummary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return entries; }
                };
            }
            @Override public boolean transcriptComplete() { return complete; }
        };
    }

    private TranscriptEntry prepared(int sequence, String variant) {
        return new TranscriptEntry(tx(sequence), RUN, Direction.OUTBOUND,
                Instant.parse("2026-08-29T00:00:00Z").plusSeconds(sequence), "corr", "GET", "/metadata/live",
                200, Map.of(), null, 0, "fixture-" + variant, fixtureBytes(variant).length, null, null,
                Map.of("type", "MetadataPrepared", "variant", variant));
    }

    private TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, "/metadata?variant=" + variant, 0,
                Map.of("type", "MetadataFetch", "variant", variant));
    }

    private TranscriptEntry use(String variant, int sequence) {
        return entry(sequence,
                "https://suite.example/p/plan/idp/sso?mdv=" + variant + "&run=" + RUN,
                10, Map.of("type", "AuthnRequest"));
    }

    private TranscriptEntry entry(
            int sequence, String url, int decodedBytes, Map<String, Object> summary) {
        return new TranscriptEntry(
                "tr_" + sequence, RUN, Direction.INBOUND,
                Instant.parse("2026-08-29T00:00:00Z").plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedBytes > 0 ? "decoded" : null, decodedBytes,
                null, null, summary);
    }
}
