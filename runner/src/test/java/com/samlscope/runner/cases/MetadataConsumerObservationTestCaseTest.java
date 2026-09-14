package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

class MetadataConsumerObservationTestCaseTest {
    @Test
    void silenceRemainsUnverifiedAndAcceptanceOfExcludedContentIsDetected() {
        var variants = List.of(
                "xpath-exclude-role-descriptors",
                "xpath-exclude-endpoints",
                "xpath-exclude-key-descriptors");
        var safe = new ArrayList<TranscriptEntry>();
        safe.add(fetch("control", 1));
        safe.add(use("control", 2));
        var sequence = 3;
        for (var variant : variants) safe.add(fetch(variant, sequence++));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT, safe));

        safe.add(use("xpath-exclude-endpoints", sequence));
        assertEquals(Outcome.VIOLATED, evaluate(
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT, safe));
    }

    @Test
    void omittedKeyInfoRequiresAWorkingControlAndObservedVariantUse() {
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
    void permittedUnauthorizedTransformRecordsEitherChoiceWithoutInventingViolation() {
        var rejected = List.of(fetch("control", 1), use("control", 2), fetch("xpath-identity", 3));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(
                MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM, rejected));
        var accepted = new ArrayList<>(rejected);
        accepted.add(use("xpath-identity", 4));
        assertEquals(Outcome.SATISFIED_WITH_NOTE, evaluate(
                MetadataConsumerObservationTestCase.Rule.PERMITTED_IDENTITY_TRANSFORM, accepted));
    }

    private Outcome evaluate(
            MetadataConsumerObservationTestCase.Rule rule, List<TranscriptEntry> entries) {
        var testCase = new MetadataConsumerObservationTestCase(
                "IIP-MD05-test-sp-01", TargetRole.SP, rule);
        var start = (CaseStep.AwaitConfig) testCase.start(context(entries));
        var finish = (CaseStep.Finish) testCase.resume(
                context(entries), start.next(), new CaseEvent.ConfigConfirmed());
        return finish.outcome().outcome();
    }

    private CaseContext context(List<TranscriptEntry> entries) {
        return new CaseContext() {
            @Override public String runId() { return "run_0123456789ABCDEFGHJKMNPQRS"; }
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
            @Override public boolean transcriptComplete() { return true; }
        };
    }

    private TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, "/metadata?variant=" + variant, 0,
                Map.of("type", "MetadataFetch", "variant", variant));
    }

    private TranscriptEntry use(String variant, int sequence) {
        return entry(sequence,
                "https://suite.example/p/plan/idp/sso?mdv=" + variant
                        + "&run=run_0123456789ABCDEFGHJKMNPQRS",
                10, Map.of("type", "AuthnRequest"));
    }

    private TranscriptEntry entry(
            int sequence, String url, int decodedBytes, Map<String, Object> summary) {
        return new TranscriptEntry(
                "tr_" + sequence, "run_0123456789ABCDEFGHJKMNPQRS", Direction.INBOUND,
                Instant.parse("2026-08-29T00:00:00Z").plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedBytes > 0 ? "decoded" : null, decodedBytes,
                null, null, summary);
    }
}
