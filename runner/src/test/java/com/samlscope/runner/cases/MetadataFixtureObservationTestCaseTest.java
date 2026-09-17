package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;

class MetadataFixtureObservationTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void successfulSsoCannotProveKeyValueConsumptionWithSignatureValidationDisabled() {
        var testCase = new MetadataFixtureObservationTestCase("key-value", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture("keyvalue-only",
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "consume the signing key")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var entries = List.of(fetch("control", 1), use("control", 2),
                fetch("keyvalue-only", 3), use("keyvalue-only", 4));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, entries));
        var status = testCase.evidenceStatus(context(entries));
        assertEquals(false, status.ready());
        assertEquals(true, status.requiredObservations().contains("signature-discrimination:keyvalue-only"));
        assertEquals(false, status.completedObservations().contains("signature-discrimination:keyvalue-only"));
    }

    @Test
    void requiresWorkingControlAndAllFixtureFetchesBeforeItIsReady() {
        var testCase = testCase();
        var incomplete = testCase.evidenceStatus(context(List.of(fetch("control", 1), use("control", 2))));
        assertEquals(false, incomplete.ready());

        var ready = testCase.evidenceStatus(context(List.of(
                fetch("control", 1), use("control", 2),
                fetch("accepted", 3), use("accepted", 4), fetch("rejected", 5), use("rejected", 6))));
        assertEquals(true, ready.ready());
        assertEquals(6, ready.requiredObservations().size());
        assertEquals(6, ready.completedObservations().size());
    }

    @Test
    void judgesAcceptAndRejectFixturesWithoutUsingMissingObservationAsTargetFailure() {
        var testCase = testCase();
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(
                fetch("control", 1), use("control", 2),
                fetch("accepted", 3), use("accepted", 4), fetch("rejected", 5))));
        assertEquals(Outcome.VIOLATED, evaluate(testCase, List.of(
                fetch("control", 1), use("control", 2),
                fetch("accepted", 3), fetch("rejected", 4), use("rejected", 5))));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(
                fetch("control", 1), use("control", 2), fetch("accepted", 3))));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(
                fetch("control", 1), use("control", 2),
                fetch("accepted", 3), fetch("rejected", 4))));
        var acceptOnly = new MetadataFixtureObservationTestCase(
                "accept-only", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(
                        "accepted", MetadataFixtureObservationTestCase.Behavior.ACCEPT, "positive")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        assertEquals(Outcome.SATISFIED, evaluate(acceptOnly, List.of(
                fetch("control", 1), use("control", 2),
                fetch("accepted", 3), use("accepted", 4))));
    }

    @Test
    void preservesTheApprovedConfigurationFailureSemantics() {
        var context = context(List.of());
        var normative = testCase(ConfigurationFailureSemantics.NORMATIVE_CAPABILITY);
        var normativeStart = (CaseStep.AwaitConfig) normative.start(context);
        var absent = (CaseStep.Finish) normative.resume(
                context, normativeStart.next(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "missing"));
        assertEquals(Outcome.VIOLATED, absent.outcome().outcome());

        var precondition = testCase(ConfigurationFailureSemantics.TEST_PRECONDITION);
        var preconditionStart = (CaseStep.AwaitConfig) precondition.start(context);
        var unavailable = (CaseStep.Finish) precondition.resume(
                context, preconditionStart.next(),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "missing"));
        assertEquals(Outcome.NOT_VERIFIED, unavailable.outcome().outcome());
    }

    @Test
    void oneAggregateFetchSuppliesRetrievalButNotUseEvidenceForItsLogicalFixtures() {
        var acceptOnly = new MetadataFixtureObservationTestCase(
                "accept-only", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(
                        "accepted", MetadataFixtureObservationTestCase.Behavior.ACCEPT, "positive")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var aggregate = entry(3, "/metadata/preloaded", 0,
                Map.of("type", "MetadataFetch", "variant", "preloaded-aggregate",
                        "variants", List.of("accepted"), "feed", "preloaded"));
        var operatorDownload = entry(2, "/metadata/preloaded/download", 0,
                Map.of("type", "MetadataExport", "variant", "preloaded-aggregate",
                        "variants", List.of("accepted"), "feed", "preloaded-download"));

        var downloadOnly = acceptOnly.evidenceStatus(context(List.of(
                fetch("control", 1), use("control", 2), operatorDownload)));
        assertEquals(List.of("fetched:control", "used:control"),
                downloadOnly.completedObservations(),
                "an operator download is not evidence that the Target fetched metadata");

        var withoutUse = acceptOnly.evidenceStatus(context(List.of(
                fetch("control", 1), use("control", 2), aggregate)));
        assertEquals(List.of("fetched:control", "used:control", "fetched:accepted"),
                withoutUse.completedObservations());
        assertEquals(false, withoutUse.ready());
        assertEquals(Outcome.SATISFIED, evaluate(acceptOnly, List.of(
                fetch("control", 1), use("control", 2), aggregate, use("accepted", 4))));
    }

    @Test
    void anErrorResponseOrMismatchedRequestDoesNotBecomeMetadataUseEvidence() {
        var acceptOnly = new MetadataFixtureObservationTestCase(
                "accept-only", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture(
                        "accepted", MetadataFixtureObservationTestCase.Behavior.ACCEPT, "positive")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var error = entry(4,
                "https://suite.example/p/plan/sp/acs/0?mdv=accepted&run=" + RUN, 10,
                Map.of("type", "Response", "metadataProbeAccepted", true,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Responder"));
        var mismatch = entry(5,
                "https://suite.example/p/plan/sp/acs/0?mdv=accepted&run=" + RUN, 10,
                Map.of("type", "Response", "metadataProbeAccepted", false,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success"));

        assertEquals(Outcome.NOT_VERIFIED, evaluate(acceptOnly, List.of(
                fetch("control", 1), use("control", 2), fetch("accepted", 3), error, mismatch)));
    }

    @Test
    void defaultSelectionRequiresActualEndpointAndRetainsCounterexamples() {
        var testCase = new MetadataFixtureObservationTestCase("default-acs", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture("second",
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "select second", 1)),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        var prefix = List.of(fetch("control", 1), use("control", 2), fetch("second", 3));
        var correct = entry(4, "https://suite.example/p/plan/sp/acs/1?mdv=second&run=" + RUN,
                10, use("second", 4).samlSummary());
        var entries = new java.util.ArrayList<>(prefix);
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, entries));
        entries.add(correct);
        assertEquals(Outcome.SATISFIED, evaluate(testCase, entries));
        entries.add(use("second", 5));
        assertEquals(Outcome.VIOLATED, evaluate(testCase, entries));
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(fetch("second", 3), use("second", 5))));
    }

    @Test
    void staleUseAndPrefixCollisionCannotCompleteARequiredFixture() {
        var testCase = new MetadataFixtureObservationTestCase("exact", TargetRole.IDP,
                List.of(new MetadataFixtureObservationTestCase.Fixture("accepted",
                        MetadataFixtureObservationTestCase.Behavior.ACCEPT, "positive")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(
                fetch("control", 1), use("control", 2), use("accepted", 3), fetch("accepted", 4))));
        for (var query : List.of("mdv=accepted-other&run=" + RUN,
                "mdv=accepted&run=" + RUN + "-other", "mdv=accepted&run=" + RUN + "&run=" + RUN)) {
            var collision = entry(4, "https://suite.example/p/plan/sp/acs/0?" + query,
                    10, use("accepted", 4).samlSummary());
            assertEquals(Outcome.NOT_VERIFIED, evaluate(testCase, List.of(
                    fetch("control", 1), use("control", 2), fetch("accepted", 3), collision)));
        }
    }

    private MetadataFixtureObservationTestCase testCase() {
        return testCase(ConfigurationFailureSemantics.TEST_PRECONDITION);
    }

    private MetadataFixtureObservationTestCase testCase(ConfigurationFailureSemantics semantics) {
        return new MetadataFixtureObservationTestCase("case", TargetRole.IDP, List.of(
                new MetadataFixtureObservationTestCase.Fixture(
                        "accepted", MetadataFixtureObservationTestCase.Behavior.ACCEPT, "positive"),
                new MetadataFixtureObservationTestCase.Fixture(
                        "rejected", MetadataFixtureObservationTestCase.Behavior.REJECT, "negative")),
                semantics);
    }

    private Outcome evaluate(MetadataFixtureObservationTestCase testCase, List<TranscriptEntry> entries) {
        var context = context(entries);
        var start = (CaseStep.AwaitConfig) testCase.start(context);
        return ((CaseStep.Finish) testCase.resume(
                context, start.next(), new CaseEvent.ConfigConfirmed())).outcome().outcome();
    }

    private CaseContext context(List<TranscriptEntry> entries) {
        return new DefaultCaseContext(
                RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                com.samlscope.core.plan.TestPlan.Parameters.defaults(),
                com.samlscope.core.plan.TestPlan.Interaction.defaults(),
                com.samlscope.core.run.Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    @Override public TranscriptEntry record(TranscriptInput input) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public TranscriptEntry updateSamlAnalysis(
                            String entryId, String correlationId, Map<String, Object> samlSummary) {
                        throw new UnsupportedOperationException();
                    }
                    @Override public List<TranscriptEntry> list(String runId) { return entries; }
                }, true);
    }

    private TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, "/metadata/live", 0,
                Map.of("type", "MetadataFetch", "variant", variant, "feed", "live"));
    }

    private TranscriptEntry use(String variant, int sequence) {
        return entry(sequence, "https://suite.example/p/plan/sp/acs/0?mdv=" + variant + "&run=" + RUN,
                10, Map.of(
                        "type", "SAMLResponse",
                        "metadataProbeAccepted", true,
                        "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success"));
    }

    private TranscriptEntry entry(
            int sequence, String url, int decodedBytes, Map<String, Object> summary) {
        return new TranscriptEntry(
                "tr_" + sequence, RUN, Direction.INBOUND, NOW.plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedBytes > 0 ? "decoded" : null, decodedBytes,
                null, null, summary);
    }
}
