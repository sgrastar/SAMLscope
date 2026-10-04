package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SoapSloContinuationWiringTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path directory;

    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, complete);
    }

    private LogoutBrowserEvidenceTestCase observer() {
        String id = ShibbolethNativeSloContinuationEvidence.CASE;
        var attestation = new AttestedOutcomeTestCase(id, TargetRole.IDP, "slo", "Observe continuation.",
                Duration.ofHours(1), List.of(AttestationOption.notVerified("unavailable", "slo.unavailable", "unavailable")));
        var browser = new BrowserEvidenceTestCase(attestation, URI.create("https://suite.example"),
                "Complete the target-initiated logout.", Duration.ofHours(1));
        return new LogoutBrowserEvidenceTestCase(browser,
                entry -> { throw new AssertionError("Missing originals must not be invented"); },
                run -> Optional.empty(), run -> List.of()).withNativePropagation(
                        directory.resolve("slo-soap-continuation-evidence"),
                        run -> { throw new AssertionError("Invalid manifest must be rejected first"); });
    }

    private void invalidProof() throws Exception {
        var folder = directory.resolve("slo-soap-continuation-evidence").resolve(RUN);
        Files.createDirectories(folder);
        Files.writeString(folder.resolve("manifest.json"), "{}");
    }

    @Test void invalidOwnedProofCannotStartAnotherBrowserActionOrDeclareReadiness() throws Exception {
        invalidProof();
        var test = observer();
        var result = assertInstanceOf(CaseStep.Finish.class, test.start(context(true))).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("slo.propagation.native-soap-evidence-incomplete", result.reasonCode());
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.evidenceStatus(context(true)).completedObservations().isEmpty());
    }

    @Test void resumeAndReevaluationApplyTheSameOriginalsGate() throws Exception {
        invalidProof();
        var test = observer();
        for (var event : List.of(new CaseEvent.Aborted("target-initiated-not-issued"), new CaseEvent.TranscriptReady())) {
            var result = assertInstanceOf(CaseStep.Finish.class,
                    test.resume(context(true), CaseState.initial(), event)).outcome();
            assertEquals(Outcome.NOT_VERIFIED, result.outcome());
            assertEquals("slo.propagation.native-soap-evidence-incomplete", result.reasonCode());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("waiting", "slo.waiting")).isEmpty());
    }

    @Test void incompleteHistoryCannotAdoptNativeProof() throws Exception {
        invalidProof();
        var test = observer();
        assertEquals(Outcome.NOT_VERIFIED,
                assertInstanceOf(CaseStep.Finish.class, test.start(context(false))).outcome().outcome());
        assertFalse(test.evidenceStatus(context(false)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(false),
                CaseOutcome.notVerified("waiting", "slo.waiting")).isEmpty());
    }

    @Test void parallelPartialLogoutProofDoesNotBecomeContinuationEvidence() throws Exception {
        var old = directory.resolve("slo-propagation-evidence").resolve(RUN);
        Files.createDirectories(old);
        Files.writeString(old.resolve("manifest.json"), "{}");
        var test = observer();
        assertInstanceOf(CaseStep.AwaitBrowser.class, test.start(context(true)));
        assertFalse(test.evidenceStatus(context(true)).ready());
    }

    @Test void registryDoesNotRestartAnOwnedInvalidCampaign() throws Exception {
        invalidProof();
        var test = ApprovedBrowserCaseRegistry.withLogoutScenarios(new TestCaseRegistry(List.of(observer())),
                (id, run) -> { throw new AssertionError("An owned campaign must not dispatch a new fixture"); },
                entry -> { throw new AssertionError("No invented original"); }, directory)
                .require(ShibbolethNativeSloContinuationEvidence.CASE);
        assertInstanceOf(SoapSloPropagationTestCase.class, test);
        var result = assertInstanceOf(CaseStep.Finish.class, test.start(context(true))).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("slo.propagation.native-soap-evidence-incomplete", result.reasonCode());
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context(true)).ready());
    }

    @Test void registryCannotInferSoapCapabilityFromParallelPartialLogoutProof() throws Exception {
        var old = directory.resolve("slo-propagation-evidence").resolve(RUN);
        Files.createDirectories(old);
        Files.writeString(old.resolve("manifest.json"), "{}");
        var test = ApprovedBrowserCaseRegistry.withLogoutScenarios(new TestCaseRegistry(List.of(observer())),
                (id, run) -> null, entry -> { throw new AssertionError("No invented original"); }, directory)
                .require(ShibbolethNativeSloContinuationEvidence.CASE);
        var result = assertInstanceOf(CaseStep.Finish.class, test.start(context(true))).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("slo.propagation.soap-preparation-unavailable", result.reasonCode());
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context(true)).ready());
    }
}
