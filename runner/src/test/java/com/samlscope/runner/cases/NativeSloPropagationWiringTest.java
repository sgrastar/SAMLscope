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

class NativeSloPropagationWiringTest {
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

    private LogoutBrowserEvidenceTestCase original(String id) {
        var attestation = new AttestedOutcomeTestCase(id, TargetRole.IDP, "slo", "Observe SLO.",
                Duration.ofHours(1), List.of(AttestationOption.notVerified("unavailable", "slo.unavailable", "unavailable")));
        var browser = new BrowserEvidenceTestCase(attestation, URI.create("https://suite.example"),
                "Complete the target-initiated logout.", Duration.ofHours(1));
        return new LogoutBrowserEvidenceTestCase(browser, entry -> { throw new AssertionError("No invented original"); },
                run -> Optional.empty(), run -> List.of());
    }

    private TestCase hooked(String id) {
        return ApprovedBrowserCaseRegistry.withLogoutScenarios(new TestCaseRegistry(List.of(original(id))),
                (caseId, run) -> { throw new AssertionError("Passive native proof must not dispatch an active fixture"); },
                entry -> { throw new AssertionError("No invented original"); }, directory).require(id);
    }

    private void invalidNativeProof() throws Exception {
        var folder = directory.resolve("slo-propagation-evidence").resolve(RUN);
        Files.createDirectories(folder);
        Files.writeString(folder.resolve("manifest.json"), "{}");
    }

    @Test void missingNativeProofKeepsTheApprovedBrowserCampaign() {
        var test = hooked(ShibbolethNativeSloPropagationEvidence.CASE);
        assertInstanceOf(CaseStep.AwaitBrowser.class, test.start(context(true)));
        assertEquals("target-initiated-logout", ((EvidenceCampaignCase)test).evidenceCampaignId());
        assertEquals("Complete the target-initiated logout.", ((BrowserPrompt)test).browserInstructionsEn());
    }

    @Test void invalidOwnedProofCannotStartAnotherBrowserActionOrDeclareReadiness() throws Exception {
        invalidNativeProof();
        var test = hooked(ShibbolethNativeSloPropagationEvidence.CASE);
        var finish = assertInstanceOf(CaseStep.Finish.class, test.start(context(true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("slo.native-propagation.evidence-incomplete", finish.outcome().reasonCode());
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context(true)).ready());
        assertTrue(((ProtocolEvidenceCase)test).evidenceStatus(context(true)).completedObservations().isEmpty());
        var recorded = (RecordedEvidenceReevaluation)test;
        assertTrue(recorded.reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("waiting", "slo.waiting")).isEmpty());
    }

    @Test void campaignConcludeAndTranscriptResumeRequireTheSameOriginals() throws Exception {
        invalidNativeProof();
        var test = hooked(ShibbolethNativeSloPropagationEvidence.CASE);
        for (var event : List.of(new CaseEvent.Aborted("target-initiated-not-issued"), new CaseEvent.TranscriptReady())) {
            var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context(true), CaseState.initial(), event));
            assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
            assertEquals("slo.native-propagation.evidence-incomplete", finish.outcome().reasonCode());
        }
    }

    @Test void incompleteHistoryCannotAdoptNativeProof() throws Exception {
        invalidNativeProof();
        var test = hooked(ShibbolethNativeSloPropagationEvidence.CASE);
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                test.start(context(false))).outcome().outcome());
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context(false)).ready());
        assertTrue(((RecordedEvidenceReevaluation)test).reevaluateRecordedEvidence(context(false),
                CaseOutcome.notVerified("waiting", "slo.waiting")).isEmpty());
    }

    @Test void parallelPropagationProofDoesNotChangeTheContinuationRule() throws Exception {
        invalidNativeProof();
        var test = original("IIP-IDP17-r-idp-01").withNativePropagation(
                directory.resolve("slo-soap-continuation-evidence"),
                run -> { throw new AssertionError("Parallel proof is not SOAP continuation evidence"); });
        assertInstanceOf(CaseStep.AwaitBrowser.class, test.start(context(true)));
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context(true)).ready());
    }
}
