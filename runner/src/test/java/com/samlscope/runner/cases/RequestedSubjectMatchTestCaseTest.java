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

class RequestedSubjectMatchTestCaseTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path directory;
    private IdpExecutableBrowserFixtureScenarioTestCase fallback(String id) {
        return new IdpExecutableBrowserFixtureScenarioTestCase(id, r -> new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp", URI.create("https://suite.example/acs"),
                Duration.ofMinutes(1), true, true, true), r -> Optional.empty());
    }
    private RequestedSubjectMatchTestCase implementation() {
        return fallback(RequestedSubjectMatchTestCase.CASE).withRequestedSubjectMatchEvidence(directory,
                e -> { throw new AssertionError("No native original available"); }, r -> new byte[0]);
    }
    private CaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Outbox only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Unchanged history");
                    }
                }, complete);
    }
    @Test void absentProofPreservesTheActiveScenarioAndBrowserPresentation() {
        var original = fallback(RequestedSubjectMatchTestCase.CASE);
        var test = original.withRequestedSubjectMatchEvidence(directory, e -> new byte[0], r -> new byte[0]);
        assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context(false)));
        assertEquals(original.browserInstructionsEn(), test.browserInstructionsEn());
        assertEquals(original.evidenceCampaignId(), test.evidenceCampaignId());
        assertEquals(original.evidenceActionKeys(), test.evidenceActionKeys());
        assertFalse(test.evidenceStatus(context(true)).ready());
    }
    @Test void ownedMalformedProofShadowsStartResumeReadinessAndReevaluation() throws Exception {
        Files.createDirectory(directory.resolve(RUN)); Files.writeString(directory.resolve(RUN).resolve("manifest.json"), "{}");
        var test = implementation();
        for (boolean complete : List.of(true, false)) {
            assertUnproven(test.start(context(complete)));
            for (var event : List.<CaseEvent>of(new CaseEvent.TranscriptReady(), new CaseEvent.ConfigConfirmed(),
                    new CaseEvent.Aborted("cancel"), new CaseEvent.TimedOut(Duration.ofSeconds(1))))
                assertUnproven(test.resume(context(complete), null, event));
            assertFalse(test.evidenceStatus(context(complete)).ready());
            assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context(complete)).outcome());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(true), CaseOutcome.notVerified("partial", "browser_fixture_partial")).isEmpty());
    }
    @Test void fileAndSymlinkOwnTheBranchInsteadOfFallingThrough() throws Exception {
        var selected = directory.resolve(RUN); Files.writeString(selected, "not a directory");
        assertUnproven(implementation().start(context(true))); Files.delete(selected);
        var other = Files.createDirectory(directory.resolve("other"));
        Files.createSymbolicLink(selected, other); assertUnproven(implementation().start(context(true)));
    }
    @Test void queuedEvidenceDoesNotConstructOrDispatchAProtocolRequest() {
        var original = new IdpExecutableBrowserFixtureScenarioTestCase(RequestedSubjectMatchTestCase.CASE,
                r -> { throw new AssertionError("Queued evidence must not start scenario"); }, r -> Optional.empty());
        var test = original.withRequestedSubjectMatchEvidence(directory, e -> new byte[0], r -> new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context(true)).outcome());
    }
    @Test void existingConclusionsAndIncompleteHistoryCannotBeReplaced() {
        var test = implementation();
        for (var outcome : List.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED)) {
            var previous = CaseOutcome.of(outcome, "previous", List.of());
            assertFalse(test.supportsRecordedEvidenceReevaluation(previous));
            assertTrue(test.reevaluateRecordedEvidence(context(true), previous).isEmpty());
        }
        assertTrue(test.reevaluateRecordedEvidence(context(false), CaseOutcome.notVerified("partial", "browser_fixture_partial")).isEmpty());
    }
    @Test void compositionWrapsOnlyTheRequestedSubjectCase() {
        var approved = fallback(RequestedSubjectMatchTestCase.CASE); var other = fallback("IIP-G02-a-idp-01");
        var composed = ApprovedBrowserCaseRegistry.withNativeEcSignature(new TestCaseRegistry(List.of(approved, other)),
                e -> new byte[0], r -> new byte[0], directory.resolve("ec-signature-evidence"));
        assertInstanceOf(RequestedSubjectMatchTestCase.class, composed.require(approved.id()));
        assertSame(other, composed.require(other.id()));
        assertThrows(IllegalStateException.class, () -> other.withRequestedSubjectMatchEvidence(directory, e -> new byte[0], r -> new byte[0]));
    }
    private static void assertUnproven(CaseStep step) {
        var result = assertInstanceOf(CaseStep.Finish.class, step).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome()); assertEquals("idp.subject.native-match-unproven", result.reasonCode());
    }
}
