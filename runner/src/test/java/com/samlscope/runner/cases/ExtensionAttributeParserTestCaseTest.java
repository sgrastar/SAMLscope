package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ExtensionAttributeParserTestCaseTest {
    @TempDir Path directory;
    static final String RUN = ExtensionAttributeParserEvidenceTest.RUN;
    static final CaseOutcome PREVIOUS = CaseOutcome.notVerified("incomplete", "browser_fixture_partial");
    static final class Fallback implements TestCase, BrowserFrontChannelScenario, BrowserPrompt, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
        int replays;
        final CaseStep step = new CaseStep.Finish(PREVIOUS);
        public String id() { return ExtensionAttributeParserEvidence.ID; }
        public TargetRole role() { return TargetRole.IDP; }
        public CaseStep start(CaseContext context) { return step; }
        public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) { return step; }
        public String browserInstructionsEn() { return "original instructions"; }
        public String instructionsEn(CaseState state) { return "original step"; }
        public Binding outboundBinding(CaseState state) { return Binding.SIGNED_REDIRECT; }
        public boolean requiresFreshSession(CaseState state) { return true; }
        public boolean plansFreshSessionBoundary() { return true; }
        public int plannedDeliberateActions() { return 2; }
        public boolean sharesDeliberateAction() { return false; }
        public boolean requiresPreparationConfirmation() { return true; }
        public EvidenceStatus evidenceStatus(CaseContext context) { return new EvidenceStatus(false, List.of("original"), List.of(), Map.of()); }
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) { return true; }
        public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
            replays++; return Optional.of(CaseOutcome.of(Outcome.SATISFIED, "original", List.of(new EvidenceRef("transcript", "original"))));
        }
    }
    private CaseContext context(boolean complete) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("No writes"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new AssertionError("No edits"); }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
    }
    private ExtensionAttributeParserTestCase wrap(Fallback fallback) {
        return new ExtensionAttributeParserTestCase(fallback, e -> new byte[0], ignored -> new byte[0], directory);
    }
    @Test void existingBrowserActionsAndPreparationContractsArePreserved() {
        var original = new Fallback(); var wrapped = wrap(original);
        assertSame(original.step, wrapped.start(context(true))); assertSame(original.step, wrapped.resume(context(true), null, null));
        assertEquals(original.browserInstructionsEn(), wrapped.browserInstructionsEn()); assertEquals(original.instructionsEn(null), wrapped.instructionsEn(null));
        assertEquals(original.outboundBinding(null), wrapped.outboundBinding(null)); assertTrue(wrapped.requiresFreshSession(null));
        assertTrue(wrapped.plansFreshSessionBoundary()); assertTrue(wrapped.requiresPreparationConfirmation());
        assertEquals(2, wrapped.plannedDeliberateActions()); assertFalse(wrapped.sharesDeliberateAction());
        assertEquals(original.evidenceActionKeys(), wrapped.evidenceActionKeys());
    }
    @Test void absentReceiptRetainsOriginalReevaluation() {
        var original = new Fallback(); var wrapped = wrap(original);
        assertEquals(Outcome.SATISFIED, wrapped.reevaluateRecordedEvidence(context(true), PREVIOUS).orElseThrow().outcome());
        assertEquals(1, original.replays); assertEquals(List.of("original"), wrapped.evidenceStatus(context(true)).requiredObservations());
    }
    @Test void invalidOwnedReceiptCannotBeMaskedByTheGenericFallback() throws Exception {
        Files.writeString(directory.resolve(RUN + ExtensionAttributeParserEvidence.SUFFIX), "{}");
        var original = new Fallback(); var wrapped = wrap(original);
        assertTrue(wrapped.reevaluateRecordedEvidence(context(true), PREVIOUS).isEmpty()); assertEquals(0, original.replays);
        assertFalse(wrapped.evidenceStatus(context(true)).ready());
    }
    @Test void incompleteHistoryAndConclusivePreviousOutcomesDoNotReevaluate() {
        var original = new Fallback(); var wrapped = wrap(original);
        assertTrue(wrapped.reevaluateRecordedEvidence(context(false), PREVIOUS).isEmpty());
        assertTrue(wrapped.reevaluateRecordedEvidence(context(true), CaseOutcome.of(Outcome.VIOLATED, "original", List.of())).isEmpty());
        assertEquals(0, original.replays);
    }
    @Test void missingTargetMetadataUnderAnOwnedReceiptFailsClosed() throws Exception {
        Files.writeString(directory.resolve(RUN + ExtensionAttributeParserEvidence.SUFFIX), "{}");
        var original = new Fallback();
        var wrapped = new ExtensionAttributeParserTestCase(original, e -> new byte[0], ignored -> { throw new IllegalArgumentException("unavailable"); }, directory);
        assertFalse(wrapped.evidenceStatus(context(true)).ready()); assertTrue(wrapped.reevaluateRecordedEvidence(context(true), PREVIOUS).isEmpty());
        assertEquals(0, original.replays);
    }
}
