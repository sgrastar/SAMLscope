package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeUiFeatureAbsenceTestCaseTest {
    @TempDir Path directory;
    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext("run_00000000000000000000000000", TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, complete);
    }
    private static final CaseOutcome PROVEN = new CaseOutcome(Outcome.SATISFIED, null, "observed", "observed",
            List.of(new EvidenceRef("transcript", "tx_new")), Map.of());
    private static final class Reader implements TestCase, QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
        int recordedCalls, queuedCalls;
        public String id() { return UiDisplayComparison.CASE_ID; }
        public TargetRole role() { return TargetRole.IDP; }
        public CaseStep start(CaseContext context) { throw new AssertionError("No new scenario"); }
        public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { throw new AssertionError("No new scenario"); }
        public CaseOutcome queuedEvidenceOutcome(CaseContext context) { queuedCalls++; return PROVEN; }
        public EvidenceStatus evidenceStatus(CaseContext context) { return new EvidenceStatus(true, List.of(), List.of(), Map.of()); }
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) { return "delegate-missing".equals(previous.reasonCode()); }
        public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
            recordedCalls++; return RecordedEvidenceReevaluation.conclusiveUpdate(previous, PROVEN);
        }
    }
    private NativeUiFeatureAbsenceTestCase wrapper(Reader delegate) {
        return new NativeUiFeatureAbsenceTestCase(delegate, r -> new byte[0],
                new NativeUiFeatureAbsenceEvidence(directory, e -> { throw new AssertionError(); }));
    }
    @Test void activeDelegateRecordedEvidenceIsNotShadowedByAbsentNonuseProof() {
        var delegate = new Reader();
        var result = wrapper(delegate).reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("missing", "delegate-missing"));
        assertEquals(PROVEN, result.orElseThrow());
        assertEquals(1, delegate.recordedCalls); assertEquals(0, delegate.queuedCalls);
    }
    @Test void oldWrapperReasonCanUseOnlyOptedInReadOnlyDelegate() {
        var delegate = new Reader();
        var result = wrapper(delegate).reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("missing", "browser.ui-native-feature.evidence-incomplete"));
        assertEquals(PROVEN, result.orElseThrow());
        assertEquals(0, delegate.recordedCalls); assertEquals(1, delegate.queuedCalls);
    }
    @Test void incompleteTranscriptNeverInvokesReadOnlyDelegate() {
        var delegate = new Reader();
        assertTrue(wrapper(delegate).reevaluateRecordedEvidence(context(false),
                CaseOutcome.notVerified("missing", "delegate-missing")).isEmpty());
        assertEquals(0, delegate.recordedCalls + delegate.queuedCalls);
    }
    @Test void ownedUnprovenShibbolethOriginalsCannotUseAConclusiveFallback() throws Exception {
        var nativeDirectory = directory.resolve("native-shib");
        var manifest = nativeDirectory.resolve("run_00000000000000000000000000/manifest.json");
        Files.createDirectories(manifest.getParent());
        Files.writeString(manifest, "{}");
        var delegate = new Reader();
        var wrapper = new NativeUiFeatureAbsenceTestCase(delegate, r -> new byte[0],
                new NativeUiFeatureAbsenceEvidence(directory, e -> { throw new AssertionError(); }),
                new ShibbolethUiConsumerEvidence(nativeDirectory, e -> { throw new AssertionError(); }));
        assertEquals(Outcome.NOT_VERIFIED, wrapper.queuedEvidenceOutcome(context(true)).outcome());
        assertFalse(wrapper.evidenceStatus(context(true)).ready());
        assertTrue(wrapper.reevaluateRecordedEvidence(context(true),
                CaseOutcome.notVerified("missing", "delegate-missing")).isEmpty());
        assertEquals(0, delegate.recordedCalls + delegate.queuedCalls);
    }
}
