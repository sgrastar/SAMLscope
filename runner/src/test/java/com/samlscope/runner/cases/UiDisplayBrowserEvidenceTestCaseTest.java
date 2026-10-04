package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UiDisplayBrowserEvidenceTestCaseTest {
    private static final String RUN = "run_00000000000000000000000000";
    @TempDir Path directory;

    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, true);
    }

    @Test void missingNativeFolderPreservesLegacyEvidencePath() {
        var test = new UiDisplayBrowserEvidenceTestCase(e -> { throw new AssertionError(); }, r -> new byte[0], directory);
        var outcome = test.observe(context());
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertFalse(((List<?>) outcome.details().get("evidence_issues"))
                .contains("native-consent-originals-unproven"));
    }

    @Test void malformedOwnedNativeProofCannotFallBackToLegacyReceipt() throws Exception {
        Files.writeString(directory.resolve(RUN), "invalid native proof");
        Files.writeString(directory.resolve(RUN + ".json"), "invalid legacy proof");
        var test = new UiDisplayBrowserEvidenceTestCase(e -> { throw new AssertionError(); }, r -> new byte[0], directory);
        var outcome = test.observe(context());
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertTrue(((List<?>) outcome.details().get("evidence_issues"))
                .contains("native-consent-originals-unproven"));
        assertTrue(test.reevaluateRecordedEvidence(context(), outcome).isEmpty());
    }
}
