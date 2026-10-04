package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UiLogoBrowserEvidenceTestCaseTest {
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
    @Test void malformedNativeLogoProofCannotFallBackToLegacyReceiptOrCompleteQueuedCase() throws Exception {
        Files.writeString(directory.resolve(RUN), "invalid native originals");
        Files.writeString(directory.resolve(RUN + ".json"), "{\"outcome\":\"SATISFIED\"}");
        var test = new UiLogoBrowserEvidenceTestCase(e -> { throw new AssertionError("No originals"); },
                run -> new byte[0], directory);
        var outcome = test.queuedEvidenceOutcome(context(true));
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertTrue(((List<?>) outcome.details().get("evidence_issues")).contains("native-consent-originals-unproven"));
        assertFalse(test.evidenceStatus(context(true)).ready());
        assertTrue(test.reevaluateRecordedEvidence(context(true), outcome).isEmpty());
        assertTrue(test.reevaluateRecordedEvidence(context(false), outcome).isEmpty());
    }
}
