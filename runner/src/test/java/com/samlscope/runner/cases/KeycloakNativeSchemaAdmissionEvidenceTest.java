package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeycloakNativeSchemaAdmissionEvidenceTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000001";
    private CaseContext context(boolean complete) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
    }
    private KeycloakNativeSchemaAdmissionEvidence reader() { return new KeycloakNativeSchemaAdmissionEvidence(directory, e -> new byte[0]); }
    private Path path() { return directory.resolve(RUN + ".keycloak-schema-admission.json"); }
    private void incomplete(boolean complete) {
        var result = reader().evaluate(context(complete), new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertEquals("metadata.schema.native-admission-incomplete", result.reasonCode());
        assertTrue(result.evidence().isEmpty());
    }
    @Test void noReceiptDoesNotClaimANativeCounterexample() { assertFalse(reader().exists(RUN)); incomplete(true); }
    @Test void bareNativeStatusAndClaimedRestorationHaveNoDetectionPower() throws Exception {
        Files.writeString(path(), "{\"runId\":\"" + RUN + "\",\"httpStatus\":400,\"restored\":true,\"nativeParserRejected\":true}");
        assertTrue(reader().exists(RUN)); incomplete(true);
    }
    @Test void ownedMalformedReceiptRemainsOwned() throws Exception {
        Files.writeString(path(), "not json"); assertTrue(reader().exists(RUN)); incomplete(true);
    }
    @Test void ownedDirectoryMustNotEscapeIntoGenericFallback() throws Exception {
        Files.createDirectory(path()); assertTrue(reader().exists(RUN)); incomplete(true);
    }
    @Test void ownedSymlinkIsRejectedEvenWhenItPointsToAReadableReceipt() throws Exception {
        var outside = directory.resolve("other.json"); Files.writeString(outside, "{}");
        Files.createSymbolicLink(path(), outside); assertTrue(reader().exists(RUN)); incomplete(true);
    }
    @Test void incompleteHistoryCannotAcquireAConclusiveNativeOutcome() throws Exception {
        Files.writeString(path(), "{}"); assertTrue(reader().exists(RUN)); incomplete(false);
    }
}
