package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class MetadataRejectionEvidenceFileTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000000";
    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Observer wrote a transcript"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new AssertionError("Observer mutated a transcript"); }
        }, true);
    }
    @Test void absentReceiptYieldsNoNativeRejection() throws Exception {
        var reader = new MetadataRejectionEvidenceFile(directory);
        assertFalse(reader.exists(RUN));
        assertTrue(reader.rejectedVariants(context(), new byte[0], e -> new byte[0]).isEmpty());
    }
    @Test void malformedOrMisboundReceiptIsRejected() throws Exception {
        var reader = new MetadataRejectionEvidenceFile(directory);
        Files.writeString(directory.resolve(RUN + ".json"), "{\"schema\":\"other\",\"runId\":\"" + RUN + "\"}");
        assertTrue(reader.exists(RUN));
        assertThrows(IllegalArgumentException.class, () -> reader.rejectedVariants(context(), new byte[0], e -> new byte[0]));
        Files.writeString(directory.resolve(RUN + ".json"),
                "{\"schema\":\"samlscope-native-metadata-rejection-receipt-v1\",\"runId\":\"" + RUN
                        + "\",\"restored\":true,\"targetMetadataSha256\":\"" + "0".repeat(64)
                        + "\",\"evidenceAdapter\":\"shibboleth-resolver\"}");
        assertThrows(IllegalArgumentException.class, () -> reader.rejectedVariants(context(), new byte[0], e -> new byte[0]));
    }
}
