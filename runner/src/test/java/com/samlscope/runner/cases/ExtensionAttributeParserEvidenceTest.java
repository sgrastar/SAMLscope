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

class ExtensionAttributeParserEvidenceTest {
    @TempDir Path directory;
    static final String RUN = "run_00000000000000000000000001";
    private CaseContext context(boolean complete) {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("No writes"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new AssertionError("No edits"); }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, complete);
    }
    private ExtensionAttributeParserEvidence reader() { return new ExtensionAttributeParserEvidence(directory, entry -> { throw new AssertionError("No original available"); }, ignored -> "metadata_idp"); }
    private Path receipt() { return directory.resolve(RUN + ExtensionAttributeParserEvidence.SUFFIX); }
    private void unverified(boolean complete) {
        var result = reader().evaluate(context(complete), new byte[0]);
        assertEquals(Outcome.NOT_VERIFIED, result.outcome()); assertEquals("browser_fixture_partial", result.reasonCode());
        assertTrue(result.evidence().isEmpty());
    }
    @Test void absentReceiptCannotConclude() { assertFalse(reader().exists(RUN)); unverified(true); }
    @Test void claimedEqualTreesAndTwoHttpErrorsCannotConclude() throws Exception {
        Files.writeString(receipt(), "{\"parserSuccessful\":true,\"inputTree\":\"same\",\"controlTree\":\"same\",\"httpStatus\":400}");
        assertTrue(reader().exists(RUN)); unverified(true);
    }
    @Test void malformedOwnedReceiptRemainsUnverified() throws Exception { Files.writeString(receipt(), "not json"); unverified(true); }
    @Test void ownedDirectoryCannotBecomeEvidence() throws Exception { Files.createDirectory(receipt()); assertTrue(reader().exists(RUN)); unverified(true); }
    @Test void ownedSymlinkCannotBecomeEvidence() throws Exception {
        var other = directory.resolve("other.json"); Files.writeString(other, "{}"); Files.createSymbolicLink(receipt(), other); unverified(true);
    }
    @Test void incompleteHistoryCannotConclude() throws Exception { Files.writeString(receipt(), "{}"); unverified(false); }
    @Test void profileLabelsMustMatchTheActualRunPlan() throws Exception {
        byte[] target = "<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='urn:target'/>".getBytes();
        var json = new com.samlscope.store.JsonCodec().mapper().createObjectNode();
        json.put("schema", "samlscope-extension-attribute-parser-v1").put("adapter", "keycloak-native-affiliation-parser-v1")
                .put("caseId", ExtensionAttributeParserEvidence.ID).put("runId", RUN).put("sourceRunId", RUN)
                .put("targetMetadataSha256", ExtensionAttributeParserEvidence.sha(target)).put("targetEntityId", "urn:target").put("profile", "browser_sso_idp");
        Files.writeString(receipt(), json.toString());
        var result = reader().evaluate(context(true), target);
        assertEquals(Outcome.NOT_VERIFIED, result.outcome()); assertEquals("receipt_and_profile", result.details().get("unproven_stage"));
    }
}
