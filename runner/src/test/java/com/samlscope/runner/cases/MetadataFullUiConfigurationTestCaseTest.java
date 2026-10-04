package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MetadataFullUiConfigurationTestCaseTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000000";
    private static final TestCase UNSAFE_IMPORT_SUCCESS = new TestCase() {
        public String id() { return MetadataFullUiConfigurationTestCase.CASE; }
        public TargetRole role() { return TargetRole.IDP; }
        public CaseStep start(CaseContext c) { throw new AssertionError("Import-only delegate must never decide full UI"); }
        public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { throw new AssertionError("Old receipt must not bypass values"); }
    };
    static CaseContext context() {
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String id) { return List.of(); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new UnsupportedOperationException(); }
        };
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
    }
    private MetadataFullUiConfigurationTestCase testCase() {
        return new MetadataFullUiConfigurationTestCase(UNSAFE_IMPORT_SUCCESS,
                new ShibbolethMetadataFullUiEvidence(directory, e -> null), id -> new byte[]{1});
    }
    @Test void MissingProofRequiresConfigAndCreatesNoBrowserAction() {
        var test = testCase(); var step = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context()));
        assertTrue(step.actions().isEmpty());
        assertEquals(RunCampaignQuery.ActionKind.CONFIGURATION, test.evidenceActionKind());
        assertFalse(test.evidenceStatus(context()).ready());
        assertFalse(((Object)test) instanceof BrowserFrontChannelScenario);
    }
    @Test void LegacyPhaseAndOldImportReceiptCannotConfirmValues() {
        var test = testCase(); var state = new CaseState("await-metadata-fixture-probe", Map.of());
        var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context(), state, new CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertTrue(test.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("pending", "case.pending-interaction")));
        assertTrue(test.reevaluateRecordedEvidence(context(), CaseOutcome.notVerified("pending", "case.pending-interaction")).isEmpty());
    }
    @Test void ConfigurationUnavailabilityRemainsTestPreconditionNotProductFailure() {
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase().resume(context(), new CaseState("old", Map.of()),
                new CaseEvent.ConfigUnavailable(CaseEvent.ConfigurationIssue.CAPABILITY_ABSENT, "No native full UI export")));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }
    @Test void OwnedPartialOrSymbolicReceiptCannotFallBackToImportSuccess() throws Exception {
        Files.createDirectory(directory.resolve(RUN)); var reader = new ShibbolethMetadataFullUiEvidence(directory, e -> null);
        assertTrue(reader.exists(RUN)); assertEquals(Outcome.NOT_VERIFIED, reader.evaluate(context(), new byte[]{1}).orElseThrow().outcome());
        Files.writeString(directory.resolve("foreign"), "{}");
        Files.createSymbolicLink(directory.resolve(RUN).resolve("manifest.json"), directory.resolve("foreign"));
        assertEquals(Outcome.NOT_VERIFIED, reader.evaluate(context(), new byte[]{1}).orElseThrow().outcome());
    }
    @Test void PublicReaderRejectsDeveloperPayloadBeforeReadingNativeOriginals() throws Exception {
        Files.createDirectory(directory.resolve(RUN));
        Files.writeString(directory.resolve(RUN).resolve("manifest.json"), """
                {"schema":"samlscope-metadata-full-ui-native-v1","adapter":"shibboleth-metadata-resolver-full-ui-v1",
                "campaignId":"native-metadata-full-ui","runId":"run_00000000000000000000000000",
                "counterfactualCalibrationOnly":true}
                """);
        assertEquals(Outcome.NOT_VERIFIED,
                new ShibbolethMetadataFullUiEvidence(directory, e -> null).evaluate(context(), new byte[]{1}).orElseThrow().outcome());
    }
}
