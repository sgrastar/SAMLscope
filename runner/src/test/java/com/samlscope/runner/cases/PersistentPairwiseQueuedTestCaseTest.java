package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.TestCaseRegistry;

class PersistentPairwiseQueuedTestCaseTest {
    @TempDir Path directory;
    private IdpExecutableBrowserFixtureScenarioTestCase scenario(String id) {
        return new IdpExecutableBrowserFixtureScenarioTestCase(id, ignored -> {
            throw new AssertionError("Queued evidence must not prepare or dispatch a scenario");
        });
    }
    private DefaultCaseContext context() {
        return new DefaultCaseContext("run_00000000000000000000000000", TargetRole.IDP,
                Clock.systemUTC(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) {
                        throw new AssertionError("Queued completion must not record a manufactured operation");
                    }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation,
                            java.util.Map<String,Object> summary) {
                        throw new AssertionError("Queued completion must not alter existing evidence");
                    }
                }, true);
    }
    @Test void absentNativeProofCannotFinishOrPrepareAQueuedScenario() {
        var test = new PersistentPairwiseQueuedTestCase(scenario(PersistentPairwiseNameIdEvidence.CASE));
        assertFalse(test.evidenceStatus(context()).ready());
        assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context()).outcome());
    }
    @Test void registryLimitsQueuedCompletionToPairwiseAndRejectsReceiptDeclarationsWithoutOriginals() throws Exception {
        var g03 = scenario(IdpExecutableBrowserFixtureScenarioTestCase.G03_CASE);
        var ext = scenario("IIP-EXT01-b-idp-01");
        var input = new TestCaseRegistry(List.of(scenario(PersistentPairwiseNameIdEvidence.CASE), g03, ext));
        var registry = ApprovedBrowserCaseRegistry.withNativeEcSignature(input,
                entry -> { throw new AssertionError("Missing originals cannot be read"); },
                run -> new byte[0], directory.resolve("ec-signature-evidence"));
        var test = assertInstanceOf(PersistentPairwiseQueuedTestCase.class,
                registry.require(PersistentPairwiseNameIdEvidence.CASE));
        assertFalse(registry.require(g03.id()) instanceof QueuedProtocolEvidenceCase);
        assertSame(ext, registry.require(ext.id()));
        var proofs = Files.createDirectories(directory.resolve("persistent-nameid-evidence"));
        Files.writeString(proofs.resolve(context().runId() + ".json"),
                "{\"same_principal\":true,\"restored\":true,\"outcome\":\"satisfied\"}");
        assertFalse(test.evidenceStatus(context()).ready());
        assertEquals(Outcome.NOT_VERIFIED, test.queuedEvidenceOutcome(context()).outcome());
    }
    @Test void unrelatedBrowserCasesCannotOptIntoPairwiseQueuedCompletion() {
        assertThrows(IllegalArgumentException.class, () ->
                new PersistentPairwiseQueuedTestCase(scenario(IdpExecutableBrowserFixtureScenarioTestCase.G03_CASE)));
        assertThrows(IllegalArgumentException.class, () ->
                new PersistentPairwiseQueuedTestCase(scenario("IIP-EXT01-b-idp-01")));
    }
}
