package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;

class PersistentPairwiseNameIdEvidenceTest {
    @TempDir Path directory;
    private static final String RUN = "run_00000000000000000000000000";
    private DefaultCaseContext context(boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Proof reader wrote evidence"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Proof reader changed evidence");
                    }
                }, complete);
    }
    private PersistentPairwiseNameIdEvidence reader() {
        return new PersistentPairwiseNameIdEvidence(directory, entry -> new byte[0],
                run -> new byte[0], run -> Optional.empty());
    }
    @Test void nakedReceiptAndMissingOriginalsCannotConclude() throws Exception {
        assertTrue(reader().evaluate(context(true)).isEmpty());
        var folder = Files.createDirectory(directory.resolve(RUN));
        Files.writeString(folder.resolve("manifest.json"), "{\"schema\":\"" + PersistentPairwiseNameIdEvidence.SCHEMA
                + "\",\"runId\":\"" + RUN + "\",\"same_principal\":true,\"restored\":true}");
        assertTrue(reader().evaluate(context(true)).isEmpty());
        assertTrue(reader().evaluate(context(false)).isEmpty());
    }
    @Test void symlinkedCampaignCannotReadOutsideItsDirectory() throws Exception {
        var external = Files.createDirectory(directory.resolve("external"));
        Files.writeString(external.resolve("manifest.json"), "{}");
        Files.createSymbolicLink(directory.resolve(RUN), external);
        assertTrue(reader().evaluate(context(true)).isEmpty());
    }
    @Test void reevaluationRetainsUnverifiedWithoutTwoPeerProof() {
        var testCase = new IdpExecutableBrowserFixtureScenarioTestCase(PersistentPairwiseNameIdEvidence.CASE,
                run -> null).withPersistentPairwiseEvidence(directory, entry -> new byte[0], run -> new byte[0]);
        var previous = new CaseOutcome(Outcome.NOT_VERIFIED, "additional_variants_not_externally_observable",
                "browser_fixture_partial", "case.idp.browser-fixture.partial", List.of(), Map.of());
        assertTrue(testCase.supportsRecordedEvidenceReevaluation(previous));
        assertTrue(testCase.reevaluateRecordedEvidence(context(true), previous).isEmpty());
        assertFalse(testCase.evidenceStatus(context(true)).ready());
        var priorPass = new CaseOutcome(Outcome.SATISFIED, null, "observed", "observed", List.of(), Map.of());
        assertFalse(testCase.supportsRecordedEvidenceReevaluation(priorPass));
        assertTrue(testCase.reevaluateRecordedEvidence(context(true), priorPass).isEmpty());
    }
}
