package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.cases.*;
import com.samlscope.store.*;

class RecordedEvidenceReevaluationTest {
    @TempDir java.nio.file.Path directory;
    private static final String RUN = "run_evidence";
    private static final Instant NOW = Instant.parse("2026-09-14T00:00:00Z");

    @Test void lateEvidenceUpdatesTheResultOnceAndArchivesTheOriginalWithoutSending() {
        var repository = repository();
        var transitions = new CaseExecutionService(repository);
        var entries = new ArrayList<>(List.of(fetch("control", 1), use("control", 2), fetch("candidate", 3)));
        var test = fixture("late", false);
        var context = context(entries, true);
        transitions.start(RUN, test, context);
        var original = transitions.resume(RUN, test, context, new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED, original.outcome().outcome());
        var automation = new ProtocolEvidenceAutomationService(repository, new TestCaseRegistry(List.of(test)), transitions, ignored -> context);
        assertEquals(0, automation.status(RUN).readyCases());
        entries.add(use("candidate", 4));
        assertEquals(1, automation.status(RUN).readyCases());
        assertEquals(1, automation.evaluateReady(RUN).completed().size());
        var updated = repository.find(RUN, test.id()).orElseThrow();
        assertEquals(original.revision() + 1, updated.revision());
        assertEquals(CaseExecutionStatus.FINISHED, updated.status());
        assertEquals(Outcome.SATISFIED, updated.outcome().outcome());
        var archived = (Map<?, ?>) updated.state().data().get("previous_recorded_evidence_result");
        assertEquals("NOT_VERIFIED", archived.get("outcome"));
        assertEquals(original.outcome().reasonCode(), archived.get("reason_code"));
        assertEquals(original.outcome().details(), archived.get("details"));
        assertFalse(((List<?>) archived.get("evidence")).isEmpty());
        assertTrue(repository.listOutbox(RUN).isEmpty());
        assertTrue(automation.evaluateReady(RUN).completed().isEmpty());
        assertEquals(updated, transitions.resume(RUN, test, context, new CaseEvent.ConfigConfirmed()),
                "ordinary resume must keep terminal executions terminal");
    }

    @Test void forbiddenMetadataUseCanResolveAnIncompleteRejectionObservation() {
        var repository = repository();
        var transitions = new CaseExecutionService(repository);
        var entries = new ArrayList<>(List.of(fetch("control", 1), use("control", 2), fetch("candidate", 3)));
        var test = fixture("reject", true);
        var context = context(entries, true);
        transitions.start(RUN, test, context);
        transitions.resume(RUN, test, context, new CaseEvent.ConfigConfirmed());
        assertEquals(Outcome.NOT_VERIFIED, transitions.reevaluateRecordedEvidence(RUN, test, context).outcome().outcome());
        entries.add(use("candidate", 4));
        assertEquals(Outcome.VIOLATED, transitions.reevaluateRecordedEvidence(RUN, test, context).outcome().outcome());
        assertTrue(repository.listOutbox(RUN).isEmpty());
    }

    @Test void terminalCancellationIncompleteHistoryAndOldEvidenceCannotBeReinterpreted() {
        var repository = repository();
        var transitions = new CaseExecutionService(repository);
        var entries = new ArrayList<>(List.of(fetch("control", 1), use("control", 2), fetch("candidate", 3)));
        var aborted = fixture("aborted", false);
        var late = fixture("late", false);
        var context = context(entries, true);
        transitions.start(RUN, aborted, context);
        var canceled = transitions.resume(RUN, aborted, context, new CaseEvent.Aborted("operator skipped"));
        transitions.start(RUN, late, context);
        var original = transitions.resume(RUN, late, context, new CaseEvent.ConfigConfirmed());
        entries.add(use("candidate", 4));
        assertEquals(canceled, transitions.reevaluateRecordedEvidence(RUN, aborted, context));
        assertEquals(original, transitions.reevaluateRecordedEvidence(RUN, late, context(entries, false)));
        var proposed = late.reevaluateRecordedEvidence(context, original.outcome()).orElseThrow();
        var oldWithSameEvidence = new CaseOutcome(Outcome.NOT_VERIFIED, "legacy", "metadata.fixture-probe.incomplete",
                "legacy", proposed.evidence(), Map.of());
        assertTrue(late.reevaluateRecordedEvidence(context, oldWithSameEvidence).isEmpty());
        for (var outcome : List.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED)) {
            assertTrue(RecordedEvidenceReevaluation.conclusiveUpdate(CaseOutcome.of(outcome, "existing", List.of()), proposed).isEmpty());
        }
    }

    @Test void metadataConsumerReevaluationAlsoRequiresFreshConclusiveEvidence() {
        var test = new MetadataConsumerObservationTestCase("consumer", TargetRole.IDP,
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO);
        var entries = new ArrayList<>(List.of(fetch("control", 1), use("control", 2), fetch("no-key-info", 3)));
        var context = context(entries, true);
        var state = ((CaseStep.AwaitConfig) test.start(context)).next();
        var previous = ((CaseStep.Finish) test.resume(context, state, new CaseEvent.ConfigConfirmed())).outcome();
        assertTrue(test.reevaluateRecordedEvidence(context, previous).isEmpty());
        entries.add(use("no-key-info", 4));
        assertEquals(Outcome.SATISFIED, test.reevaluateRecordedEvidence(context, previous).orElseThrow().outcome());
    }

    private SqliteCaseExecutionRepository repository() {
        var db = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Evidence test",
                com.samlscope.core.profile.FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(db, json).save(plan);
        new SqliteRunRepository(db, json).save(new com.samlscope.core.run.TestRun(RUN, plan.id(),
                com.samlscope.core.run.RunStatus.RUNNING, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        return new SqliteCaseExecutionRepository(db, json);
    }

    private static MetadataFixtureObservationTestCase fixture(String id, boolean reject) {
        return new MetadataFixtureObservationTestCase(id, TargetRole.IDP, List.of(
                new MetadataFixtureObservationTestCase.Fixture("candidate", reject
                        ? MetadataFixtureObservationTestCase.Behavior.REJECT : MetadataFixtureObservationTestCase.Behavior.ACCEPT, "fixture")),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
    }
    private static CaseContext context(List<TranscriptEntry> entries, boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new TranscriptRecorder() {
                    public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
                    public List<TranscriptEntry> list(String id) { return entries; }
                }, complete);
    }
    private static TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, "/metadata/live", 0, Map.of("type", "MetadataFetch", "variant", variant));
    }
    private static TranscriptEntry use(String variant, int sequence) {
        return entry(sequence, "/p/plan/sp/acs/0?mdv=" + variant + "&run=" + RUN, 10,
                Map.of("type", "Response", "metadataProbeAccepted", true, "statusCode", "urn:oasis:names:tc:SAML:2.0:status:Success"));
    }
    private static TranscriptEntry entry(int sequence, String url, int size, Map<String,Object> summary) {
        return new TranscriptEntry("tr_" + sequence, RUN, Direction.INBOUND, NOW.plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, size > 0 ? "decoded" : null, size, null, null, summary);
    }
}
