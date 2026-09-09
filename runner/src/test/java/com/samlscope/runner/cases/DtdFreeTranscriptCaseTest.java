package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.runner.CaseExecutionService;

class DtdFreeTranscriptCaseTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void inspectsPersistedInboundTargetMessagesAndIgnoresSuiteOutboundMessages() {
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "DTD Transcript", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), now, now);
        new SqlitePlanRepository(database, json).save(plan);
        var run = new TestRun(
                "run_0123456789ABCDEFGHJKMNPQRS", plan.id(), RunStatus.RUNNING,
                Reachability.UNKNOWN, Map.of(), now, now);
        new SqliteRunRepository(database, json).save(run);
        var transcript = new FileTranscriptRecorder(database, json, directory);
        record(transcript, run.id(), Direction.OUTBOUND,
                "<!DOCTYPE suite [<!ELEMENT suite EMPTY>]><suite/>", now);
        record(transcript, run.id(), Direction.INBOUND, "<Response/>", now.plusSeconds(1));
        var violating = record(transcript, run.id(), Direction.INBOUND,
                "<!DOCTYPE Response [<!ELEMENT Response EMPTY>]><Response/>", now.plusSeconds(2));

        var outcome = new DtdFreeTargetSamlCase().evaluateTranscript(run.id(), transcript, transcript);

        assertEquals(Outcome.VIOLATED, outcome.outcome());
        assertEquals(List.of("transcript:" + violating.id()),
                outcome.evidence().stream().map(value -> value.reference()).toList());
        assertEquals(2, outcome.details().get("inspected_messages"));

        var service = new CaseExecutionService(new SqliteCaseExecutionRepository(database, json));
        var execution = service.start(run.id(),
                new DtdFreeTranscriptTestCase("IIP-G03-a-idp-01", transcript),
                new CaseContext() {
                    @Override public String runId() { return run.id(); }
                    @Override public TargetRole targetRole() { return TargetRole.IDP; }
                    @Override public Clock clock() { return Clock.fixed(now, ZoneOffset.UTC); }
                    @Override public TestPlan.Parameters parameters() { return plan.parameters(); }
                    @Override public TestPlan.Interaction interaction() { return plan.interaction(); }
                    @Override public Reachability reachability() { return run.targetToSuiteReachability(); }
                    @Override public com.samlscope.core.transcript.TranscriptRecorder transcript() { return transcript; }
                    @Override public boolean transcriptComplete() { return true; }
                });
        assertEquals(CaseExecutionStatus.FINISHED, execution.status());
        assertEquals(Outcome.VIOLATED, execution.outcome().outcome());
    }

    private com.samlscope.core.transcript.TranscriptEntry record(
            FileTranscriptRecorder recorder,
            String runId,
            Direction direction,
            String xml,
            Instant timestamp) {
        var bytes = xml.getBytes(StandardCharsets.UTF_8);
        return recorder.record(new TranscriptInput(
                runId, direction, timestamp, "corr", "POST", "https://suite.example/peer", 200,
                Map.of(), bytes, "application/xml", null, bytes, Map.of()));
    }
}
