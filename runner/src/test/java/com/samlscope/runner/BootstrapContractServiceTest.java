package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.caseexec.WaitCondition;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

class BootstrapContractServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void groupsCaseWaitsAndTreatsAStandardMetadataFetchAsBootstrapEvidence() {
        var plans = new MemoryPlans(plan(MetadataDeliveryKind.HTTP_URL));
        var runs = new MemoryRuns(run());
        var events = new RunEventBus();
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var lab = new MetadataLabService(
                URI.create("https://suite.example"), plans, runs,
                new RunService(plans, runs, events, clock), clock);
        var transcripts = new MemoryTranscript();
        var definitions = new CaseDefinitionCatalog(List.of(
                definition("IIP-MD03-a-idp-01", "IIP-MD03.a"),
                definition("IIP-ALG08-a-idp-01", "IIP-ALG08.a"),
                definition("IIP-IDP04-a-idp-01", "IIP-IDP04.a")));
        var executions = new MemoryExecutions(List.of(
                waiting("IIP-MD03-a-idp-01"),
                waiting("IIP-ALG08-a-idp-01"),
                waiting("IIP-IDP04-a-idp-01")));
        var service = new BootstrapContractService(
                definitions, executions, plans, runs, transcripts, lab);

        var initial = service.contracts("run");
        assertEquals(List.of("attribute-policy", "crypto-policy", "metadata-feed"),
                initial.stream().map(BootstrapContractQuery.BootstrapContract::id).toList());
        var metadata = initial.get(2);
        assertEquals(BootstrapContractQuery.Readiness.SETUP_REQUIRED, metadata.readiness());
        assertEquals(URI.create("https://suite.example/p/plan/metadata/live?run=run"), metadata.setupUrl());

        transcripts.entries.add(new TranscriptEntry(
                "tx", "run", Direction.INBOUND, NOW, "metadata-live:control", "GET",
                metadata.setupUrl().toString(), 200, Map.of(), null, 0, null, 0, null,
                "run=run", Map.of("type", "MetadataFetch", "variant", "control", "feed", "live")));

        assertEquals(BootstrapContractQuery.Readiness.FETCH_OBSERVED,
                service.contracts("run").stream()
                        .filter(value -> value.id().equals("metadata-feed")).findFirst().orElseThrow().readiness());
    }

    @Test
    void manualMetadataDeliveryIsNotPresentedAsAutomatic() {
        var plans = new MemoryPlans(plan(MetadataDeliveryKind.MANUAL));
        var runs = new MemoryRuns(run());
        var clock = Clock.fixed(NOW, ZoneOffset.UTC);
        var lab = new MetadataLabService(
                URI.create("https://suite.example"), plans, runs,
                new RunService(plans, runs, new RunEventBus(), clock), clock);
        var service = new BootstrapContractService(
                new CaseDefinitionCatalog(List.of(definition("IIP-MD03-a-idp-01", "IIP-MD03.a"))),
                new MemoryExecutions(List.of(waiting("IIP-MD03-a-idp-01"))),
                plans, runs, new MemoryTranscript(), lab);

        assertEquals(BootstrapContractQuery.Readiness.MANUAL_ONLY,
                service.contracts("run").getFirst().readiness());
    }

    private static CaseDefinition definition(String id, String obligation) {
        var variant = obligation + "#v-test";
        return new CaseDefinition(
                id, obligation, TargetRole.IDP, ExecutionMode.CONFIG, Milestone.M2,
                List.of(variant), Map.of(variant, CaseDefinitionCatalog.VariantScope.OWNER_CONDITION),
                List.of(new CaseDefinitionCatalog.VariantInstruction(
                        variant, CaseDefinitionCatalog.VariantScope.OWNER_CONDITION,
                        CaseDefinitionCatalog.VariantTreatment.VERDICT, "Exercise the fixture.")),
                List.of(new CaseDefinitionCatalog.VariantGroup(
                        "all", CaseDefinitionCatalog.GroupKind.ALL_OF, List.of(variant), "Cover it.")),
                List.of(new CaseDefinitionCatalog.Control(
                        "control", CaseDefinitionCatalog.ControlKind.POSITIVE, "fixture",
                        "Observe the control.", "control_failed")),
                "A blanket implementation could otherwise pass.", List.of(),
                new CaseDefinitionCatalog.Requirements(List.of(), "none"), false,
                ConfigurationFailureSemantics.TEST_PRECONDITION,
                "sha256:" + "0".repeat(64));
    }

    private static CaseExecution waiting(String id) {
        return new CaseExecution(
                "run", id, 0, CaseExecutionStatus.WAITING_CONFIG,
                new CaseState("await", Map.of()),
                new WaitCondition(WaitCondition.Kind.CONFIG, "configure", null, null, NOW.plusSeconds(60)),
                null, NOW);
    }

    private static TestPlan plan(MetadataDeliveryKind delivery) {
        return new TestPlan(
                "plan", "Target", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                delivery, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
    }

    private static TestRun run() {
        return new TestRun("run", "plan", RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }

    private static final class MemoryPlans implements PlanRepository {
        private TestPlan plan;
        private MemoryPlans(TestPlan plan) { this.plan = plan; }
        @Override public List<TestPlan> list() { return List.of(plan); }
        @Override public Optional<TestPlan> find(String id) { return plan.id().equals(id) ? Optional.of(plan) : Optional.empty(); }
        @Override public void save(TestPlan value) { plan = value; }
        @Override public boolean delete(String id) { return false; }
    }

    private static final class MemoryRuns implements RunRepository {
        private TestRun run;
        private MemoryRuns(TestRun run) { this.run = run; }
        @Override public List<TestRun> listForPlan(String planId) { return List.of(run); }
        @Override public Optional<TestRun> find(String id) { return run.id().equals(id) ? Optional.of(run) : Optional.empty(); }
        @Override public void save(TestRun value) { run = value; }
    }

    private record MemoryExecutions(List<CaseExecution> values) implements CaseExecutionRepository {
        @Override public Optional<CaseExecution> find(String runId, String caseId) { return Optional.empty(); }
        @Override public List<CaseExecution> list(String runId) { return values; }
        @Override public boolean apply(long expectedRevision, CaseExecution execution, List<OutboundAction> actions) { throw new UnsupportedOperationException(); }
        @Override public List<OutboxEntry> listOutbox(String runId) { return List.of(); }
        @Override public Optional<OutboxEntry> findOutbox(String actionId) { return Optional.empty(); }
        @Override public boolean transitionOutbox(String actionId, OutboxStatus expected, OutboxStatus next, Map<String, Object> sendResult, String transcriptEntryId, Instant updatedAt) { throw new UnsupportedOperationException(); }
        @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
    }

    private static final class MemoryTranscript implements TranscriptRecorder {
        private final List<TranscriptEntry> entries = new ArrayList<>();
        @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        @Override public TranscriptEntry updateSamlAnalysis(String entryId, String correlationId, Map<String, Object> samlSummary) { throw new UnsupportedOperationException(); }
        @Override public List<TranscriptEntry> list(String runId) { return List.copyOf(entries); }
    }
}
