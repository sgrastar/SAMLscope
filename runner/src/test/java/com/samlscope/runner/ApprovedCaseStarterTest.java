package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Requirements;
import com.samlscope.core.evaluation.ApplicabilityEvaluation;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.PredicateKind;
import com.samlscope.core.evaluation.Rfc2119Level;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.ApprovedAttestedCaseRegistry;

class ApprovedCaseStarterTest {
    private static final Instant NOW = Instant.parse("2026-08-29T12:00:00Z");
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";

    @Test
    void startsOnlyProfileSelectedCasesWhoseApplicabilityIsTrue() {
        var definitions = definitions();
        var registry = ApprovedAttestedCaseRegistry.create(definitions);
        var plan = plan(FunctionalProfile.BROWSER_SSO_IDP);
        var run = run(plan);

        var falseRepository = new MemoryRepository();
        var falseStarter = new ApprovedCaseStarter(
                coverage(), definitions, registry, new CaseExecutionService(falseRepository),
                (ignoredRun, ignoredPlan) -> List.of(applicability(false)),
                ignored -> FunctionalCaseFixtures.definition(plan.profile(), definitions, coverage(),
                        "IIP-A-a-idp-01", "IIP-B-b-idp-01"));
        var falseStarted = falseStarter.startApplicable(run, plan, context(plan));
        assertEquals(List.of("IIP-A-a-idp-01"), falseStarted.stream().map(CaseExecution::caseId).toList());

        var trueRepository = new MemoryRepository();
        var trueStarter = new ApprovedCaseStarter(
                coverage(), definitions, registry, new CaseExecutionService(trueRepository),
                (ignoredRun, ignoredPlan) -> List.of(applicability(true)),
                ignored -> FunctionalCaseFixtures.definition(plan.profile(), definitions, coverage(),
                        "IIP-A-a-idp-01", "IIP-B-b-idp-01"));
        var trueStarted = trueStarter.startApplicable(run, plan, context(plan));
        assertEquals(List.of("IIP-A-a-idp-01", "IIP-B-b-idp-01"),
                trueStarted.stream().map(CaseExecution::caseId).toList());

        var corePlan = plan(FunctionalProfile.BROWSER_SSO_IDP);
        var coreRun = run(corePlan);
        var coreRepository = new MemoryRepository();
        var coreStarter = new ApprovedCaseStarter(
                coverage(), definitions, registry, new CaseExecutionService(coreRepository),
                (ignoredRun, ignoredPlan) -> List.of(),
                ignored -> FunctionalCaseFixtures.definition(corePlan.profile(), definitions, coverage(),
                        "IIP-A-a-idp-01"));
        assertEquals(List.of("IIP-A-a-idp-01"), coreStarter.startApplicable(
                coreRun, corePlan, context(corePlan)).stream().map(CaseExecution::caseId).toList());
    }

    private CoverageCatalog coverage() {
        return new CoverageCatalog(List.of(
                new CoverageCatalog.Obligation(
                        "IIP-A.a", "IIP-A", Rfc2119Level.MUST, List.of(TargetRole.IDP), null,
                        CoverageCatalog.Testability.ATTESTED, CoverageCatalog.ProfileScope.CORE),
                new CoverageCatalog.Obligation(
                        "IIP-B.b", "IIP-B", Rfc2119Level.MUST, List.of(TargetRole.IDP), "feature",
                        CoverageCatalog.Testability.ATTESTED, CoverageCatalog.ProfileScope.FULL)));
    }

    private CaseDefinitionCatalog definitions() {
        return new CaseDefinitionCatalog(List.of(
                definition("IIP-A-a-idp-01", "IIP-A.a"),
                definition("IIP-B-b-idp-01", "IIP-B.b")));
    }

    private CaseDefinition definition(String id, String obligation) {
        return new CaseDefinition(
                id, obligation, TargetRole.IDP, ExecutionMode.ATTESTED, Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(), List.of(),
                "A declaration-only oracle would miss the target behavior.", List.of(),
                new Requirements(List.of(), "none"), false, null, "sha256:" + "a".repeat(64));
    }

    private ApplicabilityEvaluation applicability(boolean value) {
        return new ApplicabilityEvaluation(
                "IIP-B.b", "feature", PredicateKind.CLAIM_BASED, value, null,
                value ? ApplicabilityEvaluation.EffectiveResult.TRUE
                        : ApplicabilityEvaluation.EffectiveResult.FALSE,
                false, ApplicabilityEvaluation.Basis.DECLARED, List.of(), null);
    }

    private TestPlan plan(FunctionalProfile profile) {
        return new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "Attested", profile,
                new TestPlan.Target(
                        TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                new TestPlan.Interaction(true, true), NOW, NOW);
    }

    private TestRun run(TestPlan plan) {
        return new TestRun(RUN_ID, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW);
    }

    private DefaultCaseContext context(TestPlan plan) {
        return new DefaultCaseContext(
                RUN_ID, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC), plan.parameters(), plan.interaction(),
                Reachability.CONFIRMED, new NoopTranscript(), true);
    }

    private static final class MemoryRepository implements CaseExecutionRepository {
        private final Map<String, CaseExecution> values = new LinkedHashMap<>();
        @Override public Optional<CaseExecution> find(String runId, String caseId) {
            return Optional.ofNullable(values.get(runId + "\n" + caseId));
        }
        @Override public List<CaseExecution> list(String runId) {
            return values.values().stream().filter(value -> value.runId().equals(runId))
                    .sorted(java.util.Comparator.comparing(CaseExecution::caseId)).toList();
        }
        @Override public boolean apply(long expectedRevision, CaseExecution execution, List<OutboundAction> actions) {
            var key = execution.runId() + "\n" + execution.caseId();
            var current = values.get(key);
            if ((current == null ? -1 : current.revision()) != expectedRevision) return false;
            values.put(key, execution);
            return true;
        }
        @Override public List<OutboxEntry> listOutbox(String runId) { return List.of(); }
        @Override public Optional<OutboxEntry> findOutbox(String actionId) { return Optional.empty(); }
        @Override public boolean transitionOutbox(
                String actionId, OutboxStatus expected, OutboxStatus next, Map<String, Object> sendResult,
                String transcriptEntryId, Instant updatedAt) { return false; }
        @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
    }

    private static final class NoopTranscript implements TranscriptRecorder {
        @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        @Override public TranscriptEntry updateSamlAnalysis(
                String entryId, String correlationId, Map<String, Object> samlSummary) {
            throw new UnsupportedOperationException();
        }
        @Override public List<TranscriptEntry> list(String runId) { return new ArrayList<>(); }
    }
}
