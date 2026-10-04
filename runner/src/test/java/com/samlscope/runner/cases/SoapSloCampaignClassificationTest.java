package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Checks real campaign provenance, rather than the presence of a marker alone. */
class SoapSloCampaignClassificationTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-10-04T00:00:00Z");

    @Test void nativePreparationRemainsOperatorAssistedAndUnresolved() {
        var execution = new CaseExecution(RUN, SoapSloPropagationTestCase.ID, 1,
                CaseExecutionStatus.WAITING_CONFIG, new CaseState("soap-slo-propagation-v1-all-success",
                Map.of("soap_definition", "soap-slo-propagation-v1", "soap_trial", "all-success", "soap_phase", "configure")),
                new WaitCondition(WaitCondition.Kind.CONFIG, "slo.propagation.soap.apply-prepared-metadata",
                        null, null, NOW.plusSeconds(900)), null, NOW);
        var report = report(execution);
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,
                report.classifications().getFirst().evidenceClass());
        assertEquals(RunCampaignQuery.Plan.STANDARD, report.classifications().getFirst().plan());
        assertFalse(report.classifications().getFirst().resolved());
        assertEquals(1, report.notVerifiedCases());
        assertEquals(0, report.selfAttestedCases());
    }

    @Test void completedNativeOriginalsAreExternallyVerifiedWithOperatorPreparation() {
        var report = report(finished(CaseOutcome.of(Outcome.SATISFIED, "native-soap-continuation",
                List.of(new EvidenceRef("transcript", "tx_native_original")))));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,
                report.classifications().getFirst().evidenceClass());
        assertTrue(report.classifications().getFirst().resolved());
        assertEquals(1, report.externallyVerifiedCases());
        assertEquals(0, report.selfAttestedCases());
        assertEquals(0, report.notVerifiedCases());
        assertTrue(report.campaigns().stream().allMatch(c -> c.remainingUserActions() == 0));
    }

    @Test void incompleteTerminalTrialCannotBecomeSelfAttestedOrRequestRepeatedLogin() {
        var report = report(finished(CaseOutcome.notVerified("native_trial_incomplete", "slo.propagation.soap-trial-incomplete")));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,
                report.classifications().getFirst().evidenceClass());
        assertFalse(report.classifications().getFirst().resolved());
        assertEquals(1, report.notVerifiedCases());
        assertEquals(0, report.selfAttestedCases());
        assertTrue(report.campaigns().stream().allMatch(c -> c.remainingUserActions() == 0));
    }

    private static CaseExecution finished(CaseOutcome outcome) {
        return new CaseExecution(RUN, SoapSloPropagationTestCase.ID, 2,
                CaseExecutionStatus.FINISHED, CaseState.initial(), null, outcome, NOW);
    }

    private static RunCampaignQuery.CampaignReport report(CaseExecution execution) {
        var observer = new TestCase() {
            public String id() { return SoapSloPropagationTestCase.ID; }
            public TargetRole role() { return TargetRole.IDP; }
            public CaseStep start(CaseContext c) { throw new AssertionError("Campaign query is read-only"); }
            public CaseStep resume(CaseContext c, CaseState s, CaseEvent e) { return start(c); }
        };
        var test = new SoapSloPropagationTestCase(observer,
                ignored -> { throw new AssertionError("Campaign query must not prepare native configuration"); },
                ignored -> { throw new AssertionError("No protocol consumption during classification"); });
        var recorder = new TranscriptRecorder() {
            public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Query recorded an action"); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                throw new AssertionError("Query changed original evidence");
            }
            public List<TranscriptEntry> list(String run) { return List.of(); }
        };
        var context = new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var repo = new CaseExecutionRepository() {
            public Optional<CaseExecution> find(String run, String id) { return Optional.of(execution); }
            public List<CaseExecution> list(String run) { assertEquals(RUN, run); return List.of(execution); }
            public boolean apply(long revision, CaseExecution next, List<OutboundAction> actions) { throw new AssertionError("Query changed case state"); }
            public List<OutboxEntry> listOutbox(String run) { return List.of(); }
            public Optional<OutboxEntry> findOutbox(String id) { return Optional.empty(); }
            public boolean transitionOutbox(String id, OutboxStatus expected, OutboxStatus next,
                    Map<String,Object> result, String ref, Instant at) { throw new AssertionError("Query changed delivery"); }
            public int recoverSendingAsUnknownDelivery(Instant at) { throw new AssertionError("Query recovered delivery"); }
        };
        var definition = new CaseDefinitionCatalog.CaseDefinition(SoapSloPropagationTestCase.ID, "IIP-IDP17.r",
                TargetRole.IDP, CaseDefinitionCatalog.ExecutionMode.BROWSER, CaseDefinitionCatalog.Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(), List.of(), "mut-iip-idp17-r-idp", List.of(),
                new CaseDefinitionCatalog.Requirements(List.of(), "required"), false, null, "sha256:" + "0".repeat(64));
        return new RunCampaignService(repo, new CaseDefinitionCatalog(List.of(definition)),
                new TestCaseRegistry(List.of(test)), ignored -> context).report(RUN);
    }
}
