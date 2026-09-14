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
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.MetadataConsumerObservationTestCase;
import com.samlscope.runner.cases.BrowserPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

class ProtocolEvidenceAutomationServiceTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void advancesOnlyAnEvidenceReadyCaseAndLetsTheCaseDeriveItsOutcome() {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var testCase = new MetadataConsumerObservationTestCase(
                "IIP-MD05-ao-sp-01", TargetRole.SP,
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO);
        var entries = List.of(
                fetch("control", 1), use("control", 2),
                fetch("no-key-info", 3), use("no-key-info", 4));
        var context = context(entries);
        transitions.start(RUN, testCase, context);
        var service = new ProtocolEvidenceAutomationService(
                repository, new TestCaseRegistry(List.of(testCase)), transitions, ignored -> context);

        var before = service.status(RUN);
        assertEquals(1, before.eligibleCases());
        assertEquals(1, before.readyCases());

        var evaluation = service.evaluateReady(RUN);
        assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                testCase.id(), Outcome.SATISFIED)), evaluation.completed());
        assertEquals(0, evaluation.remaining().eligibleCases());
        assertEquals(CaseExecutionStatus.FINISHED,
                repository.find(RUN, testCase.id()).orElseThrow().status());
    }

    @Test
    void doesNotConvertAnIncompleteProbeIntoNotVerified() {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var testCase = new MetadataConsumerObservationTestCase(
                "IIP-MD05-an-sp-01", TargetRole.SP,
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT);
        var context = context(List.of(fetch("control", 1), use("control", 2)));
        transitions.start(RUN, testCase, context);
        var service = new ProtocolEvidenceAutomationService(
                repository, new TestCaseRegistry(List.of(testCase)), transitions, ignored -> context);

        assertEquals(0, service.status(RUN).readyCases());
        assertEquals(List.of(), service.evaluateReady(RUN).completed());
        assertEquals(CaseExecutionStatus.WAITING_CONFIG,
                repository.find(RUN, testCase.id()).orElseThrow().status());
    }

    @Test
    void campaignConfirmationCannotTurnMissingRejectionEvidenceIntoSuccess() {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var first = new MetadataConsumerObservationTestCase(
                "IIP-MD05-an-sp-01", TargetRole.SP,
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT);
        var second = new MetadataConsumerObservationTestCase(
                "IIP-MD05-an-sp-02", TargetRole.SP,
                MetadataConsumerObservationTestCase.Rule.EXCLUDED_CONTENT);
        var entries = List.of(
                fetch("control", 1), use("control", 2),
                fetch("xpath-exclude-role-descriptors", 3),
                fetch("xpath-exclude-endpoints", 4),
                fetch("xpath-exclude-key-descriptors", 5));
        var context = context(entries);
        transitions.start(RUN, first, context);
        transitions.start(RUN, second, context);
        var service = new ProtocolEvidenceAutomationService(
                repository, new TestCaseRegistry(List.of(first, second)), transitions, ignored -> context);

        assertEquals(0, service.status(RUN).readyCases(), "silence alone is not auto-conclusive");
        var evaluation = service.evaluateAttempted(RUN);

        assertEquals(List.of(
                new ProtocolEvidenceAutomationService.CompletedCase(first.id(), Outcome.NOT_VERIFIED),
                new ProtocolEvidenceAutomationService.CompletedCase(second.id(), Outcome.NOT_VERIFIED)),
                evaluation.completed());
        assertEquals(CaseExecutionStatus.FINISHED,
                repository.find(RUN, first.id()).orElseThrow().status());
        assertEquals(CaseExecutionStatus.FINISHED,
                repository.find(RUN, second.id()).orElseThrow().status());
    }

    @Test
    void advancesABrowserWaitOnlyFromSuiteObservedTranscriptReadiness() {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var testCase = new ReadyBrowserCase();
        var context = context(List.of(), TargetRole.IDP);
        transitions.start(RUN, testCase, context);
        var service = new ProtocolEvidenceAutomationService(
                repository, new TestCaseRegistry(List.of(testCase)), transitions, ignored -> context);

        var evaluation = service.evaluateReady(RUN);

        assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                testCase.id(), Outcome.SATISFIED)), evaluation.completed());
        assertEquals(CaseExecutionStatus.FINISHED,
                repository.find(RUN, testCase.id()).orElseThrow().status());
    }

    private static CaseContext context(List<TranscriptEntry> entries) {
        return context(entries, TargetRole.SP);
    }

    private static CaseContext context(List<TranscriptEntry> entries, TargetRole role) {
        return new DefaultCaseContext(
                RUN, role, Clock.fixed(NOW, ZoneOffset.UTC), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new MemoryTranscript(entries), true);
    }

    private static TranscriptEntry fetch(String variant, int sequence) {
        return entry(sequence, "/metadata/live", 0,
                Map.of("type", "MetadataFetch", "variant", variant, "feed", "live"));
    }

    private static TranscriptEntry use(String variant, int sequence) {
        return entry(sequence, "https://suite.example/p/plan/idp/sso?mdv=" + variant + "&run=" + RUN,
                10, Map.of("type", "AuthnRequest"));
    }

    private static TranscriptEntry entry(
            int sequence, String url, int decodedBytes, Map<String, Object> summary) {
        return new TranscriptEntry(
                "tr_" + sequence, RUN, Direction.INBOUND, NOW.plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedBytes > 0 ? "decoded" : null, decodedBytes,
                null, null, summary);
    }

    private record MemoryTranscript(List<TranscriptEntry> entries) implements TranscriptRecorder {
        @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        @Override public TranscriptEntry updateSamlAnalysis(
                String entryId, String correlationId, Map<String, Object> samlSummary) {
            throw new UnsupportedOperationException();
        }
        @Override public List<TranscriptEntry> list(String runId) { return entries; }
    }

    private static final class MemoryExecutions implements CaseExecutionRepository {
        private final Map<String, CaseExecution> values = new LinkedHashMap<>();

        @Override public Optional<CaseExecution> find(String runId, String caseId) {
            return Optional.ofNullable(values.get(runId + "|" + caseId));
        }
        @Override public List<CaseExecution> list(String runId) {
            return values.values().stream().filter(value -> value.runId().equals(runId)).toList();
        }
        @Override public boolean apply(
                long expectedRevision, CaseExecution execution, List<OutboundAction> actions) {
            var key = execution.runId() + "|" + execution.caseId();
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

    private static final class ReadyBrowserCase
            implements com.samlscope.core.caseexec.TestCase, BrowserPrompt, ProtocolEvidenceCase {
        @Override public String id() { return "IIP-SSO03-a-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String browserInstructionsEn() { return "Run the correlated SSO flow."; }
        @Override public com.samlscope.core.caseexec.CaseStep start(CaseContext context) {
            return new com.samlscope.core.caseexec.CaseStep.AwaitBrowser(
                    new com.samlscope.core.caseexec.CaseState("await", Map.of()), List.of(),
                    java.net.URI.create("https://suite.example/start"), java.time.Duration.ofMinutes(5));
        }
        @Override public com.samlscope.core.caseexec.CaseStep resume(
                CaseContext context, com.samlscope.core.caseexec.CaseState state,
                com.samlscope.core.caseexec.CaseEvent event) {
            if (!(event instanceof com.samlscope.core.caseexec.CaseEvent.TranscriptReady)) {
                throw new IllegalArgumentException("Transcript evidence is required");
            }
            return new com.samlscope.core.caseexec.CaseStep.Finish(
                    com.samlscope.core.evaluation.CaseOutcome.of(
                            Outcome.SATISFIED, "transcript-ready", List.of()));
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(true, List.of("response"), List.of("response"), Map.of());
        }
    }
}
