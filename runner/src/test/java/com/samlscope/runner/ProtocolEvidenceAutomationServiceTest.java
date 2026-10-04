package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import com.samlscope.runner.cases.MetadataSignatureVerificationTestSupport;
import com.samlscope.runner.cases.BrowserPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

class ProtocolEvidenceAutomationServiceTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    @org.junit.jupiter.api.io.TempDir java.nio.file.Path directory;

    @Test
    void advancesOnlyAnEvidenceReadyCaseAndLetsTheCaseDeriveItsOutcome() throws Exception {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        MetadataSignatureVerificationTestSupport.writeReceipt(directory, receipt -> receipt);
        var testCase = new MetadataConsumerObservationTestCase(
                "IIP-MD05-ao-sp-01", TargetRole.SP,
                MetadataConsumerObservationTestCase.Rule.OMITTED_KEY_INFO,
                MetadataSignatureVerificationTestSupport.content(),
                runId -> MetadataSignatureVerificationTestSupport.TARGET, directory);
        var entries = MetadataSignatureVerificationTestSupport.withCorrelation(List.of(
                fetch("control", 1), use("control", 2),
                fetch("no-key-info", 3), use("no-key-info", 4)));
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

    @Test
    void completesOptedInQueuedCaseWithoutStartingOrDispatchingIt() {
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var testCase = new ReadyQueuedCase(true, Outcome.SATISFIED);
        var context = context(List.of(), TargetRole.IDP);
        transitions.enqueueFrontChannel(RUN,testCase,context);
        var service = new ProtocolEvidenceAutomationService(repository,new TestCaseRegistry(List.of(testCase)),transitions,ignored -> context);
        assertEquals(1,service.status(RUN).readyCases());
        assertEquals(1,service.evaluateReady(RUN).completed().size());
        assertEquals(CaseExecutionStatus.FINISHED,repository.find(RUN,testCase.id()).orElseThrow().status());
        assertEquals(0,repository.outboundActions);
        assertEquals(List.of(),service.evaluateReady(RUN).completed());
    }

    @Test
    void attemptedConfirmationCannotCompleteQueuedCaseWithoutConclusiveEvidence() {
        for (var testCase : List.of(new ReadyQueuedCase(false,Outcome.SATISFIED),new ReadyQueuedCase(true,Outcome.NOT_VERIFIED))) {
            var repository = new MemoryExecutions(); var transitions = new CaseExecutionService(repository);
            var context = context(List.of(),TargetRole.IDP);
            transitions.enqueueFrontChannel(RUN,testCase,context);
            var service = new ProtocolEvidenceAutomationService(repository,new TestCaseRegistry(List.of(testCase)),transitions,ignored -> context);
            assertEquals(List.of(),service.evaluateAttempted(RUN).completed());
            assertEquals(true,CaseExecutionService.isQueuedFrontChannel(repository.find(RUN,testCase.id()).orElseThrow()));
            assertEquals(0,repository.outboundActions);
        }
    }

    @Test
    void unrelatedQueuedCasesOutsideTheEvidenceRegistryAreIgnored() {
        var repository = new MemoryExecutions(); var transitions = new CaseExecutionService(repository);
        var context = context(List.of(),TargetRole.IDP);
        var testCase = new ReadyQueuedCase(true,Outcome.SATISFIED);
        transitions.enqueueFrontChannel(RUN,testCase,context);
        var service = new ProtocolEvidenceAutomationService(repository,new TestCaseRegistry(List.of()),transitions,ignored -> context);
        assertEquals(0,service.status(RUN).eligibleCases());
        assertEquals(List.of(),service.evaluateReady(RUN).completed());
        assertEquals(true,CaseExecutionService.isQueuedFrontChannel(repository.find(RUN,testCase.id()).orElseThrow()));
    }

    @Test
    void incompleteRunCannotCompleteEvenWhenObserverClaimsReadiness() {
        var repository = new MemoryExecutions(); var transitions = new CaseExecutionService(repository);
        var testCase = new ReadyQueuedCase(true,Outcome.SATISFIED);
        var context = new DefaultCaseContext(RUN,TargetRole.IDP,Clock.fixed(NOW,ZoneOffset.UTC),TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new MemoryTranscript(List.of()),false);
        transitions.enqueueFrontChannel(RUN,testCase,context);
        var service = new ProtocolEvidenceAutomationService(repository,new TestCaseRegistry(List.of(testCase)),transitions,ignored -> context);
        assertEquals(List.of(),service.evaluateReady(RUN).completed());
        assertEquals(true,CaseExecutionService.isQueuedFrontChannel(repository.find(RUN,testCase.id()).orElseThrow()));
    }

    @Test
    void statusProjectsLegacyInteractionFreeWaitsWithoutChangingThem() {
        for (var status : legacyStatuses()) {
            var repository = new MemoryExecutions();
            var testCase = new InteractionFreeCase(false);
            var original = legacyExecution(testCase.id(), status, false);
            repository.values.put(RUN + "|" + testCase.id(), original);
            var service = new ProtocolEvidenceAutomationService(repository,
                    new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                    ignored -> context(List.of(), TargetRole.IDP));

            var projection = service.status(RUN);

            assertEquals(1, projection.eligibleCases());
            assertEquals(0, projection.readyCases(), "absence is not evidence readiness");
            assertEquals(List.of("native-mechanism-trace"),
                    projection.cases().getFirst().requiredObservations());
            assertEquals(original, repository.find(RUN, testCase.id()).orElseThrow());
            assertEquals(0, repository.outboundActions);
            assertEquals(0, testCase.outcomeCalls);
        }
    }

    @Test
    void concludesObsoleteWaitsAsNotVerifiedWithoutAdditionalOperations() {
        for (var status : legacyStatuses()) {
            for (var attemptsConfirmed : List.of(false, true)) {
                var repository = new MemoryExecutions();
                var testCase = new InteractionFreeCase(false);
                var original = legacyExecution(testCase.id(), status, false);
                repository.values.put(RUN + "|" + testCase.id(), original);
                var oldAction = oldOutbox(testCase.id());
                repository.outbox.add(oldAction);
                var service = new ProtocolEvidenceAutomationService(repository,
                        new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                        ignored -> context(List.of(), TargetRole.IDP));

                var evaluation = attemptsConfirmed ? service.evaluateAttempted(RUN) : service.evaluateReady(RUN);

                assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                        testCase.id(), Outcome.NOT_VERIFIED)), evaluation.completed());
                var finished = repository.find(RUN, testCase.id()).orElseThrow();
                assertEquals(CaseExecutionStatus.FINISHED, finished.status());
                assertEquals(original.revision() + 1, finished.revision());
                assertEquals(original.state(), finished.state());
                assertEquals(null, finished.waitCondition());
                assertEquals("native-mechanism.unproven", finished.outcome().reasonCode());
                assertEquals(0, repository.outboundActions);
                assertEquals(List.of(oldAction), repository.listOutbox(RUN));
                assertEquals(List.of(), service.evaluateReady(RUN).completed());
                assertEquals(finished, repository.find(RUN, testCase.id()).orElseThrow());
            }
        }
    }

    @Test
    void expiredObsoleteWaitsFinishFromEvidenceWithoutRequiringUserRecovery() {
        for (var status : List.of(CaseExecutionStatus.WAITING_BROWSER, CaseExecutionStatus.WAITING_INBOUND)) {
            var repository = new MemoryExecutions();
            var testCase = new InteractionFreeCase(false);
            repository.values.put(RUN + "|" + testCase.id(), legacyExecution(testCase.id(), status, true));
            var service = new ProtocolEvidenceAutomationService(repository,
                    new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                    ignored -> context(List.of(), TargetRole.IDP));

            assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                    testCase.id(), Outcome.NOT_VERIFIED)), service.evaluateReady(RUN).completed());
            assertEquals(0, repository.outboundActions);
        }
    }

    @Test
    void validInteractionFreeEvidenceFinishesLegacyWaitsAndMissingEvidenceRemainsReevaluatable() {
        for (var status : legacyStatuses()) {
            var repository = new MemoryExecutions();
            var testCase = new InteractionFreeCase(true);
            repository.values.put(RUN + "|" + testCase.id(), legacyExecution(testCase.id(), status, false));
            var service = new ProtocolEvidenceAutomationService(repository,
                    new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                    ignored -> context(List.of(), TargetRole.IDP));
            assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                    testCase.id(), Outcome.SATISFIED)), service.evaluateReady(RUN).completed());
            assertEquals(0, repository.outboundActions);
        }

        var repository = new MemoryExecutions();
        var testCase = new InteractionFreeCase(false);
        repository.values.put(RUN + "|" + testCase.id(),
                legacyExecution(testCase.id(), CaseExecutionStatus.WAITING_BROWSER, false));
        var service = new ProtocolEvidenceAutomationService(repository,
                new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                ignored -> context(List.of(), TargetRole.IDP));
        service.evaluateReady(RUN);
        var missing = repository.find(RUN, testCase.id()).orElseThrow();
        testCase.proven = true;

        assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(
                testCase.id(), Outcome.SATISFIED)), service.evaluateReady(RUN).completed());
        var revised = repository.find(RUN, testCase.id()).orElseThrow();
        assertEquals(missing.revision() + 1, revised.revision());
        assertEquals("NOT_VERIFIED", ((Map<?, ?>) revised.outcome().details()
                .get("previous_recorded_evidence_result")).get("outcome"));
        assertEquals(0, repository.outboundActions);
    }

    @Test
    void interactionFreeCompletionCannotUseAnotherRunOrIncompleteTranscript() {
        var repository = new MemoryExecutions();
        var testCase = new InteractionFreeCase(true);
        var original = legacyExecution(testCase.id(), CaseExecutionStatus.WAITING_BROWSER, false);
        repository.values.put(RUN + "|" + testCase.id(), original);
        var wrongContext = new DefaultCaseContext("another-run", TargetRole.IDP,
                Clock.fixed(NOW, ZoneOffset.UTC), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new MemoryTranscript(List.of()), true);
        var wrongService = new ProtocolEvidenceAutomationService(repository,
                new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository), ignored -> wrongContext);
        assertThrows(IllegalArgumentException.class, () -> wrongService.status(RUN));
        assertThrows(IllegalArgumentException.class, () -> wrongService.evaluateReady(RUN));
        assertEquals(original, repository.find(RUN, testCase.id()).orElseThrow());

        var incompleteContext = new DefaultCaseContext(RUN, TargetRole.IDP,
                Clock.fixed(NOW, ZoneOffset.UTC), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), Reachability.CONFIRMED, new MemoryTranscript(List.of()), false);
        var service = new ProtocolEvidenceAutomationService(repository,
                new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository), ignored -> incompleteContext);
        assertEquals(List.of(new ProtocolEvidenceAutomationService.CompletedCase(testCase.id(), Outcome.NOT_VERIFIED)),
                service.evaluateReady(RUN).completed());
        assertEquals(0, repository.outboundActions);
    }

    @Test
    void unreadyOrdinaryBrowserAndInboundCasesAndConclusiveResultsAreUnchanged() {
        for (var status : List.of(CaseExecutionStatus.WAITING_BROWSER, CaseExecutionStatus.WAITING_INBOUND)) {
            var repository = new MemoryExecutions();
            var testCase = new ReadyQueuedCase(false, Outcome.SATISFIED);
            var original = legacyExecution(testCase.id(), status, false);
            repository.values.put(RUN + "|" + testCase.id(), original);
            var service = new ProtocolEvidenceAutomationService(repository,
                    new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                    ignored -> context(List.of(), TargetRole.IDP));
            assertEquals(List.of(), service.evaluateReady(RUN).completed());
            assertEquals(List.of(), service.evaluateAttempted(RUN).completed());
            assertEquals(original, repository.find(RUN, testCase.id()).orElseThrow());
        }
        for (var outcome : List.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED)) {
            var repository = new MemoryExecutions();
            var testCase = new InteractionFreeCase(false);
            var original = new CaseExecution(RUN, testCase.id(), 3, CaseExecutionStatus.FINISHED,
                    com.samlscope.core.caseexec.CaseState.initial(), null,
                    com.samlscope.core.evaluation.CaseOutcome.of(outcome, "existing", List.of()), NOW);
            repository.values.put(RUN + "|" + testCase.id(), original);
            var service = new ProtocolEvidenceAutomationService(repository,
                    new TestCaseRegistry(List.of(testCase)), new CaseExecutionService(repository),
                    ignored -> context(List.of(), TargetRole.IDP));
            assertEquals(List.of(), service.evaluateReady(RUN).completed());
            assertEquals(List.of(), service.evaluateAttempted(RUN).completed());
            assertEquals(original, repository.find(RUN, testCase.id()).orElseThrow());
            assertEquals(0, testCase.outcomeCalls);
            assertEquals(0, repository.outboundActions);
        }
    }

    private static List<CaseExecutionStatus> legacyStatuses() {
        return List.of(CaseExecutionStatus.RUNNING,
                CaseExecutionStatus.WAITING_BROWSER, CaseExecutionStatus.WAITING_INBOUND);
    }

    private static CaseExecution legacyExecution(String caseId, CaseExecutionStatus status, boolean expired) {
        var wait = status == CaseExecutionStatus.WAITING_BROWSER
                ? new com.samlscope.core.caseexec.WaitCondition(com.samlscope.core.caseexec.WaitCondition.Kind.BROWSER,
                        null, java.net.URI.create("https://suite.example/obsolete-start"), null,
                        expired ? NOW.minusSeconds(60) : NOW.plusSeconds(60))
                : status == CaseExecutionStatus.WAITING_INBOUND
                        ? new com.samlscope.core.caseexec.WaitCondition(com.samlscope.core.caseexec.WaitCondition.Kind.INBOUND,
                                null, null, new com.samlscope.core.caseexec.InboundMatcher(
                                        "saml-response", Map.of("ScenarioActionId", "obsolete-action")),
                                expired ? NOW.minusSeconds(60) : NOW.plusSeconds(60))
                        : null;
        return new CaseExecution(RUN, caseId, 3, status,
                new com.samlscope.core.caseexec.CaseState(status == CaseExecutionStatus.RUNNING
                        ? "runner-queued-front-channel" : "legacy-force-authn", Map.of()), wait, null,
                NOW.minusSeconds(120));
    }

    private static OutboxEntry oldOutbox(String caseId) {
        return new OutboxEntry(RUN, caseId, new OutboundAction("old-action",
                com.samlscope.core.caseexec.OutboundKind.AUTHN_REQUEST, new byte[] {1, 2, 3},
                java.net.URI.create("https://target.example/sso"), false), OutboxStatus.PENDING,
                Map.of(), null, NOW.minusSeconds(120), NOW.minusSeconds(120));
    }

    private static final class InteractionFreeCase implements com.samlscope.runner.cases.InteractionFreeEvidenceCase,
            RecordedEvidenceReevaluation {
        private boolean proven;
        private int outcomeCalls;
        private InteractionFreeCase(boolean proven) { this.proven = proven; }
        @Override public String id() { return "IIP-IDP06-b-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            boolean ready = proven && context.transcriptComplete() && RUN.equals(context.runId());
            return new EvidenceStatus(ready, List.of("native-mechanism-trace"),
                    ready ? List.of("native-mechanism-trace") : List.of(), Map.of());
        }
        @Override public com.samlscope.core.evaluation.CaseOutcome queuedEvidenceOutcome(CaseContext context) {
            outcomeCalls++;
            return evidenceStatus(context).ready()
                    ? com.samlscope.core.evaluation.CaseOutcome.of(Outcome.SATISFIED, "native-mechanism.proven",
                            List.of(new com.samlscope.core.evaluation.EvidenceRef("transcript", "tx_" + RUN)))
                    : com.samlscope.core.evaluation.CaseOutcome.notVerified("native evidence unavailable",
                            "native-mechanism.unproven");
        }
        @Override public boolean supportsRecordedEvidenceReevaluation(com.samlscope.core.evaluation.CaseOutcome previous) {
            return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
        }
        @Override public Optional<com.samlscope.core.evaluation.CaseOutcome> reevaluateRecordedEvidence(
                CaseContext context, com.samlscope.core.evaluation.CaseOutcome previous) {
            return evidenceStatus(context).ready() ? Optional.of(queuedEvidenceOutcome(context)) : Optional.empty();
        }
    }

    private record ReadyQueuedCase(boolean ready, Outcome outcome) implements com.samlscope.core.caseexec.TestCase,
            BrowserFrontChannelScenario, com.samlscope.runner.cases.QueuedProtocolEvidenceCase {
        @Override public String id() { return "IIP-SSO04-a-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String instructionsEn(com.samlscope.core.caseexec.CaseState state) { return "Observe originals"; }
        @Override public com.samlscope.core.caseexec.CaseStep start(CaseContext context) { throw new AssertionError("Queued observation must not start a probe"); }
        @Override public com.samlscope.core.caseexec.CaseStep resume(CaseContext context,com.samlscope.core.caseexec.CaseState state,
                com.samlscope.core.caseexec.CaseEvent event) { throw new AssertionError("Queued observation must not resume a probe"); }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) { return new EvidenceStatus(ready,List.of("originals"),List.of(),Map.of()); }
        @Override public com.samlscope.core.evaluation.CaseOutcome queuedEvidenceOutcome(CaseContext context) {
            return outcome == Outcome.NOT_VERIFIED
                    ? com.samlscope.core.evaluation.CaseOutcome.notVerified("unproven","test.unproven")
                    : com.samlscope.core.evaluation.CaseOutcome.of(outcome,"test.observed",List.of());
        }
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
        private final List<OutboxEntry> outbox = new ArrayList<>();
        private int outboundActions;

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
            outboundActions += actions.size();
            return true;
        }
        @Override public List<OutboxEntry> listOutbox(String runId) {
            return outbox.stream().filter(entry -> runId.equals(entry.runId())).toList();
        }
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
