package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptHistoryLimitExceeded;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.BrowserPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

class TranscriptAutomationRecorderTest {
    private static final String RUN = "run";
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void closeWaitsForInFlightReconciliationBeforeStorageCanBeRemoved() throws Exception {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate);
        var entered = new java.util.concurrent.CountDownLatch(1);
        var interrupted = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var finished = new java.util.concurrent.atomic.AtomicBoolean();
        recorder.onRecorded(ignored -> {
            entered.countDown();
            try { release.await(); }
            catch (InterruptedException stopping) {
                interrupted.countDown();
                try { release.await(); }
                catch (InterruptedException repeated) { Thread.currentThread().interrupt(); }
            }
            finished.set(true);
        });
        recorder.record(input());
        org.junit.jupiter.api.Assertions.assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
        var closing = java.util.concurrent.CompletableFuture.runAsync(recorder::close);
        try {
            org.junit.jupiter.api.Assertions.assertTrue(interrupted.await(5, java.util.concurrent.TimeUnit.SECONDS));
            assertThrows(java.util.concurrent.TimeoutException.class,
                    () -> closing.get(50, java.util.concurrent.TimeUnit.MILLISECONDS));
        } finally {
            release.countDown();
            closing.get(5, java.util.concurrent.TimeUnit.SECONDS);
        }
        org.junit.jupiter.api.Assertions.assertTrue(finished.get());
        recorder.close();
    }

    @Test
    void notifiesAfterDurableRecordAndDoesNotBreakProtocolTrafficWhenReconciliationFails() {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var calls = new AtomicInteger();
        recorder.onRecorded(runId -> {
            calls.incrementAndGet();
            throw new IllegalStateException("retry on the next observation");
        });

        var recorded = recorder.record(input());
        recorder.updateSamlAnalysis(recorded.id(), "request", Map.of("type", "Response"));

        assertEquals(2, calls.get());
        assertEquals(1, recorder.list("run").size());
        assertThrows(IllegalStateException.class, () -> recorder.onRecorded(ignored -> { }));
    }

    @Test
    void completedSamlAnalysisFinishesAWaitingCaseWithoutAnOperatorCompletionEvent() {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var repository = new MemoryExecutions();
        var transitions = new CaseExecutionService(repository);
        var testCase = new ResponseTranscriptCase();
        var context = new DefaultCaseContext(
                RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(),
                Reachability.CONFIRMED, recorder, true);
        transitions.start(RUN, testCase, context);
        var automation = new ProtocolEvidenceAutomationService(
                repository, new TestCaseRegistry(List.of(testCase)), transitions, ignored -> context);
        recorder.onRecorded(automation::evaluateReady);

        var entry = recorder.record(input());
        assertEquals(CaseExecutionStatus.WAITING_BROWSER,
                repository.find(RUN, testCase.id()).orElseThrow().status());

        recorder.updateSamlAnalysis(entry.id(), "request", Map.of("type", "Response"));

        var finished = repository.find(RUN, testCase.id()).orElseThrow();
        assertEquals(CaseExecutionStatus.FINISHED, finished.status());
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
    }

    @Test
    void queuesWithoutBlockingTheRecorderAndCoalescesABurstPerRun() {
        var delegate = new MemoryRecorder();
        var executor = new QueuedExecutor();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, executor);
        var calls = new AtomicInteger();
        recorder.onRecorded(ignored -> calls.incrementAndGet());

        recorder.record(input());
        recorder.record(input());

        assertEquals(0, calls.get(), "recording must not execute reconciliation on the peer thread");
        assertEquals(1, executor.tasks.size(), "one Run has at most one queued reconciliation");
        executor.runNext();
        assertEquals(1, calls.get());
    }

    @Test
    void anEntryRecordedDuringReconciliationRequestsOnlyOneFollowUpPass() {
        var delegate = new MemoryRecorder();
        var executor = new QueuedExecutor();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, executor);
        var calls = new AtomicInteger();
        recorder.onRecorded(ignored -> {
            if (calls.incrementAndGet() == 1) {
                recorder.record(input());
                recorder.record(input());
            }
        });

        recorder.record(input());
        executor.runNext();
        assertEquals(1, executor.tasks.size());
        executor.runNext();
        assertEquals(2, calls.get());
    }

    @Test
    void pendingSamlAnalysisSchedulesOnlyItsValidatedUpdate() {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var calls = new AtomicInteger();
        recorder.onRecorded(ignored -> calls.incrementAndGet());
        var pendingInput = new TranscriptInput(
                RUN, Direction.INBOUND, NOW, "corr", "POST", "https://suite.example/acs", 200,
                Map.of(), new byte[0], "application/x-www-form-urlencoded", null,
                "<Response/>".getBytes(), Map.of("parseStatus", "not-yet-parsed"));

        var entry = recorder.record(pendingInput);
        recorder.updateSamlAnalysis(entry.id(), "request", Map.of("type", "Response"));

        assertEquals(1, calls.get());
    }

    @Test
    void aFullQueueNeverBreaksDurableRecording() {
        var delegate = new MemoryRecorder();
        Executor rejected = ignored -> { throw new RejectedExecutionException("full"); };
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, rejected);
        recorder.onRecorded(ignored -> { });

        var entry = recorder.record(input());

        assertEquals("tx", entry.id());
        assertEquals(1, recorder.list(RUN).size());
    }

    @Test
    void automaticReconciliationStopsAtThePerRunPassBudget() {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var calls = new AtomicInteger();
        recorder.onRecorded(ignored -> calls.incrementAndGet());

        for (var index = 0; index < TranscriptAutomationRecorder.MAX_AUTOMATIC_PASSES_PER_RUN + 2; index++) {
            recorder.record(input());
        }

        assertEquals(TranscriptAutomationRecorder.MAX_AUTOMATIC_PASSES_PER_RUN, calls.get());
        assertEquals(1, recorder.list(RUN).size(), "durable evidence remains explicitly readable");
    }

    @Test
    void oversizedHistoryDisablesAutomaticScanningWithoutTruncatingExplicitReads() {
        var delegate = new OversizedRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var calls = new AtomicInteger();
        recorder.onRecorded(runId -> {
            calls.incrementAndGet();
            recorder.list(runId);
        });

        recorder.record(input());
        recorder.record(input());

        assertEquals(1, calls.get(), "the over-limit Run must not be scheduled again");
        assertEquals(1, recorder.list(RUN).size(), "explicit reads are not truncated by the automation limit");
    }

    @Test
    void oversizedDecodedEvidenceDisablesAutomaticScanningBeforeContentReads() {
        var delegate = new MemoryRecorder();
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, Runnable::run);
        var calls = new AtomicInteger();
        recorder.onRecorded(runId -> {
            calls.incrementAndGet();
            var entries = recorder.list(runId);
            recorder.readDecodedSaml(entries.getFirst());
        });

        recorder.record(inputWithDeclaredDecodedBytes(
                Math.toIntExact(TranscriptAutomationRecorder.MAX_AUTOMATIC_DECODED_BYTES + 1)));
        recorder.record(input());

        assertEquals(1, calls.get(), "the over-limit Run must not attempt another automatic scan");
        assertEquals(0, delegate.contentReads.get(), "oversized content must not be loaded automatically");
    }

    @Test
    void aQueueOverflowVictimIsRetriedWithoutAnotherEvidenceEvent() {
        var delegate = new MemoryRecorder();
        var executor = new QueuedExecutor(2);
        var recorder = new TranscriptAutomationRecorder(delegate, delegate, executor);
        var reconciled = new ArrayList<String>();
        recorder.onRecorded(reconciled::add);

        recorder.record(input("run-a"));
        recorder.record(input("run-b"));
        recorder.record(input("run-victim"));
        executor.runNext();
        executor.runNext();
        executor.runNext();

        assertEquals(List.of("run-a", "run-b", "run-victim"), reconciled);
    }

    private TranscriptInput input() {
        return input(RUN);
    }

    private TranscriptInput input(String runId) {
        return new TranscriptInput(
                runId, Direction.INBOUND, NOW, "corr", "POST",
                "https://suite.example/acs", 200, Map.of(), new byte[0],
                "application/x-www-form-urlencoded", null, "<Response/>".getBytes(), Map.of());
    }

    private TranscriptInput inputWithDeclaredDecodedBytes(int bytes) {
        return new TranscriptInput(
                RUN, Direction.INBOUND, NOW, "corr", "POST",
                "https://suite.example/acs", 200, Map.of(), new byte[0],
                "application/x-www-form-urlencoded", null, new byte[bytes], Map.of());
    }

    private static class MemoryRecorder implements TranscriptRecorder, TranscriptContentReader {
        private TranscriptEntry entry;
        private final AtomicInteger contentReads = new AtomicInteger();
        @Override public TranscriptEntry record(TranscriptInput input) {
            entry = new TranscriptEntry(
                    "tx", input.runId(), input.direction(), input.timestamp(), input.correlationId(),
                    input.method(), input.url(), input.status(), input.headers(), null, 0,
                    "decoded", input.decodedSaml().length, input.contentType(), input.rawQuery(),
                    input.samlSummary());
            return entry;
        }
        @Override public TranscriptEntry updateSamlAnalysis(
                String entryId, String correlationId, Map<String, Object> summary) {
            entry = new TranscriptEntry(
                    entry.id(), entry.runId(), entry.direction(), entry.timestamp(), correlationId,
                    entry.method(), entry.url(), entry.status(), entry.headers(), entry.bodyRef(),
                    entry.bodyBytes(), entry.decodedSamlRef(), entry.decodedSamlBytes(),
                    entry.contentType(), entry.rawQuery(), Map.copyOf(summary));
            return entry;
        }
        @Override public List<TranscriptEntry> list(String runId) { return List.of(entry); }
        @Override public byte[] readDecodedSaml(TranscriptEntry value) {
            contentReads.incrementAndGet();
            return "<Response/>".getBytes();
        }
    }

    private static final class OversizedRecorder extends MemoryRecorder {
        @Override public List<TranscriptEntry> listBounded(String runId, int maximumEntries) {
            throw new TranscriptHistoryLimitExceeded(runId, maximumEntries);
        }
    }

    private static final class QueuedExecutor implements Executor {
        private final ArrayDeque<Runnable> tasks = new ArrayDeque<>();
        private final int capacity;
        private QueuedExecutor() { this(Integer.MAX_VALUE); }
        private QueuedExecutor(int capacity) { this.capacity = capacity; }
        @Override public void execute(Runnable command) {
            if (tasks.size() >= capacity) throw new RejectedExecutionException("full");
            tasks.add(command);
        }
        private void runNext() { tasks.remove().run(); }
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
                String actionId, OutboxStatus expected, OutboxStatus next,
                Map<String, Object> sendResult, String transcriptEntryId, Instant updatedAt) {
            return false;
        }
        @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
    }

    private static final class ResponseTranscriptCase
            implements TestCase, BrowserPrompt, ProtocolEvidenceCase {
        @Override public String id() { return "IIP-SSO03-a-idp-01"; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String browserInstructionsEn() { return "Perform the ordinary SSO flow."; }
        @Override public CaseStep start(CaseContext context) {
            return new CaseStep.AwaitBrowser(
                    new CaseState("await-response", Map.of()), List.of(),
                    java.net.URI.create("https://suite.example/start"), java.time.Duration.ofMinutes(5));
        }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            if (!(event instanceof CaseEvent.TranscriptReady)) {
                throw new IllegalArgumentException("Transcript evidence is required");
            }
            return new CaseStep.Finish(CaseOutcome.of(
                    Outcome.SATISFIED, "transcript-ready", List.of()));
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            var ready = context.transcript().list(context.runId()).stream()
                    .anyMatch(entry -> "Response".equals(entry.samlSummary().get("type")));
            return new EvidenceStatus(
                    ready, List.of("response"), ready ? List.of("response") : List.of(), Map.of());
        }
    }
}
