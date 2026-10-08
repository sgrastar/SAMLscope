package com.samlscope.runner;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptHistoryLimitExceeded;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

/** Records first, then asks the evidence reconciler to advance any now-complete cases. */
public final class TranscriptAutomationRecorder
        implements TranscriptRecorder, TranscriptContentReader, AutoCloseable {
    private static final Logger LOG = Logger.getLogger(TranscriptAutomationRecorder.class.getName());
    static final int MAX_AUTOMATIC_TRANSCRIPT_ENTRIES = 256;
    static final long MAX_AUTOMATIC_DECODED_BYTES = 16L * 1024 * 1024;
    static final int MAX_AUTOMATIC_PASSES_PER_RUN = 64;
    private final TranscriptRecorder recorder;
    private final TranscriptContentReader content;
    private final Executor executor;
    private final Runnable shutdown;
    private final Object schedulingLock = new Object();
    private boolean closed;
    private final Map<String, PendingReconciliation> pending = new LinkedHashMap<>();
    private final ThreadLocal<AutomaticSnapshot> automaticSnapshot = new ThreadLocal<>();
    private final AtomicReference<Consumer<String>> listener = new AtomicReference<>();

    public TranscriptAutomationRecorder(
            TranscriptRecorder recorder, TranscriptContentReader content) {
        this(recorder, content, newDefaultExecutor());
    }

    private TranscriptAutomationRecorder(
            TranscriptRecorder recorder, TranscriptContentReader content, ExecutorService executor) {
        this(recorder, content, executor, () -> stopExecutor(executor));
    }

    TranscriptAutomationRecorder(
            TranscriptRecorder recorder, TranscriptContentReader content, Executor executor) {
        this(recorder, content, executor, () -> { });
    }

    private TranscriptAutomationRecorder(
            TranscriptRecorder recorder,
            TranscriptContentReader content,
            Executor executor,
            Runnable shutdown) {
        this.recorder = Objects.requireNonNull(recorder, "recorder");
        this.content = Objects.requireNonNull(content, "content");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.shutdown = Objects.requireNonNull(shutdown, "shutdown");
    }

    /** Installs the one Run-scoped reconciliation listener after runtime construction. */
    public void onRecorded(Consumer<String> value) {
        Objects.requireNonNull(value, "value");
        if (!listener.compareAndSet(null, value)) {
            throw new IllegalStateException("Transcript automation listener is already installed");
        }
    }

    @Override
    public TranscriptEntry record(TranscriptInput input) {
        var entry = recorder.record(input);
        // Inbound SAML is deliberately recorded before parsing. Its atomic analysis update is the
        // first form from which evidence automation may conclude, so avoid scheduling two scans.
        if (!"not-yet-parsed".equals(input.samlSummary().get("parseStatus"))) {
            notifyRecorded(entry.runId());
        }
        return entry;
    }

    @Override
    public TranscriptEntry updateSamlAnalysis(
            String entryId, String correlationId, Map<String, Object> samlSummary) {
        var entry = recorder.updateSamlAnalysis(entryId, correlationId, samlSummary);
        notifyRecorded(entry.runId());
        return entry;
    }

    @Override
    public List<TranscriptEntry> list(String runId) {
        var snapshot = automaticSnapshot.get();
        if (snapshot == null || !snapshot.runId.equals(runId)) return recorder.list(runId);
        if (snapshot.entries == null) {
            snapshot.entries = recorder.listBounded(runId, MAX_AUTOMATIC_TRANSCRIPT_ENTRIES);
            var decodedBytes = snapshot.entries.stream().mapToLong(TranscriptEntry::decodedSamlBytes).sum();
            if (decodedBytes > MAX_AUTOMATIC_DECODED_BYTES) {
                throw new TranscriptHistoryLimitExceeded(
                        runId, decodedBytes, MAX_AUTOMATIC_DECODED_BYTES);
            }
        }
        return snapshot.entries;
    }
    @Override public byte[] readDecodedSaml(TranscriptEntry entry) { return content.readDecodedSaml(entry); }
    @Override public byte[] readBody(TranscriptEntry entry) { return content.readBody(entry); }

    @Override
    public void close() {
        synchronized (schedulingLock) {
            closed = true;
            pending.clear();
        }
        shutdown.run();
    }

    private static void stopExecutor(ExecutorService executor) {
        executor.shutdownNow();
        try {
            if (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Transcript reconciliation did not stop before shutdown");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while stopping Transcript reconciliation", interrupted);
        }
    }

    private void notifyRecorded(String runId) {
        if (listener.get() == null) return;
        synchronized (schedulingLock) {
            if (closed) return;
            var state = pending.computeIfAbsent(runId, ignored -> new PendingReconciliation());
            if (state.automaticDisabled) return;
            state.dirty = true;
            if (!state.scheduled) enqueueLocked(runId, state);
        }
    }

    /** Caller holds schedulingLock; executor admission is nonblocking. */
    private void enqueueLocked(String runId, PendingReconciliation state) {
        state.scheduled = true;
        try {
            executor.execute(() -> reconcileOnce(runId, state));
        } catch (RejectedExecutionException rejected) {
            state.scheduled = false;
            // Evidence is durable. A later entry or management refresh retries reconciliation.
            LOG.log(Level.WARNING, "Transcript evidence reconciliation queue is full for " + runId, rejected);
        }
    }

    private void reconcileOnce(String runId, PendingReconciliation state) {
        synchronized (schedulingLock) {
            if (pending.get(runId) != state) return;
            if (state.automaticPasses >= MAX_AUTOMATIC_PASSES_PER_RUN) {
                state.automaticDisabled = true;
                state.scheduled = false;
                state.dirty = false;
                LOG.warning("Automatic Transcript reconciliation pass limit reached for " + runId);
                pending.remove(runId);
                pending.put(runId, state);
                scheduleOldestDirtyLocked();
                return;
            }
            state.automaticPasses++;
            state.dirty = false;
        }
        automaticSnapshot.set(new AutomaticSnapshot(runId));
        try {
            var value = listener.get();
            if (value != null) value.accept(runId);
        } catch (TranscriptHistoryLimitExceeded limit) {
            synchronized (schedulingLock) {
                state.automaticDisabled = true;
                state.dirty = false;
            }
            // The complete Transcript remains available to explicit, authorized reconciliation.
            LOG.log(Level.WARNING, "Automatic Transcript reconciliation disabled for " + runId, limit);
        } catch (RuntimeException failure) {
            // Evidence is safely recorded already. A later entry or management refresh retries reconciliation.
            LOG.log(Level.WARNING, "Transcript evidence reconciliation failed for " + runId, failure);
        } finally {
            automaticSnapshot.remove();
            synchronized (schedulingLock) {
                if (pending.get(runId) != state) return;
                state.scheduled = false;
                // Move the just-served Run behind previously rejected Runs. One executor slot is
                // now free, so the oldest dirty Run gets a reliable retry before new fan-out.
                pending.remove(runId);
                pending.put(runId, state);
                scheduleOldestDirtyLocked();
            }
        }
    }

    private void scheduleOldestDirtyLocked() {
        for (var entry : pending.entrySet()) {
            var state = entry.getValue();
            if (state.dirty && !state.scheduled && !state.automaticDisabled) {
                enqueueLocked(entry.getKey(), state);
                return;
            }
        }
    }

    private static ExecutorService newDefaultExecutor() {
        return new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(256), runnable -> {
                    var thread = new Thread(runnable, "samlscope-transcript-reconciler");
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
    }

    private static final class PendingReconciliation {
        private boolean dirty;
        private boolean scheduled;
        private boolean automaticDisabled;
        private int automaticPasses;
    }

    private static final class AutomaticSnapshot {
        private final String runId;
        private List<TranscriptEntry> entries;

        private AutomaticSnapshot(String runId) { this.runId = runId; }
    }
}
