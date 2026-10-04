package com.samlscope.runner.outbox;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.OutboundKind.Retry;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.evaluation.SuiteIncident;
import com.samlscope.runner.OutboundPolicy;

/** Executes persisted intents. Any ambiguity remains a Suite incident, never a target violation. */
public final class OutboundDispatcher {
    private final CaseExecutionRepository repository;
    private final OutboundSender sender;
    private final EphemeralCredentialProvider credentials;
    private final OutboundPolicy outboundPolicy;
    private final Clock clock;

    public OutboundDispatcher(
            CaseExecutionRepository repository,
            OutboundSender sender,
            EphemeralCredentialProvider credentials,
            OutboundPolicy outboundPolicy,
            Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.sender = Objects.requireNonNull(sender, "sender");
        this.credentials = Objects.requireNonNull(credentials, "credentials");
        this.outboundPolicy = Objects.requireNonNull(outboundPolicy, "outboundPolicy");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public int recoverAfterRestart() {
        return repository.recoverSendingAsUnknownDelivery(clock.instant());
    }

    /** Confirms a previously uncertain send when the awaited target response arrives. */
    public DispatchResult confirmInboundDelivery(String actionId, String transcriptEntryId) {
        var entry = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown outbox action: " + actionId));
        if (entry.status() == OutboxStatus.SENT) return new DispatchResult(State.SENT, List.of());
        if (entry.status() != OutboxStatus.UNKNOWN_DELIVERY) {
            throw new IllegalStateException("Only UNKNOWN_DELIVERY can be confirmed by inbound evidence");
        }
        if (transcriptEntryId == null || transcriptEntryId.isBlank()) {
            throw new IllegalArgumentException("transcriptEntryId must not be blank");
        }
        var recorded = repository.transitionOutbox(
                actionId, OutboxStatus.UNKNOWN_DELIVERY, OutboxStatus.SENT,
                Map.of("confirmed_by", "inbound-response"), transcriptEntryId, clock.instant());
        if (!recorded) {
            return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, "concurrent-dispatch")));
        }
        return new DispatchResult(State.SENT, List.of());
    }

    public DispatchResult dispatch(String actionId) {
        var entry = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown outbox action: " + actionId));
        if (entry.status() == OutboxStatus.SENT) return new DispatchResult(State.SENT, List.of());
        if (entry.status() == OutboxStatus.UNKNOWN_DELIVERY) return retryUnknown(entry);
        if (entry.status() != OutboxStatus.PENDING && entry.status() != OutboxStatus.BLOCKED_ON_CREDENTIAL) {
            return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, "send-already-started")));
        }
        return send(entry, entry.status());
    }

    /**
     * Hands an unsafe front-channel action to a browser. The delivery remains unknown until the
     * correlated inbound message arrives; rendering an auto-submit page is not proof of delivery.
     */
    public FrontChannelDispatch dispatchFrontChannel(
            String actionId, Function<OutboundAction, String> handoffRecorder) {
        Objects.requireNonNull(handoffRecorder, "handoffRecorder");
        var entry = repository.findOutbox(actionId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown outbox action: " + actionId));
        if (entry.action().kind() != OutboundKind.AUTHN_REQUEST && entry.action().kind() != OutboundKind.LOGOUT_REQUEST) {
            throw new IllegalArgumentException("Front-channel dispatcher does not implement "
                    + entry.action().kind());
        }
        if (entry.status() != OutboxStatus.PENDING) {
            throw new IllegalStateException("Unsafe front-channel action cannot be replayed from "
                    + entry.status());
        }
        outboundPolicy.requireAllowed(entry.action().target());
        if (!repository.transitionOutbox(
                actionId, OutboxStatus.PENDING, OutboxStatus.SENDING,
                Map.of(), null, clock.instant())) {
            throw new IllegalStateException("Concurrent front-channel dispatch");
        }
        String transcriptEntryId = null;
        try {
            transcriptEntryId = handoffRecorder.apply(entry.action());
            if (transcriptEntryId == null || transcriptEntryId.isBlank()) {
                throw new IllegalArgumentException("handoffRecorder must return a transcript entry ID");
            }
            if (!repository.transitionOutbox(
                    actionId, OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                    Map.of("transport", "browser-front-channel"), transcriptEntryId, clock.instant())) {
                throw new IllegalStateException("Front-channel delivery state was not persisted");
            }
            return new FrontChannelDispatch(entry.action(), transcriptEntryId);
        } catch (RuntimeException failure) {
            repository.transitionOutbox(
                    actionId, OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                    Map.of("transport", "browser-front-channel",
                            "exception_type", failure.getClass().getName()),
                    transcriptEntryId, clock.instant());
            throw failure;
        }
    }

    private DispatchResult retryUnknown(OutboxEntry entry) {
        if (entry.action().kind().retry() != Retry.SAFE) {
            return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, "delivery-unknown-unsafe")));
        }
        return send(entry, OutboxStatus.UNKNOWN_DELIVERY);
    }

    private DispatchResult send(OutboxEntry entry, OutboxStatus expected) {
        outboundPolicy.requireAllowed(entry.action().target());
        byte[] credential = new byte[0];
        if (entry.action().requiresEphemeralCredential()) {
            var supplied = credentials.credentialFor(entry.runId(), entry.action().actionId());
            if (supplied.isEmpty()) {
                var blocked = repository.transitionOutbox(
                        entry.action().actionId(), expected, OutboxStatus.BLOCKED_ON_CREDENTIAL,
                        Map.of(), null, clock.instant());
                if (!blocked) {
                    return new DispatchResult(
                            State.UNKNOWN_DELIVERY, List.of(incident(entry, "concurrent-dispatch")));
                }
                return new DispatchResult(State.BLOCKED_ON_CREDENTIAL, List.of());
            }
            credential = supplied.orElseThrow().clone();
        }

        try {
            if (!repository.transitionOutbox(
                    entry.action().actionId(), expected, OutboxStatus.SENDING,
                    Map.of(), null, clock.instant())) {
                return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, "concurrent-dispatch")));
            }
            var result = sender.send(entry.runId(), entry.action(), credential);
            if (result.replayRejected()) {
                var recorded = repository.transitionOutbox(
                        entry.action().actionId(), OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                        result.details(), result.transcriptEntryId(), clock.instant());
                var note = recorded ? "replay-after-unknown-delivery" : "delivery-state-not-persisted";
                return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, note)));
            }
            var recorded = repository.transitionOutbox(
                    entry.action().actionId(), OutboxStatus.SENDING, OutboxStatus.SENT,
                    result.details(), result.transcriptEntryId(), clock.instant());
            if (!recorded) {
                return new DispatchResult(
                        State.UNKNOWN_DELIVERY, List.of(incident(entry, "delivery-state-not-persisted")));
            }
            return new DispatchResult(State.SENT, List.of());
        } catch (Exception failure) {
            repository.transitionOutbox(
                    entry.action().actionId(), OutboxStatus.SENDING, OutboxStatus.UNKNOWN_DELIVERY,
                    Map.of("exception_type", failure.getClass().getName()), null, clock.instant());
            return new DispatchResult(State.UNKNOWN_DELIVERY, List.of(incident(entry, "delivery-unknown")));
        } finally {
            java.util.Arrays.fill(credential, (byte) 0);
        }
    }

    private SuiteIncident incident(OutboxEntry entry, String note) {
        return new SuiteIncident(
                "UNKNOWN_DELIVERY", entry.caseId(), entry.action().actionId(), note);
    }

    public record DispatchResult(State state, List<SuiteIncident> incidents) {
        public DispatchResult { incidents = List.copyOf(incidents); }
    }

    public record FrontChannelDispatch(OutboundAction action, String transcriptEntryId) {
        public FrontChannelDispatch {
            Objects.requireNonNull(action, "action");
            if (transcriptEntryId == null || transcriptEntryId.isBlank()) {
                throw new IllegalArgumentException("transcriptEntryId must not be blank");
            }
        }
    }

    public enum State { SENT, BLOCKED_ON_CREDENTIAL, UNKNOWN_DELIVERY }
}
