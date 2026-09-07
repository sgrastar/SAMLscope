package com.samlscope.runner;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.caseexec.WaitCondition;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.plan.TestPlan;

/** Applies pure case transitions and persists state plus outbox intents atomically. */
public final class CaseExecutionService {
    private final CaseExecutionRepository repository;
    private final java.util.function.BiFunction<String, OutboundAction, OutboundAction> requestSigning;

    public CaseExecutionService(CaseExecutionRepository repository) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.requestSigning = null;
    }

    public CaseExecutionService(CaseExecutionRepository repository,
            java.util.function.BiFunction<String, OutboundAction, OutboundAction> requestSigning) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.requestSigning = Objects.requireNonNull(requestSigning, "requestSigning");
    }

    public CaseExecution start(String runId, TestCase testCase, CaseContext context) {
        requireMatchingRun(runId, testCase, context);
        var existing = repository.find(runId, testCase.id());
        if (existing.isPresent()) return existing.orElseThrow();
        return apply(runId, testCase.id(), -1, CaseState.initial(),
                testCase.start(context), context.clock().instant(), context.interaction(), context.parameters().requestSigningMode());
    }

    public CaseExecution resume(
            String runId, TestCase testCase, CaseContext context, CaseEvent event) {
        requireMatchingRun(runId, testCase, context);
        var current = repository.find(runId, testCase.id())
                .orElseThrow(() -> new IllegalArgumentException("Case has not started: " + testCase.id()));
        if (current.status() == CaseExecutionStatus.FINISHED) return current;
        requireExpectedEvent(current, event, context.clock().instant());
        return apply(runId, testCase.id(), current.revision(), current.state(),
                testCase.resume(context, current.state(), event), context.clock().instant(), context.interaction(), context.parameters().requestSigningMode());
    }

    private void requireMatchingRun(String runId, TestCase testCase, CaseContext context) {
        if (context == null || !runId.equals(context.runId())) {
            throw new IllegalArgumentException("CaseContext belongs to another Run");
        }
        if (testCase == null || testCase.role() != context.targetRole()) {
            throw new IllegalArgumentException("TestCase belongs to another target role");
        }
    }

    private CaseExecution apply(
            String runId,
            String caseId,
            long expectedRevision,
            CaseState current,
            CaseStep step,
            Instant now,
            TestPlan.Interaction interaction,
            TestPlan.RequestSigningMode signingMode) {
        var transition = transition(current, step, now, interaction);
        validateActionIds(runId, caseId, transition.state(), transition.actions());
        List<OutboundAction> actions;
        try {
            if (requestSigning == null && signingMode == TestPlan.RequestSigningMode.REQUIRED
                    && transition.actions().stream().anyMatch(action ->
                            action.kind() == com.samlscope.core.caseexec.OutboundKind.AUTHN_REQUEST)) {
                throw new com.samlscope.saml.normal.SamlException("Required request signer was not configured");
            }
            actions = requestSigning == null ? transition.actions()
                    : transition.actions().stream().map(action -> requestSigning.apply(runId, action)).toList();
        } catch (com.samlscope.saml.normal.SamlException unsupportedFixture) {
            transition = new Transition(CaseExecutionStatus.FINISHED, current, null,
                    CaseOutcome.notVerified("request_signing_unavailable", "request.signing.unavailable"), List.of());
            actions = List.of();
        }
        var execution = new CaseExecution(
                runId,
                caseId,
                expectedRevision + 1,
                transition.status(),
                transition.state(),
                transition.waitCondition(),
                transition.outcome(),
                now);
        if (repository.apply(expectedRevision, execution, actions)) return execution;
        return repository.find(runId, caseId)
                .orElseThrow(() -> new IllegalStateException("Concurrent case transition was not persisted"));
    }

    private Transition transition(
            CaseState current,
            CaseStep step,
            Instant now,
            TestPlan.Interaction interaction) {
        return switch (step) {
            case CaseStep.Continue value -> new Transition(
                    CaseExecutionStatus.RUNNING, value.next(), null, null, value.actions());
            case CaseStep.AwaitBrowser value -> interaction.allowBrowserSteps()
                    ? new Transition(
                            CaseExecutionStatus.WAITING_BROWSER,
                            value.next(),
                            new WaitCondition(
                                    WaitCondition.Kind.BROWSER, null, value.startUrl(), null, now.plus(value.ttl())),
                            null,
                            value.actions())
                    : interactionDisallowed(current);
            case CaseStep.AwaitConfig value -> new Transition(
                    CaseExecutionStatus.WAITING_CONFIG,
                    value.next(),
                    new WaitCondition(WaitCondition.Kind.CONFIG, value.instructionKey(), null, null,
                            now.plus(value.ttl())),
                    null,
                    value.actions());
            case CaseStep.AwaitAttestation value -> interaction.allowAttestation()
                    ? new Transition(
                            CaseExecutionStatus.WAITING_ATTESTATION,
                            value.next(),
                            new WaitCondition(WaitCondition.Kind.ATTESTATION, value.questionKey(), null, null,
                                    now.plus(value.ttl())),
                            null,
                            value.actions())
                    : interactionDisallowed(current);
            case CaseStep.AwaitInbound value -> new Transition(
                    CaseExecutionStatus.WAITING_INBOUND,
                    value.next(),
                    new WaitCondition(WaitCondition.Kind.INBOUND, null, null, value.matcher(), now.plus(value.ttl())),
                    null,
                    value.actions());
            case CaseStep.Finish value -> new Transition(
                    CaseExecutionStatus.FINISHED, current, null, value.outcome(), List.of());
        };
    }

    private Transition interactionDisallowed(CaseState current) {
        return new Transition(
                CaseExecutionStatus.FINISHED,
                current,
                null,
                CaseOutcome.notVerified(
                        "interaction_disallowed", "interaction.disallowed"),
                List.of());
    }

    private void validateActionIds(
            String runId, String caseId, CaseState next, List<OutboundAction> actions) {
        for (var sequence = 0; sequence < actions.size(); sequence++) {
            var expected = ActionIds.derive(runId, caseId, next.phase(), sequence);
            if (!expected.equals(actions.get(sequence).actionId())) {
                throw new IllegalArgumentException(
                        "Outbound actionId must be deterministic for phase " + next.phase());
            }
        }
    }

    private void requireExpectedEvent(CaseExecution current, CaseEvent event, Instant now) {
        if (event == null) throw new IllegalArgumentException("event is required");
        if (current.waitCondition() != null
                && now.isAfter(current.waitCondition().expiresAt())
                && !(event instanceof CaseEvent.TimedOut)
                && !(event instanceof CaseEvent.Aborted)
                && !(event instanceof CaseEvent.RetryInbound)) {
            throw new IllegalArgumentException("Waiting case has expired; resume it with TimedOut");
        }
        var accepted = event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.Aborted || switch (current.status()) {
            case RUNNING -> event instanceof CaseEvent.Custom;
            case WAITING_BROWSER -> event instanceof CaseEvent.BrowserReturned
                    || event instanceof CaseEvent.TranscriptReady;
            case WAITING_CONFIG -> event instanceof CaseEvent.ConfigConfirmed
                    || event instanceof CaseEvent.ConfigUnavailable;
            case WAITING_ATTESTATION -> event instanceof CaseEvent.Attested;
            case WAITING_INBOUND -> event instanceof CaseEvent.InboundMessage
                    || event instanceof CaseEvent.InboundUnavailable
                    || event instanceof CaseEvent.RetryInbound;
            case FINISHED -> false;
        };
        if (!accepted) {
            throw new IllegalArgumentException(
                    "Event " + event.getClass().getSimpleName() + " does not match " + current.status());
        }
    }

    private record Transition(
            CaseExecutionStatus status,
            CaseState state,
            WaitCondition waitCondition,
            CaseOutcome outcome,
            List<OutboundAction> actions) {}
}
