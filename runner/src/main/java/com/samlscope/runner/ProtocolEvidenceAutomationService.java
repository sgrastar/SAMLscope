package com.samlscope.runner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

/** Advances recorded-evidence cases; explicitly interaction-free old waits may finish unverified. */
public final class ProtocolEvidenceAutomationService {
    private final com.samlscope.core.caseexec.CaseExecutionRepository executions;
    private final TestCaseRegistry registry;
    private final CaseExecutionService transitions;
    private final CaseContextProvider contexts;

    public ProtocolEvidenceAutomationService(
            com.samlscope.core.caseexec.CaseExecutionRepository executions,
            TestCaseRegistry registry,
            CaseExecutionService transitions,
            CaseContextProvider contexts) {
        this.executions = Objects.requireNonNull(executions, "executions");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.transitions = Objects.requireNonNull(transitions, "transitions");
        this.contexts = Objects.requireNonNull(contexts, "contexts");
    }

    public Status status(String runId) {
        var context = contexts.contextFor(required(runId));
        if (context == null || !runId.equals(context.runId()))
            throw new IllegalArgumentException("CaseContext belongs to another Run");
        var cases = new ArrayList<CaseStatus>();
        for (var execution : executions.list(runId)) {
            if (execution.status() != CaseExecutionStatus.WAITING_CONFIG
                    && execution.status() != CaseExecutionStatus.WAITING_BROWSER
                    && execution.status() != CaseExecutionStatus.WAITING_INBOUND
                    && execution.status() != CaseExecutionStatus.FINISHED
                    && !CaseExecutionService.isQueuedFrontChannel(execution)) continue;
            var testCase = execution.status() == CaseExecutionStatus.FINISHED
                    || execution.status() == CaseExecutionStatus.WAITING_INBOUND
                    || CaseExecutionService.isQueuedFrontChannel(execution)
                    ? registry.find(execution.caseId()).orElse(null) : registry.require(execution.caseId());
            if (testCase == null) continue;
            boolean interactionFree = interactionFreeLegacyWait(testCase, execution);
            boolean queued = CaseExecutionService.isQueuedFrontChannel(execution)
                    && testCase instanceof com.samlscope.runner.cases.QueuedProtocolEvidenceCase;
            boolean reconsider = execution.status() == CaseExecutionStatus.FINISHED
                    && testCase instanceof RecordedEvidenceReevaluation observer
                    && observer.supportsRecordedEvidenceReevaluation(execution.outcome());
            if (execution.status() != CaseExecutionStatus.WAITING_CONFIG
                    && execution.status() != CaseExecutionStatus.WAITING_BROWSER
                    && !reconsider && !queued && !interactionFree) continue;
            if (!(testCase instanceof ProtocolEvidenceCase evidenceCase)) continue;
            var evidence = evidenceCase.evidenceStatus(context);
            boolean ready = evidence.ready() && (!reconsider
                    || ((RecordedEvidenceReevaluation) testCase).reevaluateRecordedEvidence(context, execution.outcome()).isPresent());
            cases.add(new CaseStatus(
                    execution.caseId(), ready, evidence.requiredObservations(),
                    evidence.completedObservations(), evidence.details()));
        }
        cases.sort(java.util.Comparator.comparing(CaseStatus::caseId));
        return new Status(cases.size(), (int) cases.stream().filter(CaseStatus::ready).count(), cases);
    }

    public Evaluation evaluateReady(String runId) {
        return evaluate(runId, false);
    }

    /**
     * Finishes a metadata campaign after the operator confirms that every selected fixture was
     * refreshed or re-imported and the corresponding protocol operation was attempted. This is a
     * single operation confirmation, not a per-case verdict questionnaire; each case still derives
     * its own outcome from Transcript evidence.
     */
    public Evaluation evaluateAttempted(String runId) {
        return evaluate(runId, true);
    }

    private Evaluation evaluate(String runId, boolean attemptsConfirmed) {
        var before = status(runId);
        var context = contexts.contextFor(runId);
        var completed = new ArrayList<CompletedCase>();
        for (var candidate : before.cases()) {
            var testCase = registry.require(candidate.caseId());
            var beforeExecution = executions.find(runId, candidate.caseId()).orElseThrow();
            boolean interactionFree = interactionFreeLegacyWait(testCase, beforeExecution);
            if (!candidate.ready() && !attemptsConfirmed && !interactionFree) continue;
            if (interactionFree) {
                // The marker permits only a recorded-evidence Finish. Missing evidence is
                // NOT_VERIFIED, without reviving the obsolete browser operation or its outbox.
                var revised = transitions.resume(runId, testCase, context,
                        interactionFreeEvent(beforeExecution, context));
                if (revised.status() != CaseExecutionStatus.FINISHED || revised.outcome() == null)
                    throw new IllegalStateException("Interaction-free case did not finish: " + candidate.caseId());
                if (revised.revision() > beforeExecution.revision())
                    completed.add(new CompletedCase(revised.caseId(), revised.outcome().outcome()));
                continue;
            }
            if (CaseExecutionService.isQueuedFrontChannel(beforeExecution)) {
                if (!candidate.ready()) continue; // Attempt confirmation cannot bypass evidence readiness.
                var revised = transitions.completeQueuedFromRecordedEvidence(runId, testCase, context);
                if (revised.status() == CaseExecutionStatus.FINISHED && revised.revision() > beforeExecution.revision()) {
                    completed.add(new CompletedCase(revised.caseId(), revised.outcome().outcome()));
                }
                continue;
            }
            if (beforeExecution.status() == CaseExecutionStatus.FINISHED) {
                var revised = transitions.reevaluateRecordedEvidence(runId, testCase, context);
                if (revised.revision() > beforeExecution.revision()) {
                    completed.add(new CompletedCase(revised.caseId(), revised.outcome().outcome()));
                }
                continue;
            }
            if (attemptsConfirmed && beforeExecution.status() != CaseExecutionStatus.WAITING_CONFIG) continue;
            var event = beforeExecution.status() == CaseExecutionStatus.WAITING_BROWSER
                    ? new CaseEvent.TranscriptReady()
                    : new CaseEvent.ConfigConfirmed();
            var execution = transitions.resume(runId, testCase, context, event);
            if (execution.status() != CaseExecutionStatus.FINISHED || execution.outcome() == null) {
                throw new IllegalStateException("Evidence-driven case did not finish: " + candidate.caseId());
            }
            completed.add(new CompletedCase(candidate.caseId(), execution.outcome().outcome()));
        }
        return new Evaluation(List.copyOf(completed), status(runId));
    }

    private static boolean interactionFreeLegacyWait(
            com.samlscope.core.caseexec.TestCase testCase,
            com.samlscope.core.caseexec.CaseExecution execution) {
        return testCase instanceof com.samlscope.runner.cases.InteractionFreeEvidenceCase
                && (CaseExecutionService.isQueuedFrontChannel(execution)
                        || execution.status() == CaseExecutionStatus.WAITING_BROWSER
                        || execution.status() == CaseExecutionStatus.WAITING_INBOUND);
    }

    private static CaseEvent interactionFreeEvent(
            com.samlscope.core.caseexec.CaseExecution execution,
            com.samlscope.core.caseexec.CaseContext context) {
        var wait = execution.waitCondition();
        var now = context.clock().instant();
        if (wait != null && now.isAfter(wait.expiresAt()))
            return new CaseEvent.TimedOut(java.time.Duration.between(wait.expiresAt(), now));
        return switch (execution.status()) {
            case RUNNING -> new CaseEvent.Custom("recorded-evidence-only", Map.of());
            case WAITING_BROWSER -> new CaseEvent.TranscriptReady();
            case WAITING_INBOUND -> new CaseEvent.InboundUnavailable("interaction-cannot-provide-required-evidence");
            default -> throw new IllegalArgumentException("Not an obsolete interaction-free wait");
        };
    }

    private static String required(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId is required");
        return runId;
    }

    public record Status(int eligibleCases, int readyCases, List<CaseStatus> cases) {
        public Status { cases = List.copyOf(cases); }
    }

    public record CaseStatus(
            String caseId,
            boolean ready,
            List<String> requiredObservations,
            List<String> completedObservations,
            Map<String, Object> details) {
        public CaseStatus {
            requiredObservations = List.copyOf(requiredObservations);
            completedObservations = List.copyOf(completedObservations);
            details = Map.copyOf(details);
        }
    }

    public record CompletedCase(String caseId, Outcome outcome) {}

    public record Evaluation(List<CompletedCase> completed, Status remaining) {
        public Evaluation { completed = List.copyOf(completed); }
    }
}
