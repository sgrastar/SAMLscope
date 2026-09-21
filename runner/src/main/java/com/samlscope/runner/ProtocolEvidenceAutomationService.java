package com.samlscope.runner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

/** Advances only cases that can already derive their outcome from recorded protocol evidence. */
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
        var cases = new ArrayList<CaseStatus>();
        for (var execution : executions.list(runId)) {
            if (execution.status() != CaseExecutionStatus.WAITING_CONFIG
                    && execution.status() != CaseExecutionStatus.WAITING_BROWSER
                    && execution.status() != CaseExecutionStatus.FINISHED
                    && !CaseExecutionService.isQueuedFrontChannel(execution)) continue;
            var testCase = execution.status() == CaseExecutionStatus.FINISHED || CaseExecutionService.isQueuedFrontChannel(execution)
                    ? registry.find(execution.caseId()).orElse(null) : registry.require(execution.caseId());
            if (testCase == null) continue;
            boolean queued = CaseExecutionService.isQueuedFrontChannel(execution)
                    && testCase instanceof com.samlscope.runner.cases.QueuedProtocolEvidenceCase;
            boolean reconsider = execution.status() == CaseExecutionStatus.FINISHED
                    && testCase instanceof RecordedEvidenceReevaluation observer
                    && observer.supportsRecordedEvidenceReevaluation(execution.outcome());
            if (execution.status() != CaseExecutionStatus.WAITING_CONFIG
                    && execution.status() != CaseExecutionStatus.WAITING_BROWSER && !reconsider && !queued) continue;
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
            if (!candidate.ready() && !attemptsConfirmed) continue;
            var testCase = registry.require(candidate.caseId());
            var beforeExecution = executions.find(runId, candidate.caseId()).orElseThrow();
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
