package com.samlscope.runner;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseIds;
import com.samlscope.core.evaluation.CaseRun;

/** Projects persisted executions into the Evaluator's case-side input. */
public final class CaseRunProjection implements CaseRunProvider {
    private final CaseExecutionRepository repository;
    private final java.util.Set<String> approvedCaseIds;

    public CaseRunProjection(CaseExecutionRepository repository, TestCaseRegistry registry) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.approvedCaseIds = Objects.requireNonNull(registry, "registry").ids();
    }

    public CaseRunProjection(CaseExecutionRepository repository, java.util.Set<String> approvedCaseIds) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.approvedCaseIds = java.util.Set.copyOf(approvedCaseIds);
    }

    @Override
    public List<CaseRun> completed(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId must not be blank");
        var projected = new ArrayList<CaseRun>();
        for (var execution : repository.list(runId)) {
            // Known transport fixtures supply evidence but never enter verdict arithmetic.
            if (com.samlscope.runner.outbox.EcpProbeService.requiredFixtureIds().contains(execution.caseId())) continue;
            if (!approvedCaseIds.contains(execution.caseId())) {
                throw new IllegalArgumentException("Unknown approved case ID: " + execution.caseId());
            }
            var outcome = switch (execution.status()) {
                case FINISHED -> {
                    if (execution.outcome() == null) {
                        throw new IllegalStateException("Finished case has no outcome: " + execution.caseId());
                    }
                    yield execution.outcome();
                }
                case RUNNING -> com.samlscope.core.evaluation.CaseOutcome.notVerified(
                        "case_in_progress", "case.in-progress");
                case WAITING_BROWSER, WAITING_CONFIG, WAITING_ATTESTATION, WAITING_INBOUND ->
                        com.samlscope.core.evaluation.CaseOutcome.notVerified(
                                "pending_interaction", "case.pending-interaction");
            };
            projected.add(CaseRun.completed(
                    execution.caseId(), CaseIds.obligationKey(execution.caseId()), outcome));
        }
        return List.copyOf(projected);
    }
}
