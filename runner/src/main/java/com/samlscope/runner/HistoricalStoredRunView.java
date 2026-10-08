package com.samlscope.runner;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.EvidenceRef;
import java.util.*;

/** Read-only physical slots; no current case lookup, outcome conversion, dispatch or inferred denominator. */
public record HistoricalStoredRunView(String runId, List<Slot> slots) {
    public record Slot(String caseId, String status, String storedOutcome, List<EvidenceRef> evidence) {
        public Slot { evidence = List.copyOf(evidence); }
    }
    public HistoricalStoredRunView { slots = List.copyOf(slots); }
    public static HistoricalStoredRunView from(String runId, Collection<CaseExecution> executions) {
        if (runId == null || !runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))
            throw new IllegalArgumentException("Historical stored Run identity invalid");
        var ids = new HashSet<String>(); var slots = new ArrayList<Slot>();
        for (var execution : List.copyOf(executions)) {
            if (!runId.equals(execution.runId()) || !ids.add(execution.caseId()))
                throw new IllegalArgumentException("Duplicate or foreign historical stored slot");
            var outcome = execution.outcome();
            slots.add(new Slot(execution.caseId(),execution.status().name(),
                    outcome == null ? null : outcome.outcome().name(),outcome == null ? List.of() : outcome.evidence()));
        }
        slots.sort(Comparator.comparing(Slot::caseId));
        return new HistoricalStoredRunView(runId,slots);
    }
    public ActiveProbeCoordinator.Status activeStatus(String planId, String instructions) {
        var state = slots.isEmpty() ? ActiveProbeCoordinator.State.NOT_STARTED
                : slots.stream().allMatch(slot -> "FINISHED".equals(slot.status()))
                    ? ActiveProbeCoordinator.State.FINISHED : ActiveProbeCoordinator.State.UNAVAILABLE;
        return new ActiveProbeCoordinator.Status(planId,state,null,null,false,null,null,instructions,false);
    }
}
