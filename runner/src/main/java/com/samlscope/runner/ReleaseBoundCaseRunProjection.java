package com.samlscope.runner;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import java.util.*;
import java.util.function.Function;

/** Stored outcomes use their owning signed case catalog, including approved IDs retired by a newer release. */
public final class ReleaseBoundCaseRunProjection implements CaseRunProvider {
    private final CaseExecutionRepository repository;
    private final Function<String,FunctionalReleaseContext> releases;
    public ReleaseBoundCaseRunProjection(CaseExecutionRepository repository,Function<String,FunctionalReleaseContext> releases) {
        this.repository=Objects.requireNonNull(repository);this.releases=Objects.requireNonNull(releases);
    }
    @Override public List<CaseRun> completed(String runId) { return project(runId,releases.apply(runId),repository.list(runId)); }
    public static List<CaseRun> project(String runId,FunctionalReleaseContext release,Collection<CaseExecution> executions) {
        if(runId==null || runId.isBlank())throw new IllegalArgumentException("Run identity is required");
        Objects.requireNonNull(release);var seen=new HashSet<String>();var cases=new ArrayList<CaseRun>();
        for(var execution:List.copyOf(executions)) {
            if(!runId.equals(execution.runId())||!seen.add(execution.caseId()))throw new IllegalArgumentException("Foreign or duplicate stored case");
            if(com.samlscope.runner.outbox.EcpProbeService.isKnownNonEvaluativeFixture(execution.caseId()))continue;
            if(!release.definition().caseIds().contains(execution.caseId()))throw new IllegalArgumentException("Stored case is outside its exact approved definition");
            var owner=release.cases().require(execution.caseId());
            var outcome=switch(execution.status()) {
                case FINISHED -> execution.outcome();
                case RUNNING -> CaseOutcome.notVerified("case_in_progress","case.in-progress");
                case WAITING_BROWSER, WAITING_CONFIG, WAITING_ATTESTATION, WAITING_INBOUND -> CaseOutcome.notVerified("pending_interaction","case.pending-interaction");
            };
            cases.add(CaseRun.completed(owner.id(),owner.obligation(),outcome));
        }
        return List.copyOf(cases);
    }
}
