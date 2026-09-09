package com.samlscope.runner;

import java.util.Objects;
import java.util.List;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.Evaluator;
import com.samlscope.core.evaluation.RunResult;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalCaseDefinition;

/** The runtime's single entry point into the canonical Evaluator. */
public final class RunEvaluationService {
    private final CoverageCatalog catalog;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final CaseRunProvider caseRuns;
    private final ApplicabilityProvider applicability;
    private final SuiteIncidentProvider incidents;
    private final java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions;

    public RunEvaluationService(
            CoverageCatalog catalog,
            PlanRepository plans,
            RunRepository runs,
            CaseRunProvider caseRuns,
            ApplicabilityProvider applicability,
            SuiteIncidentProvider incidents,
            java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions) {
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.plans = Objects.requireNonNull(plans, "plans");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.caseRuns = Objects.requireNonNull(caseRuns, "caseRuns");
        this.applicability = Objects.requireNonNull(applicability, "applicability");
        this.incidents = Objects.requireNonNull(incidents, "incidents");
        this.profileDefinitions = Objects.requireNonNull(profileDefinitions, "profileDefinitions");
    }

    public RunResult evaluate(String runId) {
        return snapshot(runId).result();
    }

    /** Captures the exact plan, run and case-side inputs used for one public determination. */
    public EvaluatedRun snapshot(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId must not be blank");
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        var definition = profileDefinitions.apply(plan);
        var completedCases = caseRuns.completed(runId);
        var evaluation = Evaluator.evaluateFunctionalCaseSnapshot(
                definition, catalog,
                applicability.evaluations(run, plan),
                completedCases,
                incidents.incidents(runId));
        return new EvaluatedRun(plan, run, definition, evaluation.cases(), evaluation.result());
    }

    public record EvaluatedRun(
            com.samlscope.core.plan.TestPlan plan,
            com.samlscope.core.run.TestRun run,
            FunctionalCaseDefinition definition,
            List<CaseRun> cases,
            RunResult result) {
        public EvaluatedRun {
            Objects.requireNonNull(plan, "plan");
            Objects.requireNonNull(run, "run");
            Objects.requireNonNull(definition, "definition");
            cases = List.copyOf(cases);
            Objects.requireNonNull(result, "result");
        }
    }
}
