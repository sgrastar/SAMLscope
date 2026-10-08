package com.samlscope.runner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.evaluation.ApplicabilityEvaluation;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.profile.FunctionalCaseDefinition;

/** Starts one approved implementation slice without bypassing profile or applicability scope. */
public final class ApprovedCaseStarter {
    private final Map<String, CoverageCatalog.Obligation> obligations;
    private final CaseDefinitionCatalog definitions;
    private final TestCaseRegistry registry;
    private final CaseExecutionService executions;
    private final ApplicabilityProvider applicability;
    private final java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions;
    private final java.util.function.Function<TestPlan,FunctionalReleaseContext> releaseContexts;

    public ApprovedCaseStarter(
            CoverageCatalog coverage,
            CaseDefinitionCatalog definitions,
            TestCaseRegistry registry,
            CaseExecutionService executions,
            ApplicabilityProvider applicability,
            java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions) {
        this(coverage, definitions, registry, executions, applicability, profileDefinitions, null);
    }

    public ApprovedCaseStarter(CoverageCatalog coverage, CaseDefinitionCatalog definitions,
            TestCaseRegistry registry, CaseExecutionService executions, ApplicabilityProvider applicability,
            java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions,
            java.util.function.Function<TestPlan,FunctionalReleaseContext> releaseContexts) {
        this.releaseContexts = releaseContexts;
        this.obligations = Objects.requireNonNull(coverage, "coverage").byKey();
        this.definitions = Objects.requireNonNull(definitions, "definitions");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.executions = Objects.requireNonNull(executions, "executions");
        this.applicability = Objects.requireNonNull(applicability, "applicability");
        this.profileDefinitions = Objects.requireNonNull(profileDefinitions, "profileDefinitions");
        for (var id : registry.ids()) {
            var definition = definitions.require(id);
            var obligation = obligations.get(definition.obligation());
            if (obligation == null) {
                throw new IllegalArgumentException("Case references an unknown obligation: " + id);
            }
            if (obligation.testability().name() != definition.mode().name()) {
                throw new IllegalArgumentException("Case mode differs from obligation testability: " + id);
            }
        }
    }

    public List<CaseExecution> startApplicable(
            TestRun run, TestPlan plan, CaseContext context) {
        Objects.requireNonNull(run, "run");
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(context, "context");
        if (!run.id().equals(context.runId()) || !run.planId().equals(plan.id())) {
            throw new IllegalArgumentException("Run, plan, and case context do not belong together");
        }
        if (plan.profile().role() != context.targetRole()) {
            throw new IllegalArgumentException("Plan profile belongs to another target role");
        }
        var applicable = applicableByObligation(run, plan);
        var release = releaseContexts == null ? null : releaseContexts.apply(plan);
        var ownerDefinitions = release == null ? definitions : release.cases();
        var ownerObligations = release == null ? obligations : release.coverage().byKey();
        var selectedCases = release == null ? profileDefinitions.apply(plan).caseIds() : release.definition().caseIds();
        var started = new ArrayList<CaseExecution>();
        for (var testCase : registry.forRole(context.targetRole())) {
            if (!selectedCases.contains(testCase.id())) continue;
            var definition = ownerDefinitions.require(testCase.id());
            var obligation = ownerObligations.get(definition.obligation());
            if (obligation.condition() != null
                    && applicable.getOrDefault(obligation.key(), ApplicabilityEvaluation.EffectiveResult.UNKNOWN)
                            != ApplicabilityEvaluation.EffectiveResult.TRUE) {
                continue;
            }
            started.add(testCase instanceof BrowserFrontChannelScenario
                    ? executions.enqueueFrontChannel(run.id(), testCase, context)
                    : executions.start(run.id(), testCase, context));
        }
        return List.copyOf(started);
    }

    private Map<String, ApplicabilityEvaluation.EffectiveResult> applicableByObligation(
            TestRun run, TestPlan plan) {
        var result = new LinkedHashMap<String, ApplicabilityEvaluation.EffectiveResult>();
        for (var evaluation : applicability.evaluations(run, plan)) {
            if (result.putIfAbsent(evaluation.obligationKey(), evaluation.effectiveResult()) != null) {
                throw new IllegalStateException(
                        "Multiple applicability evaluations for " + evaluation.obligationKey());
            }
        }
        return Map.copyOf(result);
    }
}
