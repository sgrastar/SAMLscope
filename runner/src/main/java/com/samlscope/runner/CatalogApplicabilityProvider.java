package com.samlscope.runner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.evaluation.ApplicabilityEngine;
import com.samlscope.core.evaluation.ApplicabilityEvaluation;
import com.samlscope.core.evaluation.ApplicabilityInput;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.evaluation.PredicateCatalog;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.profile.FunctionalCaseDefinition;

/** Evaluates every selected conditional obligation using its approved predicate definition. */
public final class CatalogApplicabilityProvider implements ApplicabilityProvider {
    private final CoverageCatalog coverage;
    private final Map<String, PredicateCatalog.Definition> predicates;
    private final ApplicabilityInputProvider inputs;
    private final java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions;
    private final java.util.function.Function<TestPlan,FunctionalReleaseContext> releaseContexts;

    public CatalogApplicabilityProvider(
            CoverageCatalog coverage,
            PredicateCatalog predicates,
            ApplicabilityInputProvider inputs,
            java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions) {
        this(coverage, predicates, inputs, profileDefinitions, null);
    }

    public CatalogApplicabilityProvider(CoverageCatalog coverage, PredicateCatalog predicates,
            ApplicabilityInputProvider inputs,
            java.util.function.Function<TestPlan,FunctionalCaseDefinition> profileDefinitions,
            java.util.function.Function<TestPlan,FunctionalReleaseContext> releaseContexts) {
        this.releaseContexts = releaseContexts;
        this.coverage = Objects.requireNonNull(coverage, "coverage");
        this.predicates = Objects.requireNonNull(predicates, "predicates").byKey();
        this.inputs = Objects.requireNonNull(inputs, "inputs");
        this.profileDefinitions = Objects.requireNonNull(profileDefinitions, "profileDefinitions");
        for (var obligation : coverage.obligations()) {
            if (obligation.condition() != null && !this.predicates.containsKey(obligation.condition())) {
                throw new IllegalArgumentException(
                        "Obligation references an unknown predicate: " + obligation.key());
            }
        }
    }

    @Override
    public java.util.List<ApplicabilityEvaluation> evaluations(TestRun run, TestPlan plan) {
        Objects.requireNonNull(run, "run");
        Objects.requireNonNull(plan, "plan");
        var predicateInputs = new LinkedHashMap<String, ApplicabilityInput>();
        var result = new ArrayList<ApplicabilityEvaluation>();
        var release = releaseContexts == null ? null : releaseContexts.apply(plan);
        var ownerCoverage = release == null ? coverage : release.coverage();
        var ownerPredicates = release == null ? predicates : release.predicates().byKey();
        var definition = release == null ? profileDefinitions.apply(plan) : release.definition();
        var selected = definition.selectedCoverage(ownerCoverage).byKey().keySet();
        for (var obligation : ownerCoverage.obligations()) {
            if (!selected.contains(obligation.key()) || obligation.condition() == null) continue;
            var predicate = ownerPredicates.get(obligation.condition());
            var input = predicateInputs.computeIfAbsent(predicate.key(), ignored ->
                    Objects.requireNonNull(inputs.input(predicate, run, plan),
                            "Applicability input provider returned null for " + predicate.key()));
            result.add(ApplicabilityEngine.evaluate(
                    obligation.key(), predicate.key(), predicate.kind(), input));
        }
        return java.util.List.copyOf(result);
    }
}
