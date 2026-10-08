package com.samlscope.runner.result;

import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.TestRun;
import com.samlscope.runner.FunctionalReleaseRegistry;
import java.util.*;

/** Pins result source provenance to the evaluated Plan's owning release, preserving Suite metadata. */
public final class ReleaseBoundResultContextProvider implements ResultContextProvider {
    private final ResultContextProvider delegate;
    private final ResultContextProvider historicalTemplate;
    private final FunctionalReleaseRegistry releases;
    public ReleaseBoundResultContextProvider(ResultContextProvider delegate, FunctionalReleaseRegistry releases) {
        this(delegate,null,releases);
    }
    public ReleaseBoundResultContextProvider(ResultContextProvider delegate,
            ResultContextProvider historicalTemplate, FunctionalReleaseRegistry releases) {
        this.delegate = Objects.requireNonNull(delegate);
        this.historicalTemplate = historicalTemplate;
        this.releases = Objects.requireNonNull(releases);
    }
    @Override public ResultDocumentContext context(TestRun run, TestPlan plan, List<CaseRun> cases, RunResult result) {
        var release = releases.require(plan.definitionIdentity());
        if (!run.planId().equals(plan.id())) throw new IllegalArgumentException("Result Plan/Run differs");
        var provider = release.kind() == com.samlscope.runner.FunctionalReleaseContext.Kind.HISTORICAL
                ? historicalTemplate : delegate;
        if (provider == null) throw new IllegalStateException("Historical result requires a catalog-independent provenance template");
        var context = provider.context(run,plan,cases,result);
        var requirements = context.requirementSpecUrls();
        var definitions = context.caseDefinitionUrls();
        var evidenceClasses = context.caseEvidenceClasses();
        if (release.sourceCommit().isPresent()) {
            var base = "https://github.com/sgrastar/SAMLscope/blob/" + release.sourceCommit().orElseThrow();
            var requirementUrls = new LinkedHashMap<String,String>();
            context.requirementSpecUrls().keySet().forEach(id -> requirementUrls.put(id,base + "/docs/04-requirement-coverage.md#" + id));
            var caseUrls = new LinkedHashMap<String,String>();
            context.caseDefinitionUrls().keySet().forEach(id -> caseUrls.put(id,base + "/tests/cases.yaml#" + id));
            requirements = Map.copyOf(requirementUrls);
            definitions = Map.copyOf(caseUrls);
            // A newer runtime campaign classifier cannot reinterpret the old release's evidence contract.
            var owningClasses = new LinkedHashMap<String,String>();
            for (var selected : release.definition().cases()) owningClasses.put(selected.id(),switch (selected.mode()) {
                case ATTESTED -> "SELF_ATTESTED";
                case AUTOMATED -> "PROTOCOL_OBSERVED";
                case BROWSER, CONFIG -> "OPERATOR_ASSISTED";
            });
            evidenceClasses = Map.copyOf(owningClasses);
        }
        return new ResultDocumentContext(context.suite(),release.components(),context.profileSpec(),
                context.target(),requirements,definitions,evidenceClasses,context.advisories());
    }
}
