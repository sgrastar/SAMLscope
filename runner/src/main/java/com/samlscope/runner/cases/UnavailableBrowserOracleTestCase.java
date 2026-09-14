package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.plan.TargetRole;

/** No completion action can supply an absent oracle; do not ask the operator to perform one. */
public record UnavailableBrowserOracleTestCase(String id, TargetRole role) implements TestCase {
    public UnavailableBrowserOracleTestCase {
        java.util.Objects.requireNonNull(id);
        java.util.Objects.requireNonNull(role);
    }
    @Override public CaseStep start(CaseContext context) {
        return new CaseStep.Finish(CaseOutcome.notVerified(
                "automatic_oracle_unavailable", "browser.oracle-unavailable"));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        throw new IllegalStateException("An unavailable oracle cannot be completed by interaction");
    }
}
