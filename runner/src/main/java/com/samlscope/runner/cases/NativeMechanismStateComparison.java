package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.Outcome;

/** Compare a correlated indicator at the selected mechanism, independently of its adapter. */
final class NativeMechanismStateComparison {
    record Observation(String requestId, boolean requested, String stateRequestId,
                       Boolean accessibleIndicator, String selectedMechanism, String observedMechanism) {}
    static Outcome compare(Observation observation) {
        if (observation.requestId() == null || observation.requestId().isBlank()
                || observation.selectedMechanism() == null || observation.selectedMechanism().isBlank()
                || !observation.requestId().equals(observation.stateRequestId())
                || !observation.selectedMechanism().equals(observation.observedMechanism())) return Outcome.NOT_VERIFIED;
        return observation.accessibleIndicator() != null
                && observation.accessibleIndicator() == observation.requested() ? Outcome.SATISFIED : Outcome.VIOLATED;
    }
    private NativeMechanismStateComparison() {}
}
