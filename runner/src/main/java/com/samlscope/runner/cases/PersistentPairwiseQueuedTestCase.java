package com.samlscope.runner.cases;

import java.util.Optional;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Only the full native two-peer proof may finish this never-dispatched browser case. */
final class PersistentPairwiseQueuedTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    private final IdpExecutableBrowserFixtureScenarioTestCase delegate;

    PersistentPairwiseQueuedTestCase(IdpExecutableBrowserFixtureScenarioTestCase delegate) {
        this.delegate = java.util.Objects.requireNonNull(delegate);
        if (!PersistentPairwiseNameIdEvidence.CASE.equals(delegate.id()))
            throw new IllegalArgumentException("Queued native completion is only for SSO05.a3");
    }

    @Override public String id() { return delegate.id(); }
    @Override public TargetRole role() { return delegate.role(); }
    @Override public CaseStep start(CaseContext context) { return delegate.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return delegate.resume(context, state, event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) { return delegate.evidenceStatus(context); }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) {
        // Never invoke start/resume or manufacture an outbound action for this path.
        return delegate.recordedPersistentPairwise(context).orElseGet(() -> CaseOutcome.notVerified(
                "native_pairwise_evidence_unavailable", "idp.persistent-pairwise.unproven"));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return delegate.supportsRecordedEvidenceReevaluation(previous);
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return delegate.reevaluateRecordedEvidence(context, previous);
    }
    @Override public String browserInstructionsEn() { return delegate.browserInstructionsEn(); }
    @Override public String instructionsEn(CaseState state) { return delegate.instructionsEn(state); }
}
