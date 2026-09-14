package com.samlscope.runner;

import java.util.Optional;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;

/** Explicit opt-in to pure reconsideration after new recorded evidence; never dispatches a probe. */
public interface RecordedEvidenceReevaluation {
    boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous);
    Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous);

    static Optional<CaseOutcome> conclusiveUpdate(CaseOutcome previous, CaseOutcome next) {
        if (previous == null || previous.outcome() != Outcome.NOT_VERIFIED || next == null) return Optional.empty();
        if (next.outcome() != Outcome.SATISFIED && next.outcome() != Outcome.SATISFIED_WITH_NOTE
                && next.outcome() != Outcome.VIOLATED) return Optional.empty();
        boolean newTranscriptEvidence = next.evidence().stream().anyMatch(value ->
                "transcript".equals(value.kind()) && !previous.evidence().contains(value));
        return newTranscriptEvidence ? Optional.of(next) : Optional.empty();
    }
}
