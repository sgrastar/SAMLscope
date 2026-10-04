package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import java.util.Optional;

/** A product adapter owns original-backed preparation and observation, never HTTP sending. */
public interface RegisteredSignerNativeEvidence {
    boolean exists(String run);
    boolean hasFinalProof(String run);
    Optional<RegisteredSignerProbeInputs> probeInputs(CaseContext context);
    Optional<CaseOutcome> evaluate(CaseContext context);
    CaseOutcome pending(String run,String stage);
    String adapter();
    String evidenceKind();
}
