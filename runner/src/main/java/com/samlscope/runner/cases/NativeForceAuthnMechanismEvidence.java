package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;
import java.util.Optional;

/** Original-backed internal evidence; external reauthentication is insufficient. */
interface NativeForceAuthnMechanismEvidence {
    boolean exists(String runId);
    Optional<CaseOutcome> read(CaseContext context);
    NativeForceAuthnMechanismEvidence withKeys(SamlDecryptionKeyProvider provider);
}
