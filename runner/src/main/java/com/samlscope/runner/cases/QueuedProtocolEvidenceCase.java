package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.CaseOutcome;

/** Explicit opt-in to completing a never-dispatched browser case from recorded originals only. */
public interface QueuedProtocolEvidenceCase extends ProtocolEvidenceCase {
    /** Must neither create outbound actions nor start the browser scenario. */
    CaseOutcome queuedEvidenceOutcome(CaseContext context);
}
