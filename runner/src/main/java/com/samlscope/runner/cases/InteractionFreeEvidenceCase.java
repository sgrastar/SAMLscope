package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;

/**
 * A recorded-evidence case with no browser or operator input to collect.
 * Missing evidence finishes NOT_VERIFIED; starting or resuming never creates outbox actions.
 * This also identifies obsolete waits that may be safely concluded without asking the user
 * to repeat an operation that cannot provide the required evidence.
 */
public interface InteractionFreeEvidenceCase extends TestCase, QueuedProtocolEvidenceCase {
    @Override
    default CaseStep start(CaseContext context) {
        return new CaseStep.Finish(queuedEvidenceOutcome(context));
    }

    @Override
    default CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return start(context);
    }
}
