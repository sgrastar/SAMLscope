package com.samlscope.runner;

import com.samlscope.core.caseexec.CaseExecution;

/**
 * Identifies a case that first tries Suite-observed evidence and retains an approved manual
 * fallback when that evidence is inconclusive.
 *
 * <p>This distinction matters to result provenance. External evidence and a manual answer remain
 * separate evidence classes; an automatic fast path must not relabel a self-attested answer as
 * externally verified.</p>
 */
public interface FallbackEvidenceCase {
    boolean resolvedFromExternalEvidence(CaseExecution execution);
}
