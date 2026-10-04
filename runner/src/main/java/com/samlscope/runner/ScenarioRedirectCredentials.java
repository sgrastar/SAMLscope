package com.samlscope.runner;

import com.samlscope.core.caseexec.CaseState;
import com.samlscope.saml.crypto.PlanCredentials;
import java.util.Optional;

/** Run-scoped credentials for a scenario whose accepted metadata uses a dedicated fixture key. */
public interface ScenarioRedirectCredentials {
    Optional<PlanCredentials> redirectCredentials(String runId, CaseState state);
}
