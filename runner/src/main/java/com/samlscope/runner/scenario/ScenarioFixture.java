package com.samlscope.runner.scenario;

import java.time.Duration;
import java.util.Objects;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.OutboundAction;

/** One executable fixture in a persisted, ordered Runner scenario. */
public interface ScenarioFixture {
    String id();

    Prepared prepare(CaseContext context, String actionId);

    FixtureObservation observe(String expectedResponseCorrelation, byte[] decodedMessage);

    /**
     * Interprets a Recorder-backed terminal browser landing for the current action. The default
     * is deliberately inconclusive; protocol fixtures must opt in with fixture-specific rules.
     */
    default FixtureObservation observeBrowser(
            String expectedResponseCorrelation, int httpStatus, String url, String body) {
        return FixtureObservation.NOT_VERIFIED;
    }

    /**
     * Interprets an explicit operator report that browser navigation terminated without a SAML
     * callback. Negative protocol fixtures may treat that as evidence that the request was
     * discarded; positive controls should return {@link FixtureObservation#CONTROL_FAILED}.
     * Delivery timeouts and generic aborts do not use this hook.
     */
    default FixtureObservation observeUnavailable(String reason) {
        return FixtureObservation.NOT_VERIFIED;
    }

    default String inboundType() { return "saml-response"; }

    default Duration timeout() { return Duration.ofMinutes(5); }

    /** Stable, non-secret material that invalidates a persisted scenario when fixture semantics change. */
    String definitionKey();

    record Prepared(OutboundAction action, String expectedResponseCorrelation) {
        public Prepared {
            Objects.requireNonNull(action, "action");
            if (expectedResponseCorrelation == null || expectedResponseCorrelation.isBlank()) {
                throw new IllegalArgumentException("expectedResponseCorrelation is required");
            }
        }
    }
}
