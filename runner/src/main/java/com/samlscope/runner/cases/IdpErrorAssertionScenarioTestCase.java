package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.List;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.scenario.FixtureObservation;
import com.samlscope.runner.scenario.FixtureScenarioTestCase;
import com.samlscope.runner.scenario.ScenarioFixture;
import com.samlscope.runner.scenario.TargetHttpObservation;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Browser-assisted error fixtures proving that error Responses contain no assertions. */
public final class IdpErrorAssertionScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String SUBJECT_ERROR_CASE = "IIP-SSO01-d-idp-01";
    public static final String ERROR_ASSERTION_CASE = "IIP-SSO01-f-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final List<Probe> ERROR_ASSERTION_PROBES = List.of(
            Probe.BASELINE_SUCCESS,
            Probe.UNKNOWN_NAMEID_FORMAT,
            Probe.UNRECOGNIZED_SUBJECT,
            Probe.PASSIVE_WITHOUT_SESSION);
    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlErrorProbeRequestFactory requests;

    public IdpErrorAssertionScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(ERROR_ASSERTION_CASE, configurations, new SamlErrorProbeRequestFactory());
    }

    public IdpErrorAssertionScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(id, configurations, new SamlErrorProbeRequestFactory());
    }

    IdpErrorAssertionScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests) {
        if (!List.of(SUBJECT_ERROR_CASE, ERROR_ASSERTION_CASE).contains(id)) {
            throw new IllegalArgumentException("Unsupported error-assertion case: " + id);
        }
        this.id = id;
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        var probes = SUBJECT_ERROR_CASE.equals(id)
                ? List.of(Probe.BASELINE_SUCCESS, Probe.UNRECOGNIZED_SUBJECT)
                : ERROR_ASSERTION_PROBES;
        var fixtures = probes.stream().<ScenarioFixture>map(
                probe -> new ErrorAssertionFixture(id, probe, configuration, requests)).toList();
        return new FixtureScenarioTestCase(
                id, TargetRole.IDP, fixtures,
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "error_assertion_preconditions_unmet", "idp.error-assertion.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.error-assertion.delivery-unknown",
                        "scenario_aborted", "idp.error-assertion.aborted",
                        "case.idp.error-assertion.control-failed",
                        "error_response_contains_assertion", "case.idp.error-assertion.violated",
                        "error_assertion_not_conclusive", "idp.error-assertion.inconclusive",
                        "case.idp.error-assertion.inconclusive",
                        "idp.error-assertion.satisfied", "case.idp.error-assertion.satisfied"));
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public boolean requiresFreshSession(CaseState state) {
        return "passive-without-session".equals(state.data().get("fixture_id"));
    }
    @Override public boolean plansFreshSessionBoundary() { return ERROR_ASSERTION_CASE.equals(id); }
    @Override public int plannedDeliberateActions() {
        return ERROR_ASSERTION_CASE.equals(id) ? 1 : 0;
    }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return scenario(context.runId()).resume(context, state, event);
    }
    @Override public String browserInstructionsEn() {
        return "Start the error-response scenario and log in only for the positive control. SAMLscope sends the "
                + "approved abnormal requests and checks Status plus Assertion/EncryptedAssertion automatically.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private record ErrorAssertionFixture(
            String caseId,
            Probe probe,
            IdpErrorProbeConfiguration configuration,
            SamlErrorProbeRequestFactory requests) implements ScenarioFixture {
        @Override public String id() {
            return probe.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
        }

        @Override public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var payload = requests.build(
                    probe, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    configuration.registeredAcs(), context.clock().instant());
            return new Prepared(new OutboundAction(
                    actionId, OutboundKind.AUTHN_REQUEST, payload,
                    configuration.ssoEndpoint(), false), requestId);
        }

        @Override public FixtureObservation observe(String requestId, byte[] responseXml) {
            try {
                var document = SecureXml.parse(responseXml);
                var root = document.getDocumentElement();
                if (!PROTOCOL.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName())
                        || !requestId.equals(root.getAttribute("InResponseTo"))) {
                    return FixtureObservation.NOT_VERIFIED;
                }
                var statusCodes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (statusCodes.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var success = SUCCESS.equals(((Element) statusCodes.item(0)).getAttribute("Value"));
                var assertions = root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                        + root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength();
                if (probe == Probe.BASELINE_SUCCESS) {
                    return success && assertions > 0
                            ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                }
                if (success) {
                    // SSO01.d requires an error Status for the deterministic nonexistent
                    // principal. A correlated Success is therefore a direct violation whether
                    // or not the product also emits an Assertion. Keep SSO01.f unchanged: its
                    // separate oracle concerns assertion absence in an error Response.
                    return SUBJECT_ERROR_CASE.equals(caseId) && probe == Probe.UNRECOGNIZED_SUBJECT
                            ? FixtureObservation.VIOLATED : FixtureObservation.NOT_VERIFIED;
                }
                return assertions == 0 ? FixtureObservation.SATISFIED : FixtureObservation.VIOLATED;
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        @Override public FixtureObservation observeBrowser(
                String requestId, int httpStatus, String url, String body) {
            if (!TargetHttpObservation.isSameOriginError(
                    configuration.ssoEndpoint(), httpStatus, url)) {
                return FixtureObservation.NOT_VERIFIED;
            }
            if (probe == Probe.BASELINE_SUCCESS) return FixtureObservation.CONTROL_FAILED;
            // SSO01.d requires an error SAML Status for the unknown subject. A target-local HTTP
            // error proves it was not returned. SSO01.f remains inconclusive because absence of a
            // Response cannot prove whether that Response would have contained an Assertion.
            return SUBJECT_ERROR_CASE.equals(caseId) && probe == Probe.UNRECOGNIZED_SUBJECT
                    ? FixtureObservation.VIOLATED : FixtureObservation.NOT_VERIFIED;
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", caseId, probe.name(), configuration.ssoEndpoint().toString(),
                    configuration.suiteIssuer(), configuration.registeredAcs().toString(),
                    "recorder-terminal-http-v1");
        }
    }
}
