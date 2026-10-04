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

/** Browser-assisted major-version rejection scenario; correlated SAML Responses are the oracle. */
public final class IdpVersionScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String CASE_ID = "IIP-SSO01-em-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlErrorProbeRequestFactory requests;

    public IdpVersionScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(configurations, new SamlErrorProbeRequestFactory());
    }

    IdpVersionScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests) {
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        return new FixtureScenarioTestCase(
                CASE_ID, TargetRole.IDP,
                List.of(
                        fixture(Probe.BASELINE_SUCCESS, true, configuration),
                        fixture(Probe.VERSION_1_1, false, configuration),
                        fixture(Probe.VERSION_3_0, false, configuration)),
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "version_preconditions_unmet", "idp.version.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.version.delivery-unknown",
                        "scenario_aborted", "idp.version.aborted",
                        "case.idp.version.control-failed",
                        "unsupported_major_version_accepted", "case.idp.version.violated",
                        "version_rejection_not_conclusive", "idp.version.inconclusive",
                        "case.idp.version.inconclusive",
                        "idp.version.satisfied", "case.idp.version.satisfied"));
    }

    @Override public String id() { return CASE_ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return scenario(context.runId()).resume(context, state, event);
    }
    @Override public String browserInstructionsEn() {
        return "Log in for the SAML 2.0 control. SAMLscope then sends unsupported major-version requests "
                + "and judges any correlated SAML Responses automatically; do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private ScenarioFixture fixture(
            Probe probe, boolean control, IdpErrorProbeConfiguration configuration) {
        return new VersionFixture(probe, control, configuration, requests);
    }

    private record VersionFixture(
            Probe probe,
            boolean control,
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
                var root = SecureXml.parse(responseXml).getDocumentElement();
                if (!PROTOCOL.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName())
                        || !requestId.equals(root.getAttribute("InResponseTo"))) {
                    return FixtureObservation.NOT_VERIFIED;
                }
                var statusCodes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (statusCodes.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var success = SUCCESS.equals(((Element) statusCodes.item(0)).getAttribute("Value"));
                if (!control) return success ? FixtureObservation.VIOLATED : FixtureObservation.SATISFIED;
                var assertions = root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                        + root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength();
                return success && assertions > 0
                        ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
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
            // A local HTTP error proves rejection for an unsupported version. The SAML 2.0
            // control still requires a correlated Success Response and cannot pass this way.
            return control ? FixtureObservation.CONTROL_FAILED : FixtureObservation.SATISFIED;
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", probe.name(), configuration.ssoEndpoint().toString(),
                    configuration.registeredAcs().toString(), "recorder-terminal-http-v1");
        }
    }
}
