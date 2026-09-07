package com.samlscope.runner.cases;

import java.util.List;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.scenario.FixtureObservation;
import com.samlscope.runner.scenario.FixtureScenarioTestCase;
import com.samlscope.runner.scenario.ScenarioFixture;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** The approved IdP error-response scenario, executed by the generic fixture scenario engine. */
public final class IdpErrorResponseTestCase implements TestCase, BrowserFrontChannelScenario {
    public static final String CASE_ID = "IIP-IDP05-a-idp-01";
    public static final String PASSIVE_FIXTURE_ID = "passive-without-session";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    private static final List<Probe> PROBES = List.of(
            Probe.PASSIVE_WITHOUT_SESSION,
            Probe.BASELINE_SUCCESS,
            Probe.UNKNOWN_NAMEID_FORMAT,
            Probe.UNSATISFIABLE_AUTHN_CONTEXT);
    private final FixtureScenarioTestCase scenario;

    public IdpErrorResponseTestCase(IdpErrorProbeConfiguration configuration) {
        this(configuration, new SamlErrorProbeRequestFactory());
    }

    IdpErrorResponseTestCase(
            IdpErrorProbeConfiguration configuration, SamlErrorProbeRequestFactory requests) {
        java.util.Objects.requireNonNull(configuration, "configuration");
        java.util.Objects.requireNonNull(requests, "requests");
        var fixtures = PROBES.stream()
                .<ScenarioFixture>map(probe -> new ErrorProbeFixture(probe, configuration, requests))
                .toList();
        scenario = new FixtureScenarioTestCase(
                CASE_ID,
                TargetRole.IDP,
                fixtures,
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "error_response_preconditions_unmet", "idp.error-response.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.error-response.delivery-unknown",
                        "probe_aborted", "idp.error-response.aborted",
                        "case.idp.error-response.control-failed",
                        "idp.error-response.violated", "case.idp.error-response.violated",
                        "error_response_not_conclusive", "idp.error-response.inconclusive",
                        "case.idp.error-response.inconclusive",
                        "idp.error-response.satisfied", "case.idp.error-response.satisfied"));
    }

    @Override public String id() { return scenario.id(); }
    @Override public TargetRole role() { return scenario.role(); }
    @Override public boolean requiresFreshSession(CaseState state) {
        return PASSIVE_FIXTURE_ID.equals(state.data().get("fixture_id"));
    }
    @Override public boolean plansFreshSessionBoundary() { return true; }
    @Override public int plannedDeliberateActions() { return 1; }
    @Override public String instructionsEn(CaseState state) {
        return "Run the positive control and approved abnormal AuthnRequest fixtures. SAMLscope judges only correlated SAML Responses.";
    }
    @Override public CaseStep start(CaseContext context) { return scenario.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return scenario.resume(context, state, event);
    }

    private static final class ErrorProbeFixture implements ScenarioFixture {
        private final Probe probe;
        private final IdpErrorProbeConfiguration configuration;
        private final SamlErrorProbeRequestFactory requests;

        private ErrorProbeFixture(
                Probe probe,
                IdpErrorProbeConfiguration configuration,
                SamlErrorProbeRequestFactory requests) {
            this.probe = probe;
            this.configuration = configuration;
            this.requests = requests;
        }

        @Override
        public String id() {
            return probe.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
        }

        @Override
        public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var payload = requests.build(
                    probe, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    configuration.registeredAcs(), context.clock().instant());
            return new Prepared(
                    new OutboundAction(
                            actionId, OutboundKind.AUTHN_REQUEST, payload,
                            configuration.ssoEndpoint(), false),
                    requestId);
        }

        @Override
        public FixtureObservation observe(String requestId, byte[] responseXml) {
            try {
                var document = SecureXml.parse(responseXml);
                var root = document.getDocumentElement();
                if (!PROTOCOL.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName())
                        || !requestId.equals(root.getAttribute("InResponseTo"))) {
                    return FixtureObservation.NOT_VERIFIED;
                }
                var statusCodes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (statusCodes.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var topLevel = ((Element) statusCodes.item(0)).getAttribute("Value");
                if (probe == Probe.BASELINE_SUCCESS) {
                    if (!SUCCESS.equals(topLevel)) return FixtureObservation.CONTROL_FAILED;
                    var assertions = root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength();
                    var encryptedAssertions = root.getElementsByTagNameNS(
                            ASSERTION, "EncryptedAssertion").getLength();
                    return assertions + encryptedAssertions > 0
                            ? FixtureObservation.SATISFIED
                            : FixtureObservation.CONTROL_FAILED;
                }
                if (probe == Probe.UNSATISFIABLE_AUTHN_CONTEXT) {
                    if (RESPONDER.equals(topLevel)) return FixtureObservation.SATISFIED;
                    if (SUCCESS.equals(topLevel)) {
                        // This observer receives the wire XML, not decrypted assertions. The
                        // requested context may be inside ciphertext, so Success alone cannot
                        // establish that the target failed to satisfy the request.
                        if (root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength() > 0) {
                            return FixtureObservation.NOT_VERIFIED;
                        }
                        var classRefs = root.getElementsByTagNameNS(ASSERTION, "AuthnContextClassRef");
                        if (classRefs.getLength() > 0 && requests.unavailableAuthnContext(requestId)
                                .equals(classRefs.item(0).getTextContent())) {
                            return FixtureObservation.NOT_VERIFIED;
                        }
                    }
                    return FixtureObservation.VIOLATED;
                }
                return SUCCESS.equals(topLevel)
                        ? FixtureObservation.VIOLATED
                        : FixtureObservation.SATISFIED;
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        @Override public java.time.Duration timeout() { return configuration.responseTimeout(); }

        @Override
        public String definitionKey() {
            return String.join("|", probe.name(), configuration.ssoEndpoint().toString(),
                    configuration.suiteIssuer(), configuration.registeredAcs().toString());
        }
    }
}
