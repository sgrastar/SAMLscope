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
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.Fixture;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Browser-assisted exact RequestedAuthnContext matrix with Transcript-only verdicts. */
public final class IdpAuthnContextScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String CASE_ID = "IIP-IDP08-a-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlRequestedAuthnContextRequestFactory requests;
    private final SamlDecryptionKeyProvider decryptionKeys;

    public IdpAuthnContextScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(configurations, new SamlRequestedAuthnContextRequestFactory(), ignored -> java.util.Optional.empty());
    }

    public IdpAuthnContextScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(configurations, new SamlRequestedAuthnContextRequestFactory(), decryptionKeys);
    }

    IdpAuthnContextScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlRequestedAuthnContextRequestFactory requests) {
        this(configurations, requests, ignored -> java.util.Optional.empty());
    }

    IdpAuthnContextScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlRequestedAuthnContextRequestFactory requests,
            SamlDecryptionKeyProvider decryptionKeys) {
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.decryptionKeys = java.util.Objects.requireNonNull(decryptionKeys, "decryptionKeys");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        var decryptionKey = decryptionKeys.keyFor(runId).orElse(null);
        return new FixtureScenarioTestCase(
                CASE_ID, TargetRole.IDP,
                List.of(
                        fixture(Fixture.BASELINE, configuration, decryptionKey),
                        fixture(Fixture.SATISFIABLE_CLASS, configuration, decryptionKey),
                        fixture(Fixture.SATISFIABLE_DECLARATION, configuration, decryptionKey),
                        fixture(Fixture.UNSATISFIABLE_CLASS, configuration, decryptionKey)),
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "authn_context_preconditions_unmet", "idp.authn-context.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.authn-context.delivery-unknown",
                        "scenario_aborted", "idp.authn-context.aborted",
                        "case.idp.authn-context.control-failed",
                        "requested_authn_context_exact_violated", "case.idp.authn-context.violated",
                        "requested_authn_context_not_conclusive", "idp.authn-context.inconclusive",
                        "case.idp.authn-context.inconclusive",
                        "idp.authn-context.satisfied", "case.idp.authn-context.satisfied"));
    }

    @Override public String id() { return CASE_ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return scenario(context.runId()).resume(context, state, event);
    }
    @Override public String browserInstructionsEn() {
        return "Perform login when requested. SAMLscope sends exact ClassRef, DeclRef, and unsatisfiable "
                + "RequestedAuthnContext fixtures and judges only correlated SAML Responses; do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private ScenarioFixture fixture(Fixture fixture, IdpErrorProbeConfiguration configuration,
            java.security.PrivateKey decryptionKey) {
        return new AuthnContextFixture(fixture, configuration, requests, decryptionKey);
    }

    private record AuthnContextFixture(
            Fixture fixture,
            IdpErrorProbeConfiguration configuration,
            SamlRequestedAuthnContextRequestFactory requests,
            java.security.PrivateKey decryptionKey) implements ScenarioFixture {
        @Override public String id() {
            return fixture.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
        }

        @Override public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var payload = requests.build(
                    fixture, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
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
                var top = ((Element) statusCodes.item(0)).getAttribute("Value");
                var success = SUCCESS.equals(top);
                if (fixture == Fixture.BASELINE) {
                    var assertions = root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                            + root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength();
                    return success && assertions > 0
                            ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                }
                // The target may encrypt the assertion to the Run key. Decrypt before judging the
                // context, otherwise an encrypted success would be reported as inconclusive.
                if (fixture == Fixture.UNSATISFIABLE_CLASS) {
                    if (!success) return RESPONDER.equals(top)
                            ? FixtureObservation.SATISFIED
                            : top.isBlank() ? FixtureObservation.NOT_VERIFIED : FixtureObservation.VIOLATED;
                    var assertion = findAssertion(root);
                    return assertion == null ? FixtureObservation.NOT_VERIFIED : FixtureObservation.VIOLATED;
                }
                if (!success) {
                    // The target may not have the advertised fixture context configured. This is
                    // a test-precondition gap, not proof that exact comparison is implemented wrong.
                    return FixtureObservation.NOT_VERIFIED;
                }
                var assertion = findAssertion(root);
                if (assertion == null) return FixtureObservation.NOT_VERIFIED;
                var expected = fixture == Fixture.SATISFIABLE_CLASS
                        ? SamlRequestedAuthnContextRequestFactory.PASSWORD_PROTECTED_TRANSPORT
                        : SamlRequestedAuthnContextRequestFactory.FIXTURE_DECLARATION;
                var localName = fixture == Fixture.SATISFIABLE_CLASS
                        ? "AuthnContextClassRef" : "AuthnContextDeclRef";
                var references = assertion.getElementsByTagNameNS(ASSERTION, localName);
                if (references.getLength() == 0) return FixtureObservation.VIOLATED;
                for (var index = 0; index < references.getLength(); index++) {
                    if (expected.equals(references.item(index).getTextContent())) {
                        return FixtureObservation.SATISFIED;
                    }
                }
                return FixtureObservation.VIOLATED;
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        /** Returns a readable Assertion (decrypting an EncryptedAssertion with the Run key) or null. */
        private Element findAssertion(Element root) {
            for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (!(node instanceof Element element) || !ASSERTION.equals(element.getNamespaceURI())) continue;
                if ("Assertion".equals(element.getLocalName())) return element;
                if ("EncryptedAssertion".equals(element.getLocalName())) {
                    if (decryptionKey == null) return null;
                    try {
                        return new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(element, decryptionKey);
                    } catch (RuntimeException unreadable) {
                        return null;
                    }
                }
            }
            return null;
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", fixture.name(), configuration.ssoEndpoint().toString(),
                    configuration.registeredAcs().toString());
        }
    }
}
