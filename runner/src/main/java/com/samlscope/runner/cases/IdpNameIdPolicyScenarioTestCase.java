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
import com.samlscope.saml.crypto.SamlElementDecrypter;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory;
import com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory.Policy;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Human-assisted, transcript-judged execution of the approved NameIDPolicy cases. */
public final class IdpNameIdPolicyScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String PROCESSING_CASE = "IIP-IDP10-a-idp-01";
    public static final String REJECTION_CASE = "IIP-IDP10-b-idp-01";
    public static final String CONFORMANCE_CASE = "IIP-IDP10-d-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlNameIdPolicyRequestFactory requests;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final SamlElementDecrypter decrypter;

    public IdpNameIdPolicyScenarioTestCase(String id, IdpErrorProbeConfiguration configuration) {
        this(id, ignored -> configuration, ignored -> java.util.Optional.empty(),
                new SamlNameIdPolicyRequestFactory(), new SamlXmlDecrypter());
    }

    public IdpNameIdPolicyScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(id, configurations, ignored -> java.util.Optional.empty(),
                new SamlNameIdPolicyRequestFactory(), new SamlXmlDecrypter());
    }

    public IdpNameIdPolicyScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(id, configurations, decryptionKeys,
                new SamlNameIdPolicyRequestFactory(), new SamlXmlDecrypter());
    }

    IdpNameIdPolicyScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys,
            SamlNameIdPolicyRequestFactory requests,
            SamlElementDecrypter decrypter) {
        this.id = requireSupported(id);
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.decryptionKeys = java.util.Objects.requireNonNull(decryptionKeys, "decryptionKeys");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.decrypter = java.util.Objects.requireNonNull(decrypter, "decrypter");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(
                configurations.apply(runId), "configuration provider returned null");
        return new FixtureScenarioTestCase(
                id, TargetRole.IDP, fixtures(id, configuration, requests),
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "nameid_policy_preconditions_unmet", "idp.nameid-policy.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.nameid-policy.delivery-unknown",
                        "scenario_aborted", "idp.nameid-policy.aborted",
                        "case.idp.nameid-policy.control-failed",
                        "idp.nameid-policy.violated", "case.idp.nameid-policy.violated",
                        "nameid_policy_not_conclusive", "idp.nameid-policy.inconclusive",
                        "case.idp.nameid-policy.inconclusive",
                        "idp.nameid-policy.satisfied", "case.idp.nameid-policy.satisfied"));
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if ("await-browser".equals(state.phase())) {
            if (event instanceof CaseEvent.BrowserReturned
                    || event instanceof CaseEvent.TimedOut
                    || event instanceof CaseEvent.Aborted) {
                return new CaseStep.Finish(com.samlscope.core.evaluation.CaseOutcome.notVerified(
                        "scenario_upgrade_requires_new_run", "idp.nameid-policy.scenario-upgrade"));
            }
            throw new IllegalArgumentException("Expected a legacy browser completion event");
        }
        if (event instanceof CaseEvent.InboundMessage inbound) {
            var key = decryptionKeys.keyFor(context.runId()).orElse(null);
            if (key != null) {
                event = new CaseEvent.InboundMessage(
                        decryptAssertions(inbound.decodedSaml(), key), inbound.evidence());
            }
        }
        return scenario(context.runId()).resume(context, state, event);
    }

    @Override
    public String browserInstructionsEn() {
        return "This Run predates protocol-driven NameIDPolicy automation. Complete or skip this legacy step; "
                + "SAMLscope will record it as not verified. Start a new Run to execute the automated scenario.";
    }

    @Override
    public String instructionsEn(CaseState state) {
        return switch (id) {
            case PROCESSING_CASE -> "Run the NameIDPolicy processing matrix. Log in when the target asks; subsequent fixtures reuse the browser session.";
            case REJECTION_CASE -> "Run supported and unsupported NameIDPolicy controls. Log in when asked; SAMLscope judges only correlated SAML Responses.";
            case CONFORMANCE_CASE -> "Run transient, persistent, and SPNameQualifier requests. SAMLscope compares successful responses with each accepted policy.";
            default -> throw new IllegalStateException("Unsupported NameIDPolicy scenario");
        };
    }

    private static List<ScenarioFixture> fixtures(
            String id, IdpErrorProbeConfiguration configuration, SamlNameIdPolicyRequestFactory requests) {
        return switch (id) {
            case PROCESSING_CASE -> List.of(
                    fixture("policy-omitted", Policy.omitted(), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("allow-create-omitted", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, null, null), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("format-omitted", new Policy(true, null, null, true), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("allow-create-false", new Policy(true, null, null, false), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("allow-create-true", new Policy(true, null, null, true), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("format-unspecified", new Policy(true, SamlNameIdPolicyRequestFactory.UNSPECIFIED, null, null), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("format-persistent", new Policy(true, SamlNameIdPolicyRequestFactory.PERSISTENT, null, true), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("format-transient", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, null, null), Expectation.ANY_SAML_RESPONSE, configuration, requests),
                    fixture("sp-name-qualifier", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, configuration.suiteIssuer(), null), Expectation.ANY_SAML_RESPONSE, configuration, requests));
            case REJECTION_CASE -> List.of(
                    fixture("supported-transient", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, null, null), Expectation.SUCCESS_CONTROL, configuration, requests),
                    dynamic("unknown-sp-name-qualifier", Expectation.MATCH_POLICY_OR_ERROR,
                            "included|transient|unknown-per-request|null", configuration, requests,
                            requestId -> new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, requests.unknownSpNameQualifier(requestId), null)),
                    dynamic("unsupported-format", Expectation.ERROR,
                            "included|unknown-format-per-request|null|true", configuration, requests,
                            requestId -> new Policy(true, requests.unknownFormat(requestId), null, true)));
            case CONFORMANCE_CASE -> List.of(
                    fixture("format-transient", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, null, null), Expectation.MATCH_POLICY_OR_ERROR, configuration, requests),
                    fixture("format-persistent", new Policy(true, SamlNameIdPolicyRequestFactory.PERSISTENT, null, true), Expectation.MATCH_POLICY_OR_ERROR, configuration, requests),
                    fixture("sp-name-qualifier", new Policy(true, SamlNameIdPolicyRequestFactory.TRANSIENT, configuration.suiteIssuer(), null), Expectation.MATCH_POLICY_OR_ERROR, configuration, requests));
            default -> throw new IllegalArgumentException("Unsupported NameIDPolicy scenario: " + id);
        };
    }

    private static ScenarioFixture fixture(
            String id, Policy policy, Expectation expectation,
            IdpErrorProbeConfiguration configuration, SamlNameIdPolicyRequestFactory requests) {
        return dynamic(id, expectation, policyKey(policy), configuration, requests, ignored -> policy);
    }

    private static ScenarioFixture dynamic(
            String id, Expectation expectation, String policyDefinition,
            IdpErrorProbeConfiguration configuration, SamlNameIdPolicyRequestFactory requests,
            java.util.function.Function<String, Policy> policy) {
        return new NameIdFixture(id, expectation, policyDefinition, configuration, requests, policy);
    }

    private static String policyKey(Policy policy) {
        return String.join("|",
                Boolean.toString(policy.present()),
                String.valueOf(policy.format()),
                String.valueOf(policy.spNameQualifier()),
                String.valueOf(policy.allowCreate()));
    }

    /** Produces an in-memory observation view; plaintext is never submitted to the recorder. */
    private byte[] decryptAssertions(byte[] xml, java.security.PrivateKey key) {
        try {
            var document = SecureXml.parse(xml);
            var nodes = document.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion");
            var wrappers = new java.util.ArrayList<Element>();
            for (var index = 0; index < nodes.getLength(); index++) {
                wrappers.add((Element) nodes.item(index));
            }
            for (var wrapper : wrappers) {
                var plaintext = decrypter.decrypt(wrapper, key);
                wrapper.getParentNode().replaceChild(document.importNode(plaintext, true), wrapper);
            }
            return wrappers.isEmpty() ? xml : SecureXml.serialize(document);
        } catch (SamlException unavailable) {
            return xml;
        }
    }

    private static String requireSupported(String id) {
        if (!List.of(PROCESSING_CASE, REJECTION_CASE, CONFORMANCE_CASE).contains(id)) {
            throw new IllegalArgumentException("Unsupported NameIDPolicy case: " + id);
        }
        return id;
    }

    private enum Expectation { ANY_SAML_RESPONSE, SUCCESS_CONTROL, ERROR, MATCH_POLICY_OR_ERROR }

    private record NameIdFixture(
            String id,
            Expectation expectation,
            String policyDefinition,
            IdpErrorProbeConfiguration configuration,
            SamlNameIdPolicyRequestFactory requests,
            java.util.function.Function<String, Policy> policies) implements ScenarioFixture {
        @Override
        public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var payload = requests.build(
                    requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    configuration.registeredAcs(), context.clock().instant(), policies.apply(requestId));
            return new Prepared(new OutboundAction(
                    actionId, OutboundKind.AUTHN_REQUEST, payload,
                    configuration.ssoEndpoint(), false), requestId);
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
                var statusNodes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (statusNodes.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var success = SUCCESS.equals(((Element) statusNodes.item(0)).getAttribute("Value"));
                if (expectation == Expectation.ANY_SAML_RESPONSE) return FixtureObservation.SATISFIED;
                if (expectation == Expectation.SUCCESS_CONTROL) {
                    return success ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                }
                if (expectation == Expectation.ERROR) {
                    return success ? FixtureObservation.VIOLATED : FixtureObservation.SATISFIED;
                }
                if (!success) return FixtureObservation.SATISFIED;
                var expected = policies.apply(requestId);
                var nameIds = root.getElementsByTagNameNS(ASSERTION, "NameID");
                if (nameIds.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var nameId = (Element) nameIds.item(0);
                if (expected.format() != null && !expected.format().equals(nameId.getAttribute("Format"))) {
                    return FixtureObservation.VIOLATED;
                }
                if (configuration.suiteIssuer().equals(expected.spNameQualifier())
                        && !nameId.hasAttribute("SPNameQualifier")) {
                    // Core 8.3.7/8.3.8 permits implicit same-SP qualification. The approved
                    // variant currently requires literal equality: do not issue a false
                    // violation or silently approve that interpretation. Keep it unresolved
                    // until the protected catalog is reconciled and independently approved.
                    return FixtureObservation.NOT_VERIFIED;
                }
                if (expected.spNameQualifier() != null
                        && !expected.spNameQualifier().equals(nameId.getAttribute("SPNameQualifier"))) {
                    return FixtureObservation.VIOLATED;
                }
                return FixtureObservation.SATISFIED;
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }

        @Override
        public String definitionKey() {
            return String.join("|", id, expectation.name(), policyDefinition,
                    configuration.ssoEndpoint().toString(),
                    configuration.suiteIssuer(), configuration.registeredAcs().toString());
        }
    }
}
