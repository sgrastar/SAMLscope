package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.List;
import java.util.Set;
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
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Signed AuthnRequest matrix proving verification and target-side SHA-256 creation. */
public final class IdpSignedRequestScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt, ProtocolEvidenceCase,
        com.samlscope.runner.RecordedEvidenceReevaluation {
    public static final String VERIFY_CASE = "IIP-SSO01-ai-idp-01";
    public static final String RELIANCE_CASE = "IIP-SSO01-aj-idp-01";
    public static final String ERROR_CASE = "IIP-SSO01-ak-idp-01";
    public static final String EXCLUDED_CONTENT_CASE = "IIP-SSO01-fk-idp-01";
    public static final String SIGNED_OBJECT_CASE = "IIP-SSO01-fu-idp-01";
    public static final String SHA256_DIGEST_CASE = "IIP-ALG01-a-idp-01";
    public static final String RSA_SHA256_CASE = "IIP-ALG02-a-idp-01";
    private static final Set<String> CASES = Set.of(
            VERIFY_CASE, RELIANCE_CASE, ERROR_CASE, EXCLUDED_CONTENT_CASE, SIGNED_OBJECT_CASE,
            SHA256_DIGEST_CASE, RSA_SHA256_CASE);
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlPlanCredentialsProvider credentials;
    private final SamlSignedRequestFactory requests;
    private final java.util.function.Function<CaseContext,java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativeEvidence;

    public IdpSignedRequestScenarioTestCase withNativeEvidence(
            java.util.function.Function<CaseContext,java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> observer) {
        if(!NativeSignedRequestEvidence.supports(id))throw new IllegalArgumentException("Unsupported native algorithm case");
        return new IdpSignedRequestScenarioTestCase(id,configurations,credentials,requests,observer);
    }
    public IdpSignedRequestScenarioTestCase withNativeEvidence(
            java.nio.file.Path directory,com.samlscope.core.transcript.TranscriptContentReader content,
            java.util.function.Function<String,byte[]> metadata) {
        return withNativeEvidence(new NativeSignedRequestEvidence(id,directory,content,metadata,configurations,credentials));
    }

    public IdpSignedRequestScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlPlanCredentialsProvider credentials) {
        this(id, configurations, credentials, new SamlSignedRequestFactory());
    }

    IdpSignedRequestScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlPlanCredentialsProvider credentials,
            SamlSignedRequestFactory requests) {
        this(id,configurations,credentials,requests,ignored->java.util.Optional.empty());
    }

    private IdpSignedRequestScenarioTestCase(String id,
            java.util.function.Function<String,IdpErrorProbeConfiguration> configurations,
            SamlPlanCredentialsProvider credentials,SamlSignedRequestFactory requests,
            java.util.function.Function<CaseContext,java.util.Optional<com.samlscope.core.evaluation.CaseOutcome>> nativeEvidence) {
        if (!CASES.contains(id)) throw new IllegalArgumentException("Unsupported signed-request case: " + id);
        this.id = id;
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.credentials = java.util.Objects.requireNonNull(credentials, "credentials");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.nativeEvidence = java.util.Objects.requireNonNull(nativeEvidence,"nativeEvidence");
    }

    private FixtureScenarioTestCase scenario(String runId) {
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        var planCredentials = credentials.credentialsFor(runId).orElse(null);
        var matrix = switch (id) {
            case EXCLUDED_CONTENT_CASE -> List.of(
                    Fixture.VALID, Fixture.XPATH_EXCLUDE_SCOPING, Fixture.XPATH_EMPTY_CONTENT,
                    Fixture.XPATH_EXCLUDE_ACS, Fixture.XPATH_EXCLUDE_NAMEID_POLICY);
            case SIGNED_OBJECT_CASE -> List.of(Fixture.VALID, Fixture.SIGNED_WITH_OBJECT);
            default -> List.of(
                    Fixture.VALID, Fixture.TAMPERED_ACS,
                    Fixture.BAD_REFERENCE, Fixture.BAD_SIGNATURE_VALUE);
        };
        var fixtures = matrix.stream().<ScenarioFixture>map(value ->
                new SignedFixture(id, value, configuration, planCredentials, requests)).toList();
        return new FixtureScenarioTestCase(
                id, TargetRole.IDP, fixtures,
                ignored -> configuration.preconditionsSatisfied() && planCredentials != null,
                new FixtureScenarioTestCase.Vocabulary(
                        "signed_request_preconditions_unmet", "idp.signed-request.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.signed-request.delivery-unknown",
                        "scenario_aborted", "idp.signed-request.aborted",
                        "case.idp.signed-request.control-failed",
                        "signed_request_validation_violated", "case.idp.signed-request.violated",
                        "signed_request_result_not_conclusive", "idp.signed-request.inconclusive",
                        "case.idp.signed-request.inconclusive",
                        "idp.signed-request.satisfied", "case.idp.signed-request.satisfied"));
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context.runId()).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if(event instanceof CaseEvent.TranscriptReady) {
            var observed=nativeEvidence.apply(context);
            if(observed.isPresent() && observed.orElseThrow().outcome()==com.samlscope.core.evaluation.Outcome.SATISFIED)
                return new CaseStep.Finish(observed.orElseThrow());
        }
        return scenario(context.runId()).resume(context, state, event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome=nativeEvidence.apply(context);
        var required=List.of("VALID","TAMPERED_ACS","BAD_REFERENCE","BAD_SIGNATURE_VALUE");
        boolean ready=outcome.isPresent() && outcome.orElseThrow().outcome()==com.samlscope.core.evaluation.Outcome.SATISFIED;
        return new EvidenceStatus(ready,required,ready?required:List.of(),outcome.map(com.samlscope.core.evaluation.CaseOutcome::details).orElse(java.util.Map.of()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(com.samlscope.core.evaluation.CaseOutcome previous) {
        return NativeSignedRequestEvidence.supports(id) && previous!=null
            && previous.outcome()==com.samlscope.core.evaluation.Outcome.NOT_VERIFIED
            && Set.of("idp.signed-request.inconclusive","idp.signed-request.delivery-unknown","idp.signed-request.aborted")
                .contains(String.valueOf(previous.reasonCode()));
    }
    @Override public java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> reevaluateRecordedEvidence(
            CaseContext context,com.samlscope.core.evaluation.CaseOutcome previous) {
        if(!supportsRecordedEvidenceReevaluation(previous))return java.util.Optional.empty();
        return nativeEvidence.apply(context).flatMap(next->com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous,next));
    }
    @Override public String browserInstructionsEn() {
        return "Log in for the valid XML-signed AuthnRequest control. SAMLscope then sends content-tampered, reference-tampered, and SignatureValue-tampered requests. It derives the outcome from correlated Responses and target-generated signature algorithms; do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private record SignedFixture(
            String caseId,
            Fixture fixture,
            IdpErrorProbeConfiguration configuration,
            PlanCredentials credentials,
            SamlSignedRequestFactory requests) implements ScenarioFixture {
        @Override public String id() {
            return fixture.name().toLowerCase(java.util.Locale.ROOT).replace('_', '-');
        }

        @Override public Prepared prepare(CaseContext context, String actionId) {
            if (credentials == null) throw new IllegalStateException("Suite signing credentials unavailable");
            var requestId = "_" + actionId;
            var payload = requests.build(
                    fixture, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    configuration.registeredAcs(), context.clock().instant(), credentials);
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
                var codes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (codes.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                var success = SUCCESS.equals(((Element) codes.item(0)).getAttribute("Value"));
                var assertions = root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                        + root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength();
                if (fixture != Fixture.VALID) {
                    // ALG01/ALG02 require support for the algorithms, not that every deployment
                    // globally requires signed AuthnRequests. Acceptance of an invalid optional
                    // signature in a non-enforcing configuration therefore cannot prove that the
                    // capability is absent. A rejection is positive evidence of verification;
                    // acceptance remains inconclusive and must not become target nonconformance.
                    if (SHA256_DIGEST_CASE.equals(caseId) || RSA_SHA256_CASE.equals(caseId)) {
                        return success && assertions > 0
                                ? FixtureObservation.NOT_VERIFIED : FixtureObservation.SATISFIED;
                    }
                    if (ERROR_CASE.equals(caseId)) {
                        return success && assertions > 0
                                ? FixtureObservation.VIOLATED : FixtureObservation.SATISFIED;
                    }
                    return success && assertions > 0
                            ? FixtureObservation.VIOLATED : FixtureObservation.SATISFIED;
                }
                if (!success || assertions == 0) return FixtureObservation.CONTROL_FAILED;
                if (SHA256_DIGEST_CASE.equals(caseId)) {
                    return containsAlgorithm(root, "DigestMethod", SHA256)
                            ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                }
                if (RSA_SHA256_CASE.equals(caseId)) {
                    return containsAlgorithm(root, "SignatureMethod", RSA_SHA256)
                            ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                }
                return FixtureObservation.SATISFIED;
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
            if (fixture == Fixture.VALID) return FixtureObservation.CONTROL_FAILED;
            // IIP-SSO01.ak explicitly requires a SAML error Response. A local HTTP error does
            // not satisfy the SHOULD. Other signed-request cases remain inconclusive here.
            return ERROR_CASE.equals(caseId)
                    ? FixtureObservation.VIOLATED : FixtureObservation.NOT_VERIFIED;
        }

        @Override public FixtureObservation observeUnavailable(String reason) {
            // Absence of a callback does not establish algorithm verification. A native
            // rejection may be used only by a request-bound evidence adapter, not this event.
            if (SHA256_DIGEST_CASE.equals(caseId) || RSA_SHA256_CASE.equals(caseId)) {
                return FixtureObservation.NOT_VERIFIED;
            }
            if (!"operator-reported-no-saml-response".equals(reason)) {
                return FixtureObservation.NOT_VERIFIED;
            }
            return fixture == Fixture.VALID
                    ? FixtureObservation.CONTROL_FAILED
                    : ERROR_CASE.equals(caseId)
                            ? FixtureObservation.NOT_VERIFIED : FixtureObservation.SATISFIED;
        }

        private boolean containsAlgorithm(Element root, String localName, String algorithm) {
            var values = root.getElementsByTagNameNS(DS, localName);
            for (var index = 0; index < values.getLength(); index++) {
                if (algorithm.equals(((Element) values.item(index)).getAttribute("Algorithm"))) return true;
            }
            return false;
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            var certificate = credentials == null ? "missing" : credentials.certificate().getSerialNumber().toString(16);
            return String.join("|", caseId, fixture.name(), configuration.ssoEndpoint().toString(),
                    configuration.registeredAcs().toString(), certificate,
                    NativeSignedRequestEvidence.supports(caseId)
                            ? "signed-request-algorithm-v2" : "signed-request-recorder-terminal-http-v2");
        }
    }
}
