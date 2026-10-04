package com.samlscope.runner.cases;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.InboundMatcher;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SamlLogoutRequestFactory;
import com.samlscope.saml.normal.SecureXml;

/**
 * Delivers one crafted LogoutRequest with the authenticated browser and proves by a follow-up
 * valid logout whether the target applied it. Rejection fixtures never conclude from silence
 * alone, and the observed HTTP feedback is submitted by the browser driver as evidence.
 */
public final class LogoutRejectionScenarioTestCase implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String DESTINATION_ID = "IIP-IDP17-x-idp-01";
    public static final String SIGNATURE_ID = "IIP-IDP17-y-idp-01";
    public static final String INVALID_SIGNATURE_ID = "IIP-IDP17-z-idp-01";
    public static final String ERROR_RESPONSE_ID = "IIP-IDP17-aa-idp-01";
    public static final String EXCLUDED_CONTENT_ID = "IIP-IDP17-al-idp-01";
    public static final Set<String> CASE_IDS = Set.of(
            DESTINATION_ID, SIGNATURE_ID, INVALID_SIGNATURE_ID, ERROR_RESPONSE_ID, EXCLUDED_CONTENT_ID);
    private static final String VERSION = "slo-rejection-v2";
    private static final String P = SamlLogoutRequestFactory.PROTOCOL;
    private static final String A = SamlLogoutRequestFactory.ASSERTION;
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final Duration PROBE_WAIT = Duration.ofMinutes(5);
    private static final URI WRONG_DESTINATION = URI.create("https://samlscope.invalid/sp/slo");
    private static final String ENVELOPED_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    private static final String EXCLUSIVE_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    private final String caseId;
    private final Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations;
    private final TranscriptContentReader content;
    private final SamlLogoutRequestFactory logout = new SamlLogoutRequestFactory();
    private final XmlSigner signer = new XmlSigner();
    private final SamlXmlDecrypter decrypter = new SamlXmlDecrypter();
    private final XmlSignatureVerifier signatures = new XmlSignatureVerifier();

    public LogoutRejectionScenarioTestCase(String caseId,
            Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations,
            TranscriptContentReader content) {
        if (!CASE_IDS.contains(caseId)) throw new IllegalArgumentException("Unsupported SLO rejection case " + caseId);
        this.caseId = caseId;
        this.configurations = Objects.requireNonNull(configurations, "configurations");
        this.content = Objects.requireNonNull(content, "content");
    }

    @Override public String id() { return caseId; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public boolean plansFreshSessionBoundary() { return true; }
    @Override public boolean requiresFreshSession(CaseState state) {
        return String.valueOf(state.data().get("stage")).startsWith("login");
    }
    @Override public Binding outboundBinding(CaseState state) { return Binding.HTTP_POST; }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }
    @Override public String browserInstructionsEn() {
        return "Start with a fresh browser session and log in. SAMLscope sends one crafted logout request "
                + "and then one valid logout request to prove whether the session survived the crafted one.";
    }

    @Override public CaseStep start(CaseContext context) {
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED, "slo.rejection.history-incomplete", List.of());
        var c = configurations.apply(context.runId());
        if (!c.login().preconditionsSatisfied() || c.logoutEndpoint() == null || c.suiteLogoutEndpoint() == null
                || c.suiteCredentials() == null || c.targetSigningCertificates().isEmpty() || c.targetIssuer() == null)
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.preconditions-unmet", List.of());
        return beginLogin(context, c, List.of());
    }

    private CaseStep beginLogin(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            List<EvidenceRef> evidence) {
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-login", 0);
        var xml = new SamlErrorProbeRequestFactory().build(SamlErrorProbeRequestFactory.Probe.BASELINE_SUCCESS,
                "_" + action, c.login().ssoEndpoint(), c.login().suiteIssuer(), c.login().registeredAcs(),
                context.clock().instant());
        var document = SecureXml.parse(xml);
        signer.sign(document.getDocumentElement(), c.suiteCredentials(), null);
        var data = stateData("login", action, "slo-rejection-login", evidence);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-login", Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.AUTHN_REQUEST, SecureXml.serialize(document),
                        c.login().ssoEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)),
                c.login().responseTimeout());
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!caseId.equals(state.data().get("case_id")) || !VERSION.equals(state.data().get("definition"))
                || !List.of("login", "probe", "control").contains(state.data().get("stage")))
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.scenario-changed", List.of());
        var evidence = evidence(state);
        var stage = String.valueOf(state.data().get("stage"));
        if (event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.Aborted
                || event instanceof CaseEvent.InboundUnavailable || event instanceof CaseEvent.RetryInbound)
            return finish(Outcome.NOT_VERIFIED,
                    "login".equals(stage) ? "slo.rejection.control-unavailable" : "slo.rejection.probe-no-response",
                    evidence);
        if (event instanceof CaseEvent.BrowserObservation browser) {
            if (!"probe".equals(stage)) return finish(Outcome.NOT_VERIFIED, "slo.rejection.control-unverifiable", evidence);
            return afterProbe(context, configurations.apply(context.runId()), state,
                    browserObservation(browser), evidence);
        }
        if (!(event instanceof CaseEvent.InboundMessage inbound))
            throw new IllegalArgumentException("SLO rejection scenario requires recorded inbound XML");
        evidence.add(inbound.evidence());
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED, "slo.rejection.history-incomplete", evidence);
        var c = configurations.apply(context.runId());
        return switch (stage) {
            case "login" -> afterLogin(context, c, state, inbound, evidence);
            case "probe" -> afterProbe(context, c, state, samlObservation(inbound), evidence);
            case "control" -> afterControl(context, c, state, inbound, evidence);
            default -> throw new IllegalStateException("Unsupported stage " + stage);
        };
    }

    private CaseStep afterLogin(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, CaseEvent.InboundMessage inbound, List<EvidenceRef> evidence) {
        var root = SecureXml.parse(inbound.decodedSaml()).getDocumentElement();
        if (!is(root, P, "Response") || !"2.0".equals(root.getAttribute("Version"))
                || !Objects.equals(state.data().get("request_id"), root.getAttribute("InResponseTo"))
                || !c.login().registeredAcs().toString().equals(root.getAttribute("Destination"))
                || !SUCCESS.equals(status(root)))
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.control-unverifiable", evidence);
        var assertions = new ArrayList<>(children(root, A, "Assertion"));
        for (var encrypted : children(root, A, "EncryptedAssertion"))
            assertions.add(decrypter.decrypt(encrypted, c.suiteCredentials().privateKey()));
        if (assertions.size() != 1 || !is(assertions.getFirst(), A, "Assertion"))
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence);
        var assertion = assertions.getFirst();
        if (!trusted(root, c) && !trusted(assertion, c))
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence);
        var subjects = children(assertion, A, "Subject");
        if (subjects.size() != 1) return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence);
        var names = children(subjects.getFirst(), A, "NameID");
        if (names.size() != 1) return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence);
        var indexes = children(assertion, A, "AuthnStatement").stream()
                .map(element -> element.getAttribute("SessionIndex")).filter(value -> !value.isBlank()).toList();
        if (indexes.isEmpty()) return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence);
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-probe", 0);
        byte[] payload;
        try {
            payload = craft(c, "_" + action, names.getFirst(), indexes, context.clock().instant());
        } catch (RuntimeException fixtureFailure) {
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.fixture-unavailable", evidence);
        }
        var data = stateData("probe", action, fixtureId(), evidence);
        data.put("identifier_xml", serializeIdentifier(names.getFirst()));
        data.put("session_indexes", List.copyOf(indexes));
        // The probe is delivered by the authenticated browser; its HTTP feedback is reported back.
        data.put("browser_observation", true);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-probe", Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                        c.logoutEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)), PROBE_WAIT);
    }

    private CaseStep afterProbe(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, SloProbeObservation observation, List<EvidenceRef> evidence) {
        if (observation == null) return finish(Outcome.NOT_VERIFIED, "slo.rejection.probe-unrecorded", evidence);
        var details = new LinkedHashMap<String, Object>(observation.diagnostics());
        if (ERROR_RESPONSE_ID.equals(caseId)) {
            if (observation.samlPresent() && !observation.samlSuccess())
                return finish(optionalDirectionObserved() ? Outcome.SATISFIED : Outcome.SATISFIED_WITH_NOTE,
                        "slo.invalid-signature.error-response-observed", evidence, details);
            if (observation.samlSuccess())
                return finish(Outcome.VIOLATED, "slo.invalid-signature.accepted-as-success", evidence, details);
            return finish(Outcome.VIOLATED, "slo.invalid-signature.no-error-response", evidence, details);
        }
        if (observation.samlSuccess())
            return finish(Outcome.VIOLATED, "slo.rejection.applied-to-session", evidence, details);
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-control", 0);
        Element identifier;
        try {
            identifier = SecureXml.parse(String.valueOf(state.data().get("identifier_xml"))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
        } catch (RuntimeException unavailable) {
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.session-unverifiable", evidence, details);
        }
        @SuppressWarnings("unchecked")
        var indexes = (List<String>) state.data().get("session_indexes");
        var payload = logout.sign(logout.build("_" + action, c.logoutEndpoint(), c.login().suiteIssuer(),
                identifier, indexes, context.clock().instant(), null, false), c.suiteCredentials());
        var data = stateData("control", action, fixtureId() + "-control", evidence);
        data.putAll(details);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-control", Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                        c.logoutEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)),
                c.login().responseTimeout());
    }

    private CaseStep afterControl(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, CaseEvent.InboundMessage inbound, List<EvidenceRef> evidence) {
        var details = new LinkedHashMap<String, Object>();
        details.put("probe_http_status", state.data().getOrDefault("probe_http_status", ""));
        details.put("probe_saml", state.data().getOrDefault("probe_saml", ""));
        try {
            var root = SecureXml.parse(inbound.decodedSaml()).getDocumentElement();
            if (!is(root, P, "LogoutResponse") || !trustedInbound(context, inbound, root, c)
                    || !Objects.equals(state.data().get("request_id"), root.getAttribute("InResponseTo"))
                    || !c.suiteLogoutEndpoint().toString().equals(root.getAttribute("Destination")))
                return finish(Outcome.NOT_VERIFIED, "slo.rejection.control-unverifiable", evidence, details);
            details.put("control_status", status(root));
            if (!SUCCESS.equals(status(root)))
                return finish(Outcome.VIOLATED, "slo.rejection.session-not-preserved", evidence, details);
            return finish(optionalDirectionObserved() ? Outcome.SATISFIED : Outcome.SATISFIED_WITH_NOTE,
                    satisfiedReason(), evidence, details);
        } catch (RuntimeException unparsable) {
            return finish(Outcome.NOT_VERIFIED, "slo.rejection.control-unverifiable", evidence, details);
        }
    }

    private byte[] craft(IdpBasicLogoutScenarioTestCase.Configuration c, String requestId,
            Element identifier, List<String> indexes, java.time.Instant now) {
        if (EXCLUDED_CONTENT_ID.equals(caseId)) {
            var document = SecureXml.parse(logout.build(requestId, c.logoutEndpoint(), c.login().suiteIssuer(),
                    identifier, indexes, now, null, false));
            var root = document.getDocumentElement();
            signer.sign(root, c.suiteCredentials(), null, new XmlSigner.SignatureOptions(true, List.of(
                    XmlSigner.TransformSpec.algorithm(ENVELOPED_SIGNATURE),
                    XmlSigner.TransformSpec.xpath("not(ancestor-or-self::samlp:SessionIndex)"),
                    XmlSigner.TransformSpec.algorithm(EXCLUSIVE_C14N))));
            if (root.getElementsByTagNameNS(P, "SessionIndex").getLength() == 0
                    || root.getElementsByTagNameNS(DS, "XPath").getLength() == 0)
                throw new IllegalStateException("Fixture did not exclude SessionIndex");
            if (!signatures.hasValidEnvelopedSignature(root, c.suiteCredentials().certificate()))
                throw new IllegalStateException("Exclusion fixture signature is not cryptographically valid");
            return SecureXml.serialize(document);
        }
        var asynchronous = INVALID_SIGNATURE_ID.equals(caseId);
        var destination = DESTINATION_ID.equals(caseId) ? WRONG_DESTINATION : c.logoutEndpoint();
        var signed = logout.sign(logout.build(requestId, destination, c.login().suiteIssuer(),
                identifier, indexes, now, null, asynchronous), c.suiteCredentials());
        if (DESTINATION_ID.equals(caseId)) return signed;
        return tampered(signed);
    }

    private static byte[] tampered(byte[] signed) {
        var document = SecureXml.parse(signed);
        var values = document.getElementsByTagNameNS(DS, "SignatureValue");
        if (values.getLength() != 1) throw new IllegalStateException("Fixture has no single SignatureValue");
        var node = (Element) values.item(0);
        var text = node.getTextContent();
        if (text.isEmpty()) throw new IllegalStateException("SignatureValue is empty");
        node.setTextContent((text.charAt(0) == 'A' ? 'B' : 'A') + text.substring(1));
        return SecureXml.serialize(document);
    }

    private static SloProbeObservation samlObservation(CaseEvent.InboundMessage inbound) {
        return SloProbeObservation.ofSamlResponse(inbound.decodedSaml(), 200, "");
    }

    private static SloProbeObservation browserObservation(CaseEvent.BrowserObservation observation) {
        return SloProbeObservation.ofBrowserResponse(
                observation.httpStatus(), observation.url(), observation.body());
    }

    private boolean trustedInbound(CaseContext context, CaseEvent.InboundMessage inbound, Element root,
            IdpBasicLogoutScenarioTestCase.Configuration c) {
        if (trusted(root, c)) return true;
        var entry = contentEntry(context, inbound.evidence());
        if (entry == null || !"GET".equalsIgnoreCase(entry.method()) || entry.rawQuery() == null) return false;
        var verifier = new com.samlscope.saml.binding.RedirectSignatureVerifier();
        var xml = inbound.decodedSaml();
        return c.targetSigningCertificates().stream()
                .anyMatch(cert -> verifier.isValidForMessage(entry.rawQuery(), cert, xml));
    }

    private com.samlscope.core.transcript.TranscriptEntry contentEntry(CaseContext context, EvidenceRef evidence) {
        if (!"transcript".equals(evidence.kind())) return null;
        return context.transcript().list(context.runId()).stream()
                .filter(value -> evidence.reference().equals(value.id())).findFirst().orElse(null);
    }

    private boolean trusted(Element root, IdpBasicLogoutScenarioTestCase.Configuration c) {
        return c.targetSigningCertificates().stream()
                .anyMatch(cert -> signatures.hasValidEnvelopedSignature(root, cert));
    }

    private boolean optionalDirectionObserved() {
        return DESTINATION_ID.equals(caseId) || EXCLUDED_CONTENT_ID.equals(caseId);
    }

    private String fixtureId() {
        if (DESTINATION_ID.equals(caseId)) return "slo-destination-mismatch";
        if (SIGNATURE_ID.equals(caseId)) return "slo-tampered-signature";
        if (INVALID_SIGNATURE_ID.equals(caseId)) return "slo-invalid-signature-async";
        if (ERROR_RESPONSE_ID.equals(caseId)) return "slo-invalid-signature-error";
        return "slo-excluded-content";
    }

    private String satisfiedReason() {
        if (DESTINATION_ID.equals(caseId)) return "slo.destination-mismatch.not-applied";
        if (SIGNATURE_ID.equals(caseId)) return "slo.tampered-signature.not-applied";
        if (INVALID_SIGNATURE_ID.equals(caseId)) return "slo.invalid-signature.not-relied-upon";
        return "slo.excluded-content.rejected";
    }

    private Map<String, Object> stateData(String stage, String action, String fixture, List<EvidenceRef> evidence) {
        var data = new LinkedHashMap<String, Object>();
        data.put("definition", VERSION); data.put("stage", stage); data.put("case_id", caseId);
        data.put("request_id", "_" + action); data.put("fixture_id", fixture);
        data.put("evidence", references(evidence));
        return data;
    }

    private List<EvidenceRef> evidence(CaseState state) {
        var result = new ArrayList<EvidenceRef>();
        if (state.data().get("evidence") instanceof List<?> refs)
            for (var ref : refs) if (ref instanceof String value) result.add(new EvidenceRef("transcript", value));
        return result;
    }

    private static List<String> references(List<EvidenceRef> evidence) {
        return evidence.stream().map(EvidenceRef::reference).toList();
    }

    private CaseStep finish(Outcome outcome, String reason, List<EvidenceRef> evidence) {
        return finish(outcome, reason, evidence, Map.of());
    }

    private CaseStep finish(Outcome outcome, String reason, List<EvidenceRef> evidence, Map<String, Object> details) {
        return new CaseStep.Finish(new CaseOutcome(outcome, outcome == Outcome.NOT_VERIFIED ? reason : null,
                reason, reason, List.copyOf(evidence), details));
    }

    private String status(Element root) {
        var statuses = children(root, P, "Status");
        if (statuses.size() != 1) return "";
        var codes = children(statuses.getFirst(), P, "StatusCode");
        return codes.size() == 1 ? codes.getFirst().getAttribute("Value") : "";
    }

    private static boolean is(Element e, String ns, String name) {
        return ns.equals(e.getNamespaceURI()) && name.equals(e.getLocalName());
    }

    private static List<Element> children(Element root, String ns, String name) {
        var result = new ArrayList<Element>();
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element && is(element, ns, name)) result.add(element);
        return result;
    }

    private static String serializeIdentifier(Element identifier) {
        var document = SecureXml.newDocument();
        document.appendChild(document.importNode(identifier, true));
        return new String(SecureXml.serialize(document), java.nio.charset.StandardCharsets.UTF_8);
    }
}
