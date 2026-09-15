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
 * Asynchronous SLO extension probes delivered by the authenticated browser. A trusted
 * asynchronous request must not receive a LogoutResponse, an invalid one must not be applied,
 * and the user-facing response must distinguish success from failure.
 */
public final class LogoutAsyncScenarioTestCase implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String PROCESSING_ID = "IIP-IDP17-b-idp-01";
    public static final String NO_RESPONSE_ID = "IIP-IDP17-b1-idp-01";
    public static final String FEEDBACK_ID = "IIP-IDP17-b2-idp-01";
    public static final Set<String> CASE_IDS = Set.of(PROCESSING_ID, NO_RESPONSE_ID, FEEDBACK_ID);
    private static final String VERSION = "slo-async-v2";
    private static final String P = SamlLogoutRequestFactory.PROTOCOL;
    private static final String A = SamlLogoutRequestFactory.ASSERTION;
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final Duration PROBE_WAIT = Duration.ofMinutes(5);
    private static final URI WRONG_DESTINATION = URI.create("https://samlscope.invalid/sp/slo");

    private final String caseId;
    private final Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations;
    private final TranscriptContentReader content;
    private final SamlLogoutRequestFactory logout = new SamlLogoutRequestFactory();
    private final XmlSigner signer = new XmlSigner();
    private final SamlXmlDecrypter decrypter = new SamlXmlDecrypter();
    private final XmlSignatureVerifier signatures = new XmlSignatureVerifier();

    public LogoutAsyncScenarioTestCase(String caseId,
            Function<String, IdpBasicLogoutScenarioTestCase.Configuration> configurations,
            TranscriptContentReader content) {
        if (!CASE_IDS.contains(caseId)) throw new IllegalArgumentException("Unsupported async SLO case " + caseId);
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
        return "Start with a fresh browser session and log in. SAMLscope sends asynchronous SLO probes and "
                + "checks the user-facing responses and the absence of LogoutResponse messages.";
    }

    @Override public CaseStep start(CaseContext context) {
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED, "slo.async.history-incomplete", List.of());
        var c = configurations.apply(context.runId());
        if (!c.login().preconditionsSatisfied() || c.logoutEndpoint() == null || c.suiteLogoutEndpoint() == null
                || c.suiteCredentials() == null || c.targetSigningCertificates().isEmpty() || c.targetIssuer() == null)
            return finish(Outcome.NOT_VERIFIED, "slo.async.preconditions-unmet", List.of());
        return beginLogin(context, c, "login", List.of());
    }

    private CaseStep beginLogin(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            String stage, List<EvidenceRef> evidence) {
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-" + stage, 0);
        var xml = new SamlErrorProbeRequestFactory().build(SamlErrorProbeRequestFactory.Probe.BASELINE_SUCCESS,
                "_" + action, c.login().ssoEndpoint(), c.login().suiteIssuer(), c.login().registeredAcs(),
                context.clock().instant());
        var document = SecureXml.parse(xml);
        signer.sign(document.getDocumentElement(), c.suiteCredentials(), null);
        var data = stateData(stage, action, "slo-async-login", evidence);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-" + stage, Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.AUTHN_REQUEST, SecureXml.serialize(document),
                        c.login().ssoEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)),
                c.login().responseTimeout());
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!caseId.equals(state.data().get("case_id")) || !VERSION.equals(state.data().get("definition")))
            return finish(Outcome.NOT_VERIFIED, "slo.async.scenario-changed", List.of());
        var stage = String.valueOf(state.data().get("stage"));
        if (!List.of("login", "login2", "control", "probe-mismatch", "probe-valid").contains(stage))
            return finish(Outcome.NOT_VERIFIED, "slo.async.scenario-changed", List.of());
        var evidence = evidence(state);
        if (event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.Aborted
                || event instanceof CaseEvent.InboundUnavailable || event instanceof CaseEvent.RetryInbound)
            return finish(Outcome.NOT_VERIFIED,
                    stage.startsWith("login") ? "slo.async.control-unavailable" : "slo.async.probe-no-response",
                    evidence);
        if (event instanceof CaseEvent.BrowserObservation browser) {
            var observation = browserObservation(browser);
            return switch (stage) {
                case "probe-mismatch" -> afterMismatchProbe(context, configurations.apply(context.runId()),
                        state, observation, evidence);
                case "probe-valid" -> afterValidProbe(context, configurations.apply(context.runId()),
                        state, observation, evidence);
                default -> finish(Outcome.NOT_VERIFIED, "slo.async.control-unavailable", evidence);
            };
        }
        if (!(event instanceof CaseEvent.InboundMessage inbound))
            throw new IllegalArgumentException("Async SLO scenario requires recorded inbound messages");
        evidence.add(inbound.evidence());
        if (!context.transcriptComplete()) return finish(Outcome.NOT_VERIFIED, "slo.async.history-incomplete", evidence);
        var c = configurations.apply(context.runId());
        return switch (stage) {
            case "login", "login2" -> afterLogin(context, c, state, stage, inbound, evidence);
            case "control" -> afterControl(context, c, state, inbound, evidence);
            case "probe-mismatch" -> afterMismatchProbe(context, c, state,
                    SloProbeObservation.ofSamlResponse(inbound.decodedSaml(), 200, ""), evidence);
            case "probe-valid" -> afterValidProbe(context, c, state,
                    SloProbeObservation.ofSamlResponse(inbound.decodedSaml(), 200, ""), evidence);
            default -> throw new IllegalStateException("Unsupported stage " + stage);
        };
    }

    private CaseStep afterLogin(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, String stage, CaseEvent.InboundMessage inbound, List<EvidenceRef> evidence) {
        var root = SecureXml.parse(inbound.decodedSaml()).getDocumentElement();
        if (!is(root, P, "Response") || !"2.0".equals(root.getAttribute("Version"))
                || !Objects.equals(state.data().get("request_id"), root.getAttribute("InResponseTo"))
                || !c.login().registeredAcs().toString().equals(root.getAttribute("Destination"))
                || !SUCCESS.equals(status(root)))
            return finish(Outcome.NOT_VERIFIED, "slo.async.control-unverifiable", evidence);
        var assertions = new ArrayList<>(children(root, A, "Assertion"));
        for (var encrypted : children(root, A, "EncryptedAssertion"))
            assertions.add(decrypter.decrypt(encrypted, c.suiteCredentials().privateKey()));
        if (assertions.size() != 1) return finish(Outcome.NOT_VERIFIED, "slo.async.session-unverifiable", evidence);
        var subject = children(assertions.getFirst(), A, "Subject");
        if (subject.size() != 1) return finish(Outcome.NOT_VERIFIED, "slo.async.session-unverifiable", evidence);
        var names = children(subject.getFirst(), A, "NameID");
        if (names.size() != 1) return finish(Outcome.NOT_VERIFIED, "slo.async.session-unverifiable", evidence);
        var indexes = children(assertions.getFirst(), A, "AuthnStatement").stream()
                .map(element -> element.getAttribute("SessionIndex")).filter(value -> !value.isBlank()).toList();
        if (indexes.isEmpty()) return finish(Outcome.NOT_VERIFIED, "slo.async.session-unverifiable", evidence);
        if (NO_RESPONSE_ID.equals(caseId) && "login".equals(stage)) {
            // The ICs require a synchronous response control before the asynchronous probe.
            var action = ActionIds.derive(context.runId(), caseId, VERSION + "-control", 0);
            var payload = logout.sign(logout.build("_" + action, c.logoutEndpoint(), c.login().suiteIssuer(),
                    names.getFirst(), indexes, context.clock().instant(), null, false), c.suiteCredentials());
            var data = stateData("control", action, "slo-async-sync-control", evidence);
            return new CaseStep.AwaitInbound(new CaseState(VERSION + "-control", Map.copyOf(data)),
                    List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                            c.logoutEndpoint(), false)),
                    new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)),
                    c.login().responseTimeout());
        }
        var stageName = PROCESSING_ID.equals(caseId) || FEEDBACK_ID.equals(caseId) ? "probe-mismatch" : "probe-valid";
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-" + stageName, 0);
        var mismatched = !"probe-valid".equals(stageName);
        var destination = mismatched ? WRONG_DESTINATION : c.logoutEndpoint();
        var payload = logout.sign(logout.build("_" + action, destination, c.login().suiteIssuer(),
                names.getFirst(), indexes, context.clock().instant(), null, true), c.suiteCredentials());
        var data = stateData(stageName, action,
                mismatched ? "slo-async-destination-mismatch" : "slo-async-trusted", evidence);
        data.put("identifier_xml", serializeIdentifier(names.getFirst()));
        data.put("session_indexes", List.copyOf(indexes));
        data.put("browser_observation", true);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-" + stageName, Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                        c.logoutEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)), PROBE_WAIT);
    }

    private CaseStep afterControl(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, CaseEvent.InboundMessage inbound, List<EvidenceRef> evidence) {
        var root = SecureXml.parse(inbound.decodedSaml()).getDocumentElement();
        var trustedResponse = is(root, P, "LogoutResponse") && trustedInbound(context, inbound, root, c)
                && Objects.equals(state.data().get("request_id"), root.getAttribute("InResponseTo"));
        if (!trustedResponse) return finish(Outcome.NOT_VERIFIED, "slo.async.sync-control-unavailable", evidence);
        var postProbe = state.data().containsKey("probe_saml") || state.data().containsKey("probe_http_status");
        if (postProbe) {
            return SUCCESS.equals(status(root))
                    ? finish(Outcome.SATISFIED, "slo.async.mismatch-not-applied", evidence,
                            Map.of("control_status", status(root)))
                    : finish(Outcome.VIOLATED, "slo.async.mismatch-applied", evidence,
                            Map.of("control_status", status(root)));
        }
        if (!SUCCESS.equals(status(root))) return finish(Outcome.NOT_VERIFIED, "slo.async.sync-control-unavailable", evidence);
        return beginLogin(context, c, "login2", evidence);
    }

    private CaseStep afterMismatchProbe(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, SloProbeObservation observation, List<EvidenceRef> evidence) {
        if (observation == null) return finish(Outcome.NOT_VERIFIED, "slo.async.probe-unrecorded", evidence);
        var details = new LinkedHashMap<String, Object>(observation.diagnostics());
        if (!FEEDBACK_ID.equals(caseId) && observation.samlPresent())
            return finish(Outcome.VIOLATED, "slo.async.mismatch-response-returned", evidence, details);
        if (FEEDBACK_ID.equals(caseId)) {
            var action = ActionIds.derive(context.runId(), caseId, VERSION + "-probe-valid", 0);
            var identifier = SecureXml.parse(String.valueOf(state.data().get("identifier_xml"))
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
            @SuppressWarnings("unchecked")
            var indexes = (List<String>) state.data().get("session_indexes");
            var payload = logout.sign(logout.build("_" + action, c.logoutEndpoint(), c.login().suiteIssuer(),
                    identifier, indexes, context.clock().instant(), null, true), c.suiteCredentials());
            var data = stateData("probe-valid", action, "slo-async-trusted", evidence);
            data.put("failure_page", observation.bodyHash());
            data.put("failure_status", observation.httpStatus());
            data.put("failure_indicated", observation.failureIndicated());
            data.put("browser_observation", true);
            return new CaseStep.AwaitInbound(new CaseState(VERSION + "-probe-valid", Map.copyOf(data)),
                    List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                            c.logoutEndpoint(), false)),
                    new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)), PROBE_WAIT);
        }
        var action = ActionIds.derive(context.runId(), caseId, VERSION + "-control", 0);
        var identifier = SecureXml.parse(String.valueOf(state.data().get("identifier_xml"))
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
        @SuppressWarnings("unchecked")
        var indexes = (List<String>) state.data().get("session_indexes");
        var payload = logout.sign(logout.build("_" + action, c.logoutEndpoint(), c.login().suiteIssuer(),
                identifier, indexes, context.clock().instant(), null, false), c.suiteCredentials());
        var data = stateData("control", action, "slo-async-mismatch-control", evidence);
        data.putAll(details);
        return new CaseStep.AwaitInbound(new CaseState(VERSION + "-control", Map.copyOf(data)),
                List.of(new OutboundAction(action, OutboundKind.LOGOUT_REQUEST, payload,
                        c.logoutEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", action)),
                c.login().responseTimeout());
    }

    private CaseStep afterValidProbe(CaseContext context, IdpBasicLogoutScenarioTestCase.Configuration c,
            CaseState state, SloProbeObservation observation, List<EvidenceRef> evidence) {
        if (observation == null) return finish(Outcome.NOT_VERIFIED, "slo.async.probe-unrecorded", evidence);
        var details = new LinkedHashMap<String, Object>(observation.diagnostics());
        if (FEEDBACK_ID.equals(caseId)) {
            var failure = String.valueOf(state.data().getOrDefault("failure_page", ""));
            var fixed = !failure.isEmpty() && failure.equals(observation.bodyHash())
                    && Objects.equals(state.data().get("failure_status"), observation.httpStatus());
            details.put("failure_page", failure);
            details.put("success_page", observation.bodyHash());
            details.put("failure_indicated", state.data().getOrDefault("failure_indicated", false));
            if (fixed) return finish(Outcome.VIOLATED, "slo.async.feedback.fixed-page", evidence, details);
            var indicated = Boolean.TRUE.equals(state.data().get("failure_indicated"));
            return finish(indicated ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                    indicated ? "slo.async.feedback.distinguishes-success-and-failure"
                            : "slo.async.feedback.unrecognized",
                    evidence, details);
        }
        if (observation.samlPresent())
            return finish(Outcome.VIOLATED, "slo.async.response-returned", evidence, details);
        return finish(Outcome.SATISFIED, "slo.async.no-response", evidence, details);
    }

    private static SloProbeObservation browserObservation(CaseEvent.BrowserObservation observation) {
        return SloProbeObservation.ofBrowserResponse(
                observation.httpStatus(), observation.url(), observation.body());
    }

    private boolean trustedInbound(CaseContext context, CaseEvent.InboundMessage inbound, Element root,
            IdpBasicLogoutScenarioTestCase.Configuration c) {
        if (c.targetSigningCertificates().stream()
                .anyMatch(cert -> signatures.hasValidEnvelopedSignature(root, cert))) return true;
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

    private String serializeIdentifier(Element identifier) {
        var document = SecureXml.newDocument();
        document.appendChild(document.importNode(identifier, true));
        return new String(SecureXml.serialize(document), java.nio.charset.StandardCharsets.UTF_8);
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
}
