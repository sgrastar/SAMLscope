package com.samlscope.runner.cases;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** Browser-driven ForceAuthn sequence; the user only clears/login sessions when prompted. */
public final class IdpForceAuthnScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String CASE_ID = "IIP-IDP06-a-idp-01";
    public static final String MECHANISM_ACCESS_CASE = "IIP-IDP06-b-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final List<Stage> STAGES = List.of(
            new Stage("establish-session", Probe.BASELINE_SUCCESS),
            new Stage("omitted-with-session", Probe.BASELINE_SUCCESS),
            new Stage("false-with-session", Probe.FORCE_AUTHN_FALSE),
            new Stage("true-with-session", Probe.FORCE_AUTHN_TRUE));
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlErrorProbeRequestFactory requests;
    private final SamlDecryptionKeyProvider decryptionKeys;
    private final String id;

    public IdpForceAuthnScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(CASE_ID, configurations, ignored -> java.util.Optional.empty());
    }

    public IdpForceAuthnScenarioTestCase(
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(CASE_ID, configurations, decryptionKeys);
    }

    public IdpForceAuthnScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(id, configurations, ignored -> java.util.Optional.empty());
    }

    public IdpForceAuthnScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider decryptionKeys) {
        this(id, configurations, new SamlErrorProbeRequestFactory(), decryptionKeys);
    }

    IdpForceAuthnScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests) {
        this(id, configurations, requests, ignored -> java.util.Optional.empty());
    }

    IdpForceAuthnScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlErrorProbeRequestFactory requests,
            SamlDecryptionKeyProvider decryptionKeys) {
        if (!List.of(CASE_ID, MECHANISM_ACCESS_CASE).contains(id)) {
            throw new IllegalArgumentException("Unsupported ForceAuthn case: " + id);
        }
        this.id = id;
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.decryptionKeys = java.util.Objects.requireNonNull(decryptionKeys, "decryptionKeys");
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public boolean requiresFreshSession(CaseState state) {
        return "establish-session".equals(state.data().get("stage"));
    }
    @Override public boolean plansFreshSessionBoundary() { return true; }
    @Override public int plannedDeliberateActions() {
        // Establish a clean session, then perform the ForceAuthn=true reauthentication.
        return 2;
    }
    @Override public String browserInstructionsEn() {
        return "Start with no target session and log in for the control. SAMLscope then runs omitted and explicit false controls. For ForceAuthn=true, complete the target's fresh authentication action; SAMLscope compares the correlated AuthnStatement timestamps. Do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    @Override
    public CaseStep start(CaseContext context) {
        var configuration = configuration(context.runId());
        if (!configuration.preconditionsSatisfied()) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "force_authn_preconditions_unmet", "idp.force-authn.preconditions-unmet"));
        }
        return await(context, configuration, 0, null, List.of());
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var index = number(state, "stage_index");
        if (index < 0 || index >= STAGES.size()
                || !STAGES.get(index).id().equals(state.data().get("stage"))) {
            return new CaseStep.Finish(CaseOutcome.notVerified(
                    "force_authn_scenario_changed", "idp.force-authn.scenario-changed"));
        }
        if (event instanceof CaseEvent.TimedOut || event instanceof CaseEvent.InboundUnavailable
                || event instanceof CaseEvent.Aborted) {
            return new CaseStep.Finish(notVerified(
                    state, index == 0 ? "control_failed" : "force_authn_response_unavailable"));
        }
        if (!(event instanceof CaseEvent.InboundMessage inbound)
                || !"transcript".equals(inbound.evidence().kind())) {
            throw new IllegalArgumentException("ForceAuthn scenario requires Transcript inbound evidence");
        }
        var observation = observe(
                inbound.decodedSaml(), text(state, "expected_response_correlation"),
                decryptionKeys.keyFor(context.runId()).orElse(null));
        var evidence = strings(state, "evidence");
        evidence.add(inbound.evidence().reference());
        if (observation == null || !observation.success()) {
            return new CaseStep.Finish(notVerified(
                    state, index < STAGES.size() - 1 ? "control_failed" : "force_authn_not_conclusive",
                    evidence));
        }
        var baseline = state.data().get("baseline_authn_instant") instanceof String value ? value : null;
        if (index == 0) baseline = observation.authnInstant().toString();
        if (index == STAGES.size() - 1) {
            var requestInstant = Instant.parse(text(state, "request_issue_instant"));
            var baselineInstant = Instant.parse(text(state, "baseline_authn_instant"));
            // A timestamp with omitted fractional digits cannot establish ordering within
            // that reported unit. This is measurement ambiguity, not clock-skew tolerance.
            var reportedUpperBound = observation.authnInstant().plusNanos(observation.precisionNanos());
            if (!observation.authnInstant().isAfter(requestInstant)
                    && reportedUpperBound.isAfter(requestInstant)) {
                return new CaseStep.Finish(notVerified(
                        state, "force_authn_timestamp_precision_insufficient", evidence));
            }
            if (observation.authnInstant().isBefore(requestInstant)
                    || !observation.authnInstant().isAfter(baselineInstant)) {
                return new CaseStep.Finish(new CaseOutcome(
                        Outcome.VIOLATED, null, "force_authn_existing_context_reused",
                        "idp.force-authn.existing-context-reused", refs(evidence), Map.of(
                                "baseline_authn_instant", baselineInstant.toString(),
                                "request_issue_instant", requestInstant.toString(),
                                "force_authn_authn_instant", observation.authnInstant().toString())));
            }
            return new CaseStep.Finish(new CaseOutcome(
                    Outcome.SATISFIED, null, "force_authn_fresh_authentication_observed",
                    "idp.force-authn.satisfied", refs(evidence), Map.of(
                            "baseline_authn_instant", baselineInstant.toString(),
                            "force_authn_authn_instant", observation.authnInstant().toString())));
        }
        return await(context, configuration(context.runId()), index + 1, baseline, evidence);
    }

    private CaseStep.AwaitInbound await(
            CaseContext context,
            IdpErrorProbeConfiguration configuration,
            int index,
            String baseline,
            List<String> evidence) {
        var stage = STAGES.get(index);
        var phase = "await-force-authn-" + stage.id();
        var actionId = ActionIds.derive(context.runId(), id, phase, 0);
        var requestId = "_" + actionId;
        var issueInstant = context.clock().instant();
        var payload = requests.build(
                stage.probe(), requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                configuration.registeredAcs(), issueInstant);
        var data = new java.util.LinkedHashMap<String, Object>();
        data.put("stage_index", index);
        data.put("stage", stage.id());
        data.put("expected_response_correlation", requestId);
        data.put("request_issue_instant", issueInstant.toString());
        data.put("evidence", List.copyOf(evidence));
        if (baseline != null) data.put("baseline_authn_instant", baseline);
        return new CaseStep.AwaitInbound(
                new CaseState(phase, Map.copyOf(data)),
                List.of(new OutboundAction(
                        actionId, OutboundKind.AUTHN_REQUEST, payload,
                        configuration.ssoEndpoint(), false)),
                new InboundMatcher("saml-response", Map.of("ScenarioActionId", actionId)),
                configuration.responseTimeout());
    }

    private Observation observe(byte[] responseXml, String requestId, java.security.PrivateKey decryptionKey) {
        try {
            var root = SecureXml.parse(responseXml).getDocumentElement();
            if (!PROTOCOL.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName())
                    || !requestId.equals(root.getAttribute("InResponseTo"))) return null;
            var codes = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
            if (codes.getLength() == 0
                    || !SUCCESS.equals(((Element) codes.item(0)).getAttribute("Value"))) {
                return new Observation(false, null, 0);
            }
            // The target may encrypt the assertion to the Run key; decrypt before reading the
            // AuthnStatement, otherwise an encrypted success would look like a missing control.
            var assertions = new java.util.ArrayList<Element>();
            for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
                if (!(node instanceof Element element) || !ASSERTION.equals(element.getNamespaceURI())) continue;
                if ("Assertion".equals(element.getLocalName())) {
                    assertions.add(element);
                } else if ("EncryptedAssertion".equals(element.getLocalName()) && decryptionKey != null) {
                    try {
                        assertions.add(new com.samlscope.saml.crypto.SamlXmlDecrypter().decrypt(element, decryptionKey));
                    } catch (RuntimeException unreadable) {
                        // Leave the encrypted form; another assertion may still be readable.
                    }
                }
            }
            for (var assertion : assertions) {
                var statements = assertion.getElementsByTagNameNS(ASSERTION, "AuthnStatement");
                if (statements.getLength() == 0) continue;
                var value = ((Element) statements.item(0)).getAttribute("AuthnInstant");
                var dot = value.indexOf('.');
                var digits = 0;
                if (dot >= 0) {
                    for (var i = dot + 1; i < value.length() && Character.isDigit(value.charAt(i)); i++) digits++;
                }
                long precisionNanos = 1;
                for (var i = Math.min(digits, 9); i < 9; i++) precisionNanos *= 10;
                return new Observation(true, Instant.parse(value), precisionNanos);
            }
            return null;
        } catch (SamlException | DateTimeParseException invalid) {
            return null;
        }
    }

    private IdpErrorProbeConfiguration configuration(String runId) {
        return java.util.Objects.requireNonNull(configurations.apply(runId));
    }

    private CaseOutcome notVerified(CaseState state, String reason) {
        return notVerified(state, reason, strings(state, "evidence"));
    }

    private CaseOutcome notVerified(CaseState state, String reason, List<String> evidence) {
        return new CaseOutcome(
                Outcome.NOT_VERIFIED, reason, reason, "idp.force-authn.inconclusive",
                refs(evidence), Map.of("stage", String.valueOf(state.data().get("stage"))));
    }

    private static int number(CaseState state, String key) {
        if (!(state.data().get(key) instanceof Number value)) {
            throw new IllegalStateException("Missing numeric state: " + key);
        }
        return value.intValue();
    }

    private static String text(CaseState state, String key) {
        if (!(state.data().get(key) instanceof String value) || value.isBlank()) {
            throw new IllegalStateException("Missing text state: " + key);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static ArrayList<String> strings(CaseState state, String key) {
        if (!(state.data().get(key) instanceof List<?> value)
                || value.stream().anyMatch(item -> !(item instanceof String))) {
            throw new IllegalStateException("Missing evidence state");
        }
        return new ArrayList<>((List<String>) value);
    }

    private static List<EvidenceRef> refs(List<String> evidence) {
        return evidence.stream().map(value -> new EvidenceRef("transcript", value)).toList();
    }

    private record Stage(String id, Probe probe) {}
    private record Observation(boolean success, Instant authnInstant, long precisionNanos) {}
}
