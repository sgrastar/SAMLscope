package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.function.Function;

/** Execute the policy inputs; native state and policy evidence is required to judge causation. */
public final class TransientAllowCreateScenarioTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE = "IIP-SSO01-fp-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String REASON = "idp.transient-allow-create.unproven";
    private static final List<String> REQUIRED = List.of("six-policy-exchanges", "same-native-policy",
            "native-transient-association-path", "positive-and-negative-controls", "configuration-restoration");
    private final Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlDecryptionKeyProvider keys;
    private final SimpleSamlPhpTransientAllowCreateEvidence nativeEvidence;
    private final KeycloakTransientAllowCreateEvidence keycloakEvidence;
    private final ShibbolethTransientAllowCreateEvidence shibbolethEvidence;

    public TransientAllowCreateScenarioTestCase(Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider keys) {
        this(configurations, keys, null, null, null);
    }
    private TransientAllowCreateScenarioTestCase(Function<String, IdpErrorProbeConfiguration> configurations,
            SamlDecryptionKeyProvider keys, SimpleSamlPhpTransientAllowCreateEvidence evidence,
            KeycloakTransientAllowCreateEvidence keycloakEvidence,
            ShibbolethTransientAllowCreateEvidence shibbolethEvidence) {
        this.configurations = Objects.requireNonNull(configurations);
        this.keys = Objects.requireNonNull(keys);
        this.nativeEvidence = evidence;
        this.keycloakEvidence = keycloakEvidence;
        this.shibbolethEvidence = shibbolethEvidence;
    }
    TransientAllowCreateScenarioTestCase withNativeEvidence(Path directory, TranscriptContentReader content,
            Function<String, byte[]> metadata) {
        return new TransientAllowCreateScenarioTestCase(configurations, keys,
                new SimpleSamlPhpTransientAllowCreateEvidence(directory, content, metadata, keys),
                new KeycloakTransientAllowCreateEvidence(directory, content, metadata),
                new ShibbolethTransientAllowCreateEvidence(directory, content, metadata, keys));
    }
    private Optional<CaseOutcome> observed(CaseContext context) {
        boolean ssp = nativeEvidence != null && nativeEvidence.exists(context.runId());
        boolean keycloak = keycloakEvidence != null && keycloakEvidence.exists(context.runId());
        boolean shibboleth = shibbolethEvidence != null && shibbolethEvidence.exists(context.runId());
        int owners = (ssp ? 1 : 0) + (keycloak ? 1 : 0) + (shibboleth ? 1 : 0);
        if (owners == 0) return Optional.empty();
        if (owners != 1) return Optional.of(unproven());
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try {
            var proof = ssp ? nativeEvidence.evaluate(context)
                    : keycloak ? keycloakEvidence.evaluate(context)
                    : shibbolethEvidence.evaluate(context);
            return Optional.of(proof.orElseGet(TransientAllowCreateScenarioTestCase::unproven));
        }
        catch (RuntimeException incomplete) { return Optional.of(unproven()); }
    }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("transient_allow_create_native_context_unproven", REASON);
    }
    private FixtureScenarioTestCase scenario(String run) {
        var configuration = Objects.requireNonNull(configurations.apply(run));
        var fixtures = new ArrayList<ScenarioFixture>();
        for (boolean explicit : List.of(true, false)) {
            for (String value : List.of("true", "false", "omitted")) {
                String id = (explicit ? "transient" : "implicit-transient") + "-allow-create-" + value;
                fixtures.add(new PolicyFixture(id, new SamlNameIdPolicyRequestFactory.Policy(true,
                        explicit ? SamlNameIdPolicyRequestFactory.TRANSIENT : null, null,
                        value.equals("omitted") ? null : Boolean.valueOf(value)), configuration));
            }
        }
        return new FixtureScenarioTestCase(CASE, TargetRole.IDP, fixtures,
                ignored -> configuration.preconditionsSatisfied(),
                new FixtureScenarioTestCase.Vocabulary(
                        "transient_allow_create_preconditions_unmet", "idp.transient-allow-create.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.transient-allow-create.delivery-unknown",
                        "scenario_aborted", "idp.transient-allow-create.aborted",
                        "idp.transient-allow-create.control-failed", "transient_allow_create_violation",
                        "idp.transient-allow-create.violation", "native_policy_context_unproven", REASON,
                        REASON, "transient_allow_create_inputs_observed", "idp.transient-allow-create.inputs-observed"));
    }
    @Override public String id() { return CASE; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) {
        return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> scenario(context.runId()).start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var proof = observed(context);
        if (proof.isPresent()) return new CaseStep.Finish(proof.get());
        if (state == null || "await-browser".equals(state.phase())) return new CaseStep.Finish(
                CaseOutcome.notVerified("scenario_upgrade_requires_new_run", REASON));
        var step = scenario(context.runId()).resume(context, state, event);
        if (!(step instanceof CaseStep.Finish finish) || finish.outcome().outcome() == Outcome.NOT_VERIFIED) return step;
        // Six matching protocol messages alone cannot establish absence of persistent state,
        // nor establish that AllowCreate alone caused an observed difference.
        var result = finish.outcome();
        return new CaseStep.Finish(new CaseOutcome(Outcome.NOT_VERIFIED,
                "transient_allow_create_native_context_unproven", REASON, REASON, result.evidence(), result.details()));
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) {
        // This path must never invoke the scenario or create another outbound action.
        return observed(context).orElseGet(TransientAllowCreateScenarioTestCase::unproven);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var proof = observed(context);boolean ready = proof.isPresent() && conclusive(proof.get());
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(),
                proof.map(CaseOutcome::details).orElse(Map.of()));
    }
    private static boolean conclusive(CaseOutcome outcome) {
        return Set.of(Outcome.SATISFIED, Outcome.SATISFIED_WITH_NOTE, Outcome.VIOLATED).contains(outcome.outcome());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of(REASON, "browser.nameid.transient-allow-create-native-unproven",
                        "browser.oracle-unavailable", "browser_fixture_partial").contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return observed(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }
    @Override public String browserInstructionsEn() {
        return "Log in once and keep the same target session for all six NameIDPolicy requests. "
                + "The Suite compares AllowCreate under the fixed native policy and verifies transient association behavior.";
    }
    @Override public String instructionsEn(CaseState state) {
        return state != null && "await-browser".equals(state.phase())
                ? "Start a new Run to execute the six protocol-driven NameIDPolicy inputs."
                : browserInstructionsEn();
    }

    private record PolicyFixture(String id, SamlNameIdPolicyRequestFactory.Policy policy,
            IdpErrorProbeConfiguration configuration) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context, String actionId) {
            String requestId = "_" + actionId;
            byte[] xml = new SamlNameIdPolicyRequestFactory().build(requestId, configuration.ssoEndpoint(),
                    configuration.suiteIssuer(), configuration.registeredAcs(), context.clock().instant(), policy);
            return new Prepared(new OutboundAction(actionId, OutboundKind.AUTHN_REQUEST, xml,
                    configuration.ssoEndpoint(), false), requestId);
        }
        @Override public FixtureObservation observe(String requestId, byte[] response) {
            try {
                var root = SecureXml.parse(response).getDocumentElement();
                if (!PROTOCOL.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName())
                        || !requestId.equals(root.getAttribute("InResponseTo"))) return FixtureObservation.NOT_VERIFIED;
                var status = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
                if (status.getLength() == 0) return FixtureObservation.NOT_VERIFIED;
                if (!"urn:oasis:names:tc:SAML:2.0:status:Success".equals(((org.w3c.dom.Element) status.item(0)).getAttribute("Value")))
                    return FixtureObservation.NOT_VERIFIED;
                return root.getElementsByTagNameNS(ASSERTION, "Assertion").getLength()
                        + root.getElementsByTagNameNS(ASSERTION, "EncryptedAssertion").getLength() > 0
                        ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
            } catch (RuntimeException malformed) { return FixtureObservation.NOT_VERIFIED; }
        }
        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", id, String.valueOf(policy.format()), String.valueOf(policy.allowCreate()),
                    configuration.ssoEndpoint().toString(), configuration.suiteIssuer(), configuration.registeredAcs().toString());
        }
    }
}
