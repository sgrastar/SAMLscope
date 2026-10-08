package com.samlscope.runner.cases;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.scenario.FixtureObservation;
import com.samlscope.runner.scenario.FixtureScenarioTestCase;
import com.samlscope.runner.scenario.ScenarioFixture;
import com.samlscope.saml.normal.SamlAcsSelectionRequestFactory;
import com.samlscope.saml.normal.SamlAcsSelectionRequestFactory.Fixture;
import com.samlscope.saml.normal.SamlException;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.binding.RedirectSignatureVerifier;
import org.w3c.dom.Element;

/** Browser-assisted, Transcript-judged ACS selection scenarios for a target IdP. */
public final class IdpAcsSelectionScenarioTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt {
    public static final String INDEX_CASE = "IIP-IDP12-a-idp-01";
    public static final String URL_CASE = "IIP-IDP12-e-idp-01";
    public static final String BINDING_CASE = "IIP-IDP12-f-idp-01";
    public static final String UNREGISTERED_URL_CASE = "IIP-IDP12-b-idp-01";
    public static final String UNKNOWN_INDEX_CASE = "IIP-IDP12-d-idp-01";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final List<String> BINDING_FIXTURES = List.of(
            "post-binding-control", "redirect-binding", "unsupported-binding");
    private final String id;
    private final java.util.function.Function<String, IdpErrorProbeConfiguration> configurations;
    private final SamlAcsSelectionRequestFactory requests;
    private final TranscriptContentReader content;
    private final Function<String, Optional<String>> targetEntityIds;
    private final Function<String, List<X509Certificate>> targetSigningCertificates;
    private final SamlPlanCredentialsProvider suiteCredentials;
    private final Function<String,byte[]> artifactMetadata;

    public IdpAcsSelectionScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations) {
        this(id, configurations, new SamlAcsSelectionRequestFactory(), null,
                ignored -> Optional.empty(), ignored -> List.of(), ignored -> Optional.empty());
    }

    public IdpAcsSelectionScenarioTestCase(String id,
            Function<String, IdpErrorProbeConfiguration> configurations,
            TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetSigningCertificates,
            SamlPlanCredentialsProvider suiteCredentials) {
        this(id, configurations, new SamlAcsSelectionRequestFactory(), content,
                targetEntityIds, targetSigningCertificates, suiteCredentials);
    }

    IdpAcsSelectionScenarioTestCase(
            String id,
            java.util.function.Function<String, IdpErrorProbeConfiguration> configurations,
            SamlAcsSelectionRequestFactory requests) {
        this(id, configurations, requests, null,
                ignored -> Optional.empty(), ignored -> List.of(), ignored -> Optional.empty());
    }

    private IdpAcsSelectionScenarioTestCase(String id,
            Function<String, IdpErrorProbeConfiguration> configurations,
            SamlAcsSelectionRequestFactory requests, TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetSigningCertificates,
            SamlPlanCredentialsProvider suiteCredentials) {
        this(id,configurations,requests,content,targetEntityIds,targetSigningCertificates,suiteCredentials,null);
    }
    private IdpAcsSelectionScenarioTestCase(String id,
            Function<String, IdpErrorProbeConfiguration> configurations,
            SamlAcsSelectionRequestFactory requests, TranscriptContentReader content,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetSigningCertificates,
            SamlPlanCredentialsProvider suiteCredentials,Function<String,byte[]> artifactMetadata) {
        this.id = requireSupported(id);
        this.configurations = java.util.Objects.requireNonNull(configurations, "configurations");
        this.requests = java.util.Objects.requireNonNull(requests, "requests");
        this.content = content;
        this.targetEntityIds = java.util.Objects.requireNonNull(targetEntityIds);
        this.targetSigningCertificates = java.util.Objects.requireNonNull(targetSigningCertificates);
        this.suiteCredentials = java.util.Objects.requireNonNull(suiteCredentials);
        this.artifactMetadata = artifactMetadata;
    }
    public IdpAcsSelectionScenarioTestCase withArtifactInput(TranscriptContentReader content,Function<String,byte[]> metadata) {
        return new IdpAcsSelectionScenarioTestCase(id,configurations,requests,Objects.requireNonNull(content),
                targetEntityIds,targetSigningCertificates,suiteCredentials,Objects.requireNonNull(metadata));
    }
    public TestCase artifactScenario(Function<String,Optional<com.samlscope.core.caseexec.OutboxEntry>> outbox) {
        if(!BINDING_CASE.equals(id) || artifactMetadata == null || content == null) return this;
        return new ArtifactProtocolBindingTestCase(this,configurations,
                new ArtifactBindingEvidence(content,artifactMetadata,suiteCredentials,targetEntityIds),outbox,content);
    }

    private FixtureScenarioTestCase scenario(CaseContext context) {
        var runId = context.runId();
        var configuration = java.util.Objects.requireNonNull(configurations.apply(runId));
        var defaultAcs = configuration.registeredAcs();
        var secondaryAcs = defaultAcs.resolve("1");
        var otherEntityAcs = SamlAcsSelectionRequestFactory.otherEntityAcs(defaultAcs);
        var fixtures = switch (id) {
            case INDEX_CASE -> List.<ScenarioFixture>of(
                    fixture("default-control", Fixture.DEFAULT, Expectation.SUCCESS_AT_DEFAULT,
                            configuration, defaultAcs, secondaryAcs),
                    fixture("non-default-index", Fixture.INDEX_ONE, Expectation.SUCCESS_AT_SECONDARY,
                            configuration, defaultAcs, secondaryAcs));
            case URL_CASE -> List.<ScenarioFixture>of(
                    fixture("default-control", Fixture.DEFAULT, Expectation.SUCCESS_AT_DEFAULT,
                            configuration, defaultAcs, secondaryAcs),
                    fixture("non-default-url", Fixture.URL_ONE, Expectation.SUCCESS_AT_SECONDARY,
                            configuration, defaultAcs, secondaryAcs));
            case BINDING_CASE -> List.<ScenarioFixture>of(
                    bindingFixture(BINDING_FIXTURES.get(0), Fixture.POST_BINDING, configuration, context),
                    bindingFixture(BINDING_FIXTURES.get(1), Fixture.REDIRECT_BINDING, configuration, context),
                    bindingFixture(BINDING_FIXTURES.get(2), Fixture.UNSUPPORTED_BINDING, configuration, context));
            case UNREGISTERED_URL_CASE -> List.<ScenarioFixture>of(
                    fixture("registered-url-signed-control", Fixture.URL_ONE,
                            Expectation.SUCCESS_AT_SECONDARY,
                            OutboundAction.RequestSigning.REQUIRE, null,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("registered-url-unsigned", Fixture.URL_ONE,
                            Expectation.SUCCESS_AT_SECONDARY,
                            OutboundAction.RequestSigning.OMIT_FOR_IDP12_B, null,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("unregistered-url-signed", Fixture.UNKNOWN_URL,
                            Expectation.UNREGISTERED_URL_SAFE,
                            OutboundAction.RequestSigning.REQUIRE, defaultAcs.resolve("999999"),
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("unregistered-url-unsigned", Fixture.UNKNOWN_URL,
                            Expectation.UNREGISTERED_URL_SAFE,
                            OutboundAction.RequestSigning.OMIT_FOR_IDP12_B, defaultAcs.resolve("999999"),
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("other-entity-url-signed", Fixture.OTHER_ENTITY_URL,
                            Expectation.ASSOCIATED_OR_LOCAL_REJECTION,
                            OutboundAction.RequestSigning.REQUIRE, otherEntityAcs,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("other-entity-url-unsigned", Fixture.OTHER_ENTITY_URL,
                            Expectation.ASSOCIATED_OR_LOCAL_REJECTION,
                            OutboundAction.RequestSigning.OMIT_FOR_IDP12_B, otherEntityAcs,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("unknown-index-signed", Fixture.UNKNOWN_INDEX,
                            Expectation.ASSOCIATED_OR_LOCAL_REJECTION,
                            OutboundAction.RequestSigning.REQUIRE, null,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs),
                    fixture("unknown-index-unsigned", Fixture.UNKNOWN_INDEX,
                            Expectation.ASSOCIATED_OR_LOCAL_REJECTION,
                            OutboundAction.RequestSigning.OMIT_FOR_IDP12_B, null,
                            configuration, defaultAcs, secondaryAcs, otherEntityAcs));
            case UNKNOWN_INDEX_CASE -> List.<ScenarioFixture>of(
                    fixture("unknown-index", Fixture.UNKNOWN_INDEX, Expectation.DEFAULT_OR_ERROR,
                            configuration, defaultAcs, secondaryAcs));
            default -> throw new IllegalStateException("Unsupported ACS scenario");
        };
        return new FixtureScenarioTestCase(
                id, TargetRole.IDP, fixtures,
                ignored -> configuration.userAgentAvailable() && configuration.acceptableResponseLocationKnown()
                        && (!BINDING_CASE.equals(id) || (bindingConfigured(runId)
                                && context.transcript() != null && context.interaction().allowBrowserSteps())),
                new FixtureScenarioTestCase.Vocabulary(
                        "acs_probe_preconditions_unmet", "idp.acs-probe.preconditions-unmet",
                        "delivery_or_response_unknown", "idp.acs-probe.delivery-unknown",
                        "scenario_aborted", "idp.acs-probe.aborted",
                        "case.idp.acs-probe.control-failed",
                        "idp_acs_selection_violated", "case.idp.acs-probe.violated",
                        "idp_acs_selection_not_conclusive", "idp.acs-probe.inconclusive",
                        "case.idp.acs-probe.inconclusive",
                        "idp.acs-probe.satisfied", "case.idp.acs-probe.satisfied"));
    }

    @Override public String id() { return id; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public CaseStep start(CaseContext context) { return scenario(context).start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!BINDING_CASE.equals(id)) return scenario(context).resume(context, state, event);
        if (!validBindingState(context, state)) {
            return new CaseStep.Finish(bindingNotVerified("idp.binding-probe.state-incompatible", Map.of()));
        }
        if (event instanceof CaseEvent.InboundMessage inbound) {
            try {
                var response = bindingResponse(context, String.valueOf(state.data().get("fixture_id")),
                        String.valueOf(state.data().get("expected_response_correlation")));
                require(response.entry().id().equals(inbound.evidence().reference())
                        && "transcript".equals(inbound.evidence().kind())
                        && Arrays.equals(response.bytes(), inbound.decodedSaml()));
            } catch (Exception invalid) {
                return new CaseStep.Finish(bindingNotVerified("idp.binding-probe.observation-unbound", Map.of()));
            }
        }
        var step = scenario(context).resume(context, state, event);
        if (step instanceof CaseStep.Finish finish && finish.outcome().outcome() == Outcome.SATISFIED) {
            // Positive evidence B does not waive the conditional Artifact variant. This observer
            // does not own or prove the Artifact runtime chain; the opt-in wrapper verifies it.
            // An absent endpoint or an operator's flag cannot establish non-applicability.
            return new CaseStep.Finish(bindingNotVerified("idp.binding-probe.artifact-applicability-unproven",
                    Map.of("completed_binding_fixtures", BINDING_FIXTURES,
                            "positive_protocol_binding_evidence", "B",
                            "artifact_applicability", "unknown",
                            "artifact_switch_variant", "not_executed",
                            "artifact_resolution_transport", "requires_artifact_runtime_evidence"),
                    bindingEvidence(context, finish.outcome().evidence())));
        }
        if (step instanceof CaseStep.Finish finish) {
            var previous = finish.outcome();
            var details = new java.util.LinkedHashMap<>(previous.details());
            details.put("artifact_applicability", "unknown");
            details.put("artifact_switch_variant", "not_executed");
            // Every B-only conclusion leaves the independent Artifact runtime proof outstanding.
            details.put("artifact_resolution_transport", "requires_artifact_runtime_evidence");
            return new CaseStep.Finish(new CaseOutcome(previous.outcome(), previous.notVerifiedReason(),
                    previous.reasonCode(), previous.reasonMessageKey(), bindingEvidence(context, previous.evidence()), details));
        }
        return step;
    }
    @Override public String browserInstructionsEn() {
        return "Start the ACS selection scenario and log in when the target asks. SAMLscope compares the correlated "
                + "Response destination and Status with the requested index, URL, or binding; do not enter a verdict.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }

    private ScenarioFixture bindingFixture(String fixtureId, Fixture fixture,
            IdpErrorProbeConfiguration configuration, CaseContext context) {
        return new ScenarioFixture() {
            @Override public String id() { return fixtureId; }
            @Override public Prepared prepare(CaseContext current, String actionId) {
                var requestId = "_" + actionId;
                var payload = requests.build(fixture, requestId, configuration.ssoEndpoint(),
                        configuration.suiteIssuer(), configuration.registeredAcs(),
                        configuration.registeredAcs().resolve("1"), current.clock().instant());
                return new Prepared(new OutboundAction(actionId, OutboundKind.AUTHN_REQUEST,
                        payload, configuration.ssoEndpoint(), false,
                        OutboundAction.RequestSigning.REQUIRE), requestId);
            }
            @Override public FixtureObservation observe(String requestId, byte[] responseXml) {
                try {
                    var response = bindingResponse(context, fixtureId, requestId);
                    require(Arrays.equals(responseXml, response.bytes()));
                    var status = single(single(response.xml(), PROTOCOL, "Status"),
                            PROTOCOL, "StatusCode").getAttribute("Value");
                    if (fixture == Fixture.POST_BINDING) {
                        if (!SUCCESS.equals(status) || !"POST".equals(response.entry().method())) {
                            return FixtureObservation.CONTROL_FAILED;
                        }
                        var assertions = MetadataAlgorithmEvidence.children(response.xml(), ASSERTION, "Assertion");
                        var encrypted = MetadataAlgorithmEvidence.children(response.xml(), ASSERTION, "EncryptedAssertion");
                        return assertions.size() + encrypted.size() > 0
                                ? FixtureObservation.SATISFIED : FixtureObservation.CONTROL_FAILED;
                    }
                    if ("GET".equals(response.entry().method())) return FixtureObservation.VIOLATED;
                    // Default-only producers and silent POST fallback have no detection power.
                    // A missing optional UnsupportedBinding subcode is never a violation.
                    return List.of("urn:oasis:names:tc:SAML:2.0:status:Requester",
                                    "urn:oasis:names:tc:SAML:2.0:status:Responder",
                                    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch").contains(status)
                            ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                } catch (Exception invalid) { return FixtureObservation.NOT_VERIFIED; }
            }
            @Override public Duration timeout() { return configuration.responseTimeout(); }
            @Override public String definitionKey() {
                return fixtureId + "|" + fixture.name() + "|binding-originals-v1|"
                        + configuration.ssoEndpoint() + "|" + configuration.registeredAcs();
            }
        };
    }

    private boolean bindingConfigured(String runId) {
        try {
            return content != null && targetEntityIds.apply(runId).filter(s -> !s.isBlank()).isPresent()
                    && !targetSigningCertificates.apply(runId).isEmpty()
                    && suiteCredentials.credentialsFor(runId).isPresent();
        } catch (Exception unavailable) { return false; }
    }

    private boolean validBindingState(CaseContext context, CaseState state) {
        if (state == null || !BINDING_CASE.equals(state.data().get("scenario_case_id"))) return false;
        var fixture = state.data().get("fixture_id");
        var index = state.data().get("fixture_index");
        var attempt = state.data().get("fixture_attempt");
        var n = stateInteger(index);
        var retry = stateInteger(attempt);
        if (n == null || retry == null || n < 0 || n >= BINDING_FIXTURES.size()
                || retry < 0 || retry > 3 || !BINDING_FIXTURES.get(n).equals(fixture)) return false;
        if (!(state.data().get("scenario_fingerprint") instanceof String fingerprint)
                || !fingerprint.matches("sha256:[a-f0-9]{64}")) return false;
        for (var key : List.of("violations", "violating_action_ids", "unverifiable", "evidence")) {
            if (!(state.data().get(key) instanceof List<?> values)
                    || values.stream().anyMatch(value -> !(value instanceof String))) return false;
        }
        var phase = "await-fixture-" + fixture + (retry == 0 ? "" : "-retry-" + retry);
        return phase.equals(state.phase()) && ("_" + ActionIds.derive(context.runId(), id, phase, 0))
                .equals(state.data().get("expected_response_correlation"));
    }

    private static Integer stateInteger(Object value) {
        if (value instanceof Integer integer) return integer;
        if (value instanceof Long integer && integer >= Integer.MIN_VALUE && integer <= Integer.MAX_VALUE) {
            return integer.intValue();
        }
        return null;
    }

    private record BindingResponse(TranscriptEntry entry, Element xml, byte[] bytes) {}

    private BindingResponse bindingResponse(CaseContext context, String fixture, String requestId) {
        require(bindingConfigured(context.runId()) && context.transcript() != null
                && BINDING_FIXTURES.contains(fixture));
        var entries = context.transcript().listBounded(context.runId(), 10000);
        var seen = new HashSet<String>();
        for (var entry : entries) require(context.runId().equals(entry.runId()) && seen.add(entry.id()));
        String actionId = null;
        for (int retry = 0; retry <= 3; retry++) {
            var phase = "await-fixture-" + fixture + (retry == 0 ? "" : "-retry-" + retry);
            var candidate = ActionIds.derive(context.runId(), id, phase, 0);
            if (("_" + candidate).equals(requestId)) actionId = candidate;
        }
        require(actionId != null);
        var action = actionId;
        var sent = entries.stream().filter(entry -> entry.direction() == Direction.OUTBOUND
                && action.equals(entry.correlationId())).toList();
        require(sent.size() == 1);
        var request = sent.getFirst();
        var config = configurations.apply(context.runId());
        var summary = request.samlSummary();
        require(id.equals(summary.get("scenario_case_id")) && fixture.equals(summary.get("fixture_id"))
                && action.equals(summary.get("action_id")) && "AuthnRequest".equals(summary.get("type"))
                && Boolean.TRUE.equals(summary.get("active_probe"))
                && "POST".equals(request.method()) && formContentType(request.contentType())
                && config.ssoEndpoint().toString().equals(request.url()) && request.rawQuery() == null);
        var requestRaw = decoded(request);
        var requestXml = SecureXml.parse(requestRaw).getDocumentElement();
        require(PROTOCOL.equals(requestXml.getNamespaceURI()) && "AuthnRequest".equals(requestXml.getLocalName())
                && requestId.equals(requestXml.getAttribute("ID")) && "2.0".equals(requestXml.getAttribute("Version"))
                && config.ssoEndpoint().toString().equals(requestXml.getAttribute("Destination"))
                && config.registeredAcs().toString().equals(requestXml.getAttribute("AssertionConsumerServiceURL"))
                && !requestXml.hasAttribute("AssertionConsumerServiceIndex")
                && config.suiteIssuer().equals(single(requestXml, ASSERTION, "Issuer").getTextContent())
                && bindingFor(fixture).equals(requestXml.getAttribute("ProtocolBinding"))
                && !Instant.parse(requestXml.getAttribute("IssueInstant")).isAfter(request.timestamp())
                && new XmlSignatureVerifier().hasValidEnvelopedSignature(requestXml,
                        suiteCredentials.credentialsFor(context.runId()).orElseThrow().certificate()));
        var allowed = java.util.Set.of("ID", "Version", "IssueInstant", "Destination",
                "AssertionConsumerServiceURL", "ProtocolBinding");
        var attributes = requestXml.getAttributes();
        for (int index = 0; index < attributes.getLength(); index++) {
            var attribute = attributes.item(index);
            if (javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())) continue;
            require(attribute.getNamespaceURI() == null && allowed.contains(attribute.getNodeName()));
        }
        require(MetadataAlgorithmEvidence.children(requestXml, DS, "Signature").size() == 1);
        var issuer = single(requestXml, ASSERTION, "Issuer");
        for (int index = 0; index < issuer.getAttributes().getLength(); index++) {
            require(javax.xml.XMLConstants.XMLNS_ATTRIBUTE_NS_URI
                    .equals(issuer.getAttributes().item(index).getNamespaceURI()));
        }
        for (var node = issuer.getFirstChild(); node != null; node = node.getNextSibling()) {
            require(!(node instanceof Element));
        }
        for (var node = requestXml.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element child) require(
                    (ASSERTION.equals(child.getNamespaceURI()) && "Issuer".equals(child.getLocalName()))
                    || (DS.equals(child.getNamespaceURI()) && "Signature".equals(child.getLocalName())));
        }
        var replies = new ArrayList<BindingResponse>();
        for (var entry : entries) {
            if (entry.direction() != Direction.INBOUND || entry.decodedSamlRef() == null
                    || entry.decodedSamlBytes() == 0 || !"Response".equals(entry.samlSummary().get("type"))) continue;
            var raw = decoded(entry);
            var xml = SecureXml.parse(raw).getDocumentElement();
            if (!requestId.equals(xml.getAttribute("InResponseTo"))) continue;
            require(PROTOCOL.equals(xml.getNamespaceURI()) && "Response".equals(xml.getLocalName())
                    && "2.0".equals(xml.getAttribute("Version")) && !xml.getAttribute("ID").isBlank()
                    && java.util.Set.of(action, requestId).contains(entry.correlationId())
                    && !entry.timestamp().isBefore(request.timestamp())
                    && config.registeredAcs().toString().equals(xml.getAttribute("Destination"))
                    && receivedAtRegisteredAcs(entry, config.registeredAcs())
                    && targetEntityIds.apply(context.runId()).orElseThrow()
                            .equals(single(xml, ASSERTION, "Issuer").getTextContent()));
            var status = single(single(xml, PROTOCOL, "Status"), PROTOCOL, "StatusCode").getAttribute("Value");
            var certificates = targetSigningCertificates.apply(context.runId());
            var xmlSigned = certificates.stream().anyMatch(cert ->
                    new XmlSignatureVerifier().hasValidEnvelopedSignature(xml, cert));
            if ("POST".equals(entry.method())) {
                require(formContentType(entry.contentType()) && entry.rawQuery() == null);
                var assertionSigned = SUCCESS.equals(status) && MetadataAlgorithmEvidence.children(xml, ASSERTION, "Assertion")
                        .stream().anyMatch(assertion -> targetEntityIds.apply(context.runId()).orElseThrow()
                                .equals(single(assertion, ASSERTION, "Issuer").getTextContent())
                                && certificates.stream().anyMatch(cert ->
                                        new XmlSignatureVerifier().hasValidEnvelopedSignature(assertion, cert)));
                require(xmlSigned || assertionSigned);
            } else if ("GET".equals(entry.method())) {
                var redirect = new RedirectSignatureVerifier();
                require(entry.bodyBytes() == 0 && entry.rawQuery() != null
                        && redirect.matchesMessage(entry.rawQuery(), raw)
                        && (xmlSigned || certificates.stream().anyMatch(cert ->
                                redirect.isValidForMessage(entry.rawQuery(), cert, raw))));
            } else throw new IllegalArgumentException("Not a front-channel SAML Response");
            replies.add(new BindingResponse(entry, xml, raw));
        }
        require(replies.size() == 1);
        return replies.getFirst();
    }

    private byte[] decoded(TranscriptEntry entry) {
        require(entry.decodedSamlRef() != null && entry.decodedSamlBytes() > 0);
        var raw = content.readDecodedSaml(entry);
        require(raw != null && raw.length == entry.decodedSamlBytes());
        return raw;
    }

    private static String bindingFor(String fixture) {
        return switch (fixture) {
            case "post-binding-control" -> SamlAcsSelectionRequestFactory.POST;
            case "redirect-binding" -> SamlAcsSelectionRequestFactory.REDIRECT;
            case "unsupported-binding" -> SamlAcsSelectionRequestFactory.UNSUPPORTED;
            default -> throw new IllegalArgumentException("Unknown binding fixture");
        };
    }

    private static boolean formContentType(String value) {
        return value != null && "application/x-www-form-urlencoded"
                .equals(value.split(";", 2)[0].trim().toLowerCase(java.util.Locale.ROOT));
    }

    private static boolean receivedAtRegisteredAcs(TranscriptEntry entry, URI acs) {
        try {
            if ("POST".equals(entry.method())) return acs.toString().equals(entry.url());
            if (!"GET".equals(entry.method()) || acs.getRawQuery() != null) return false;
            var actual = URI.create(entry.url());
            var queryAt = entry.url().indexOf('?');
            return queryAt > 0 && acs.equals(URI.create(entry.url().substring(0, queryAt)))
                    && actual.getRawFragment() == null && actual.getRawUserInfo() == null
                    && java.util.Objects.equals(actual.getRawQuery(), entry.rawQuery());
        } catch (Exception invalid) { return false; }
    }

    private static Element single(Element parent, String namespace, String localName) {
        var values = MetadataAlgorithmEvidence.children(parent, namespace, localName);
        require(values.size() == 1);
        return values.getFirst();
    }

    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Binding original evidence unavailable or inconsistent");
    }

    private static CaseOutcome bindingNotVerified(String reason, Map<String, Object> details) {
        return bindingNotVerified(reason, details, List.of());
    }

    private static CaseOutcome bindingNotVerified(String reason, Map<String, Object> details, List<EvidenceRef> evidence) {
        return new CaseOutcome(Outcome.NOT_VERIFIED, reason, reason,
                "idp.acs-probe.inconclusive", evidence, details);
    }

    private static List<EvidenceRef> bindingEvidence(CaseContext context, List<EvidenceRef> responseEvidence) {
        var result = new java.util.LinkedHashSet<EvidenceRef>();
        var entries = context.transcript().listBounded(context.runId(), 10000);
        for (var reference : responseEvidence) {
            var replies = entries.stream().filter(entry -> entry.id().equals(reference.reference())).toList();
            if (replies.size() == 1) {
                var correlation = replies.getFirst().correlationId();
                if (correlation != null && correlation.startsWith("_")) {
                    var action = correlation.substring(1);
                    entries.stream().filter(entry -> entry.direction() == Direction.OUTBOUND
                            && action.equals(entry.correlationId())).forEach(entry ->
                            result.add(new EvidenceRef("transcript", entry.id())));
                }
            }
            result.add(reference);
        }
        return List.copyOf(result);
    }

    /** Replays every B control from originals after the conditional Artifact leg; never caches outcomes. */
    boolean stillProvesBindingB(CaseContext context, List<EvidenceRef> admitted) {
        try {
            var ids = new HashSet<String>();
            for (var ref : admitted) require("transcript".equals(ref.kind()) && ids.add(ref.reference()));
            require(ids.size() == 6);
            var actual = new HashSet<String>();
            var entries = context.transcript().listBounded(context.runId(),10000);
            var configuration = configurations.apply(context.runId());
            for (var fixture : BINDING_FIXTURES) {
                var requests = entries.stream().filter(entry -> ids.contains(entry.id())
                        && entry.direction() == Direction.OUTBOUND
                        && fixture.equals(entry.samlSummary().get("fixture_id"))).toList();
                require(requests.size() == 1);
                var request = requests.getFirst(); var requestId = SecureXml.parse(decoded(request))
                        .getDocumentElement().getAttribute("ID");
                var response = bindingResponse(context,fixture,requestId);
                var input = switch(fixture) {
                    case "post-binding-control" -> Fixture.POST_BINDING;
                    case "redirect-binding" -> Fixture.REDIRECT_BINDING;
                    default -> Fixture.UNSUPPORTED_BINDING;
                };
                require(bindingFixture(fixture,input,configuration,context).observe(requestId,response.bytes())
                        == FixtureObservation.SATISFIED);
                actual.add(request.id());actual.add(response.entry().id());
            }
            return actual.equals(ids);
        } catch(Exception incomplete) { return false; }
    }


    private ScenarioFixture fixture(
            String fixtureId,
            Fixture fixture,
            Expectation expectation,
            IdpErrorProbeConfiguration configuration,
            URI defaultAcs,
            URI secondaryAcs) {
        return fixture(
                fixtureId, fixture, expectation, OutboundAction.RequestSigning.PLAN_DEFAULT, null,
                configuration, defaultAcs, secondaryAcs,
                SamlAcsSelectionRequestFactory.otherEntityAcs(defaultAcs));
    }

    private ScenarioFixture fixture(
            String fixtureId,
            Fixture fixture,
            Expectation expectation,
            OutboundAction.RequestSigning requestSigning,
            URI hostileAcs,
            IdpErrorProbeConfiguration configuration,
            URI defaultAcs,
            URI secondaryAcs,
            URI otherEntityAcs) {
        return new AcsFixture(
                fixtureId, fixture, expectation, requestSigning, hostileAcs,
                configuration, defaultAcs, secondaryAcs, otherEntityAcs, requests);
    }

    private enum Expectation {
        SUCCESS_AT_DEFAULT,
        SUCCESS_AT_SECONDARY,
        DEFAULT_OR_ERROR,
        UNREGISTERED_URL_SAFE,
        ASSOCIATED_OR_LOCAL_REJECTION
    }

    private record AcsFixture(
            String id,
            Fixture fixture,
            Expectation expectation,
            OutboundAction.RequestSigning requestSigning,
            URI hostileAcs,
            IdpErrorProbeConfiguration configuration,
            URI defaultAcs,
            URI secondaryAcs,
            URI otherEntityAcs,
            SamlAcsSelectionRequestFactory requests) implements ScenarioFixture {
        @Override
        public Prepared prepare(CaseContext context, String actionId) {
            var requestId = "_" + actionId;
            var payload = requests.build(
                    fixture, requestId, configuration.ssoEndpoint(), configuration.suiteIssuer(),
                    defaultAcs, secondaryAcs, otherEntityAcs, context.clock().instant());
            return new Prepared(new OutboundAction(
                    actionId, OutboundKind.AUTHN_REQUEST, payload,
                    configuration.ssoEndpoint(), false, requestSigning), requestId);
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
                var success = SUCCESS.equals(((Element) statusCodes.item(0)).getAttribute("Value"));
                var responseDestination = root.getAttribute("Destination");
                var expectedDestination = expectation == Expectation.SUCCESS_AT_SECONDARY
                        ? secondaryAcs : defaultAcs;
                var destinationMatches = expectedDestination.toString().equals(responseDestination);
                var associatedDestination = defaultAcs.toString().equals(responseDestination)
                        || secondaryAcs.toString().equals(responseDestination);
                return switch (expectation) {
                    case SUCCESS_AT_DEFAULT -> success && destinationMatches
                            ? FixtureObservation.SATISFIED
                            : FixtureObservation.CONTROL_FAILED;
                    case SUCCESS_AT_SECONDARY -> success && destinationMatches
                            ? FixtureObservation.SATISFIED : FixtureObservation.VIOLATED;
                    // IDP12.d records two permitted MAY choices. A response to another
                    // location is judged by IDP12.b, not a fabricated negative oracle here.
                    case DEFAULT_OR_ERROR -> (success && destinationMatches)
                            || List.of("urn:oasis:names:tc:SAML:2.0:status:Requester",
                                    "urn:oasis:names:tc:SAML:2.0:status:Responder",
                                    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")
                                    .contains(((Element) statusCodes.item(0)).getAttribute("Value"))
                            ? FixtureObservation.SATISFIED : FixtureObservation.NOT_VERIFIED;
                    case UNREGISTERED_URL_SAFE -> associatedDestination
                            && (!success || defaultAcs.toString().equals(responseDestination))
                            ? FixtureObservation.SATISFIED : FixtureObservation.VIOLATED;
                    case ASSOCIATED_OR_LOCAL_REJECTION -> associatedDestination
                            ? FixtureObservation.SATISFIED : FixtureObservation.VIOLATED;
                };
            } catch (SamlException malformed) {
                return FixtureObservation.NOT_VERIFIED;
            }
        }

        @Override
        public FixtureObservation observeBrowser(
                String requestId, int httpStatus, String url, String body) {
            if (httpStatus < 400) return FixtureObservation.NOT_VERIFIED;
            URI landing;
            try {
                landing = URI.create(url);
            } catch (IllegalArgumentException invalid) {
                return FixtureObservation.NOT_VERIFIED;
            }
            if (hostileAcs != null && sameLocation(landing, hostileAcs)) {
                return FixtureObservation.VIOLATED;
            }
            if (!sameOrigin(landing, configuration.ssoEndpoint())) {
                return FixtureObservation.NOT_VERIFIED;
            }
            return switch (expectation) {
                case SUCCESS_AT_DEFAULT, SUCCESS_AT_SECONDARY -> FixtureObservation.CONTROL_FAILED;
                case DEFAULT_OR_ERROR -> FixtureObservation.NOT_VERIFIED;
                case UNREGISTERED_URL_SAFE,
                        ASSOCIATED_OR_LOCAL_REJECTION -> FixtureObservation.SATISFIED;
            };
        }

        @Override public Duration timeout() { return configuration.responseTimeout(); }
        @Override public String definitionKey() {
            return String.join("|", id, fixture.name(), expectation.name(),
                    requestSigning.name(), String.valueOf(hostileAcs),
                    configuration.ssoEndpoint().toString(), defaultAcs.toString(), secondaryAcs.toString(),
                    otherEntityAcs.toString());
        }

        private static boolean sameOrigin(URI left, URI right) {
            return left.isAbsolute() && right.isAbsolute()
                    && java.util.Objects.equals(lower(left.getScheme()), lower(right.getScheme()))
                    && java.util.Objects.equals(lower(left.getHost()), lower(right.getHost()))
                    && effectivePort(left) == effectivePort(right);
        }

        private static boolean sameLocation(URI left, URI right) {
            return sameOrigin(left, right)
                    && java.util.Objects.equals(left.getPath(), right.getPath());
        }

        private static int effectivePort(URI value) {
            if (value.getPort() >= 0) return value.getPort();
            return "https".equalsIgnoreCase(value.getScheme()) ? 443 : 80;
        }

        private static String lower(String value) {
            return value == null ? null : value.toLowerCase(java.util.Locale.ROOT);
        }
    }

    private static String requireSupported(String value) {
        if (!List.of(INDEX_CASE, URL_CASE, BINDING_CASE, UNREGISTERED_URL_CASE, UNKNOWN_INDEX_CASE)
                .contains(value)) {
            throw new IllegalArgumentException("Unsupported ACS selection case: " + value);
        }
        return value;
    }
}
