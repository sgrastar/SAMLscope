package com.samlscope.runner.cases;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/**
 * Original-backed evaluation of the complete approved SSO01.f scenario.
 *
 * Each original stays in its owning Run/case/action. A successful control and
 * all three error paths are necessary for satisfaction; a HTTP landing or a
 * successful abnormal request never substitutes for an error Response. Session
 * cookies are deliberately unavailable to this reader: it does not assert that
 * independently recorded requests share an IdP authentication session.
 */
public final class IdpErrorAssertionRecordedEvidenceTestCase
        implements TestCase, BrowserFrontChannelScenario, BrowserPrompt,
        ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String STATUS = "urn:oasis:names:tc:SAML:2.0:status:";
    static final List<String> REQUIRED = List.of("baseline-success", "unknown-nameid-format",
            "unrecognized-subject", "passive-without-session");
    private final IdpErrorAssertionScenarioTestCase delegate;
    private final Function<String, IdpErrorProbeConfiguration> configurations;
    private final TranscriptContentReader content;
    private final SamlPlanCredentialsProvider credentials;
    private final Function<String, Optional<String>> targetEntityIds;
    private final Function<String, List<X509Certificate>> targetCertificates;

    public IdpErrorAssertionRecordedEvidenceTestCase(
            IdpErrorAssertionScenarioTestCase delegate,
            Function<String, IdpErrorProbeConfiguration> configurations,
            TranscriptContentReader content,
            SamlPlanCredentialsProvider credentials,
            Function<String, Optional<String>> targetEntityIds,
            Function<String, List<X509Certificate>> targetCertificates) {
        this.delegate = Objects.requireNonNull(delegate);
        if (!IdpErrorAssertionScenarioTestCase.ERROR_ASSERTION_CASE.equals(delegate.id())) {
            throw new IllegalArgumentException("Only the full SSO01.f case has this evidence contract");
        }
        this.configurations = Objects.requireNonNull(configurations);
        this.content = Objects.requireNonNull(content);
        this.credentials = Objects.requireNonNull(credentials);
        this.targetEntityIds = Objects.requireNonNull(targetEntityIds);
        this.targetCertificates = Objects.requireNonNull(targetCertificates);
    }

    @Override public String id() { return delegate.id(); }
    @Override public TargetRole role() { return delegate.role(); }
    @Override public boolean requiresFreshSession(CaseState state) { return delegate.requiresFreshSession(state); }
    @Override public boolean plansFreshSessionBoundary() { return delegate.plansFreshSessionBoundary(); }
    @Override public int plannedDeliberateActions() { return delegate.plannedDeliberateActions(); }
    @Override public Binding outboundBinding(CaseState state) { return delegate.outboundBinding(state); }
    @Override public String browserInstructionsEn() { return delegate.browserInstructionsEn(); }
    @Override public String instructionsEn(CaseState state) { return delegate.instructionsEn(state); }

    @Override public CaseStep start(CaseContext context) {
        var existing = read(context);
        if (existing.outcome().isPresent()) return new CaseStep.Finish(existing.outcome().get());
        return delegate.start(context);
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TranscriptReady) return finishRead(context);
        // Keep the existing deterministic fixture progression. At its terminal
        // step, the original graph, rather than a caller-supplied event, owns the
        // conclusion. Fake events cannot preserve a satisfied delegate outcome.
        var step = delegate.resume(context, state, event);
        return step instanceof CaseStep.Finish ? finishRead(context) : step;
    }

    private CaseStep finishRead(CaseContext context) {
        var observed = read(context);
        return new CaseStep.Finish(observed.outcome().orElseGet(() -> new CaseOutcome(
                Outcome.NOT_VERIFIED, "error_assertion_originals_incomplete",
                "idp.error-assertion.inconclusive", "case.idp.error-assertion.inconclusive",
                List.of(), observed.details())));
    }

    private record Request(TranscriptEntry entry, Element xml, byte[] bytes) {}
    private record Observation(Optional<CaseOutcome> outcome, List<String> completed, Map<String, Object> details) {}

    private Observation read(CaseContext context) {
        var completed = new ArrayList<String>();
        var evidence = new LinkedHashSet<EvidenceRef>();
        var violations = new ArrayList<String>();
        var unverifiable = new ArrayList<String>();
        try {
            var entries = context.transcript().list(context.runId());
            var ids = new LinkedHashSet<String>();
            for (var entry : entries) require(context.runId().equals(entry.runId()) && ids.add(entry.id()));
            var configuration = configurations.apply(context.runId());
            require(configuration != null);
            var entity = targetEntityIds.apply(context.runId()).orElseThrow();
            var certificates = targetCertificates.apply(context.runId());
            require(certificates != null);
            Instant precedingResponse = null;
            for (String fixture : REQUIRED) {
                var request = request(context, entries, fixture, configuration);
                // One ordered scenario operation, rather than a bag of messages
                // copied from independent or overlapping processing epochs.
                if (precedingResponse != null) require(!request.entry().timestamp().isBefore(precedingResponse));
                var responses = new ArrayList<TranscriptEntry>();
                for (var entry : entries) {
                    if (entry.direction() != Direction.INBOUND || entry.decodedSamlRef() == null
                            || entry.decodedSamlBytes() <= 0 || !"Response".equals(entry.samlSummary().get("type"))) continue;
                    var xml = SecureXml.parse(decoded(entry)).getDocumentElement();
                    if (P.equals(xml.getNamespaceURI()) && "Response".equals(xml.getLocalName())
                            && request.xml().getAttribute("ID").equals(xml.getAttribute("InResponseTo"))) responses.add(entry);
                }
                require(responses.size() <= 1);
                if (responses.isEmpty()) {
                    require(!fixture.equals("baseline-success"));
                    unverifiable.add(fixture + ":response-unavailable-or-ambiguous");
                    // All required requests must still be present. A partial
                    // positive cannot claim the rest of the error matrix.
                    continue;
                }
                var entry = responses.getFirst();
                require(entries.stream().noneMatch(other -> other.direction() == Direction.INBOUND
                        && "BROWSER".equals(other.method()) && request.entry().correlationId().equals(other.correlationId())));
                require(request.xml().getAttribute("ID").equals(entry.correlationId())
                        && !entry.timestamp().isBefore(request.entry().timestamp())
                        && configuration.registeredAcs().toString().equals(entry.url()));
                var response = SecureXml.parse(decoded(entry)).getDocumentElement();
                require("2.0".equals(response.getAttribute("Version")) && !response.getAttribute("ID").isBlank()
                        && configuration.registeredAcs().toString().equals(response.getAttribute("Destination"))
                        && entity.equals(single(response, A, "Issuer").getTextContent()));
                validatePresentSignature(response, certificates);
                var top = single(single(response, P, "Status"), P, "StatusCode").getAttribute("Value");
                require(Set.of(STATUS + "Success", STATUS + "Requester", STATUS + "Responder",
                        STATUS + "VersionMismatch").contains(top));
                // Count every plain/encrypted assertion, including a misplaced
                // nested assertion. An error must not hide one outside the usual
                // direct-child extraction path.
                int assertions = response.getElementsByTagNameNS(A, "Assertion").getLength()
                        + response.getElementsByTagNameNS(A, "EncryptedAssertion").getLength();
                boolean success = (STATUS + "Success").equals(top);
                if (fixture.equals("baseline-success")) {
                    require(success && assertions > 0);
                    for (var assertion : MetadataAlgorithmEvidence.children(response, A, "Assertion")) {
                        require(entity.equals(single(assertion, A, "Issuer").getTextContent()));
                        validatePresentSignature(assertion, certificates);
                    }
                } else if (success) {
                    unverifiable.add(fixture + ":error-response-not-observed");
                } else if (assertions > 0) {
                    violations.add(fixture);
                }
                precedingResponse = entry.timestamp();
                completed.add(fixture);
                evidence.add(new EvidenceRef("transcript", request.entry().id()));
                evidence.add(new EvidenceRef("transcript", entry.id()));
            }
            var details = new LinkedHashMap<String, Object>();
            details.put("required_fixtures", REQUIRED);
            details.put("completed_fixtures", List.copyOf(completed));
            details.put("unverifiable_fixtures", List.copyOf(unverifiable));
            details.put("violating_fixtures", List.copyOf(violations));
            details.put("original_backed", true);
            details.put("same_authentication_session_asserted", false);
            details.put("operator_verdict_requested", false);
            // A counterexample retains the scenario engine's failure semantics;
            // satisfaction still requires every approved error Response.
            var outcome = violations.isEmpty()
                    ? unverifiable.isEmpty() && completed.equals(REQUIRED) ? Outcome.SATISFIED : null
                    : Outcome.VIOLATED;
            return new Observation(outcome == null ? Optional.empty() : Optional.of(new CaseOutcome(
                    outcome, null, outcome == Outcome.VIOLATED ? "case.idp.error-assertion.violated" : "idp.error-assertion.satisfied",
                    outcome == Outcome.VIOLATED ? "case.idp.error-assertion.violated" : "case.idp.error-assertion.satisfied",
                    List.copyOf(evidence), Map.copyOf(details))), List.copyOf(completed), Map.copyOf(details));
        } catch (Exception invalid) {
            return new Observation(Optional.empty(), List.copyOf(completed), Map.of(
                    "required_fixtures", REQUIRED, "completed_fixtures", List.copyOf(completed),
                    "original_backed", false, "evidence_issue", "error-assertion-originals-unbound"));
        }
    }

    private Request request(CaseContext context, List<TranscriptEntry> entries, String fixture,
            IdpErrorProbeConfiguration configuration) {
        var action = ActionIds.derive(context.runId(), id(), "await-fixture-" + fixture, 0);
        var requests = entries.stream().filter(entry -> entry.direction() == Direction.OUTBOUND
                && action.equals(entry.correlationId())).toList();
        require(requests.size() == 1);
        var entry = requests.getFirst();
        require(action.equals(entry.samlSummary().get("action_id"))
                && id().equals(entry.samlSummary().get("scenario_case_id"))
                && fixture.equals(entry.samlSummary().get("fixture_id"))
                && "AuthnRequest".equals(entry.samlSummary().get("type"))
                && !entry.samlSummary().containsValue("UNKNOWN_DELIVERY")
                && configuration.ssoEndpoint().toString().equals(entry.url()));
        var original = decoded(entry);
        var xml = SecureXml.parse(original).getDocumentElement();
        require(P.equals(xml.getNamespaceURI()) && "AuthnRequest".equals(xml.getLocalName())
                && ("_" + action).equals(xml.getAttribute("ID")));
        var probe = SamlErrorProbeRequestFactory.Probe.valueOf(fixture.toUpperCase(java.util.Locale.ROOT).replace('-', '_'));
        var expected = new SamlErrorProbeRequestFactory().build(probe, xml.getAttribute("ID"),
                configuration.ssoEndpoint(), configuration.suiteIssuer(), configuration.registeredAcs(),
                Instant.parse(xml.getAttribute("IssueInstant")));
        boolean signed = xml.getElementsByTagNameNS(DS, "Signature").getLength() > 0;
        require(context.parameters() != null);
        if (signed) {
            var key = credentials.credentialsFor(context.runId()).orElseThrow();
            require(new XmlSignatureVerifier().hasValidEnvelopedSignature(xml, key.certificate()));
            expected = signRequest(expected, key);
        } else require(context.parameters().requestSigningMode() != TestPlan.RequestSigningMode.REQUIRED);
        require(Arrays.equals(original, expected));
        return new Request(entry, xml, original);
    }

    static byte[] signRequest(byte[] original, PlanCredentials key) {
        var document = SecureXml.parse(original);
        var root = document.getDocumentElement();
        Element before = null;
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && !(A.equals(element.getNamespaceURI()) && "Issuer".equals(element.getLocalName()))) {
                before = element;
                break;
            }
        }
        new XmlSigner().sign(root, key, before);
        return SecureXml.serialize(document);
    }

    private static void validatePresentSignature(Element element, List<X509Certificate> certificates) {
        if (MetadataAlgorithmEvidence.children(element, DS, "Signature").isEmpty()) return;
        require(certificates.stream().anyMatch(certificate -> new XmlSignatureVerifier().hasValidEnvelopedSignature(element, certificate)));
    }

    private byte[] decoded(TranscriptEntry entry) {
        require(entry.decodedSamlRef() != null && entry.decodedSamlBytes() > 0);
        require(("transcripts/" + entry.runId() + "/" + entry.id() + ".saml.xml").equals(entry.decodedSamlRef()));
        var bytes = content.readDecodedSaml(entry);
        require(bytes != null && bytes.length == entry.decodedSamlBytes());
        return bytes;
    }

    private static Element single(Element parent, String namespace, String localName) {
        var children = MetadataAlgorithmEvidence.children(parent, namespace, localName);
        require(children.size() == 1);
        return children.getFirst();
    }

    private static void require(boolean condition) { if (!condition) throw new IllegalArgumentException("Unbound error-response originals"); }

    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observed = read(context);
        return new EvidenceStatus(observed.outcome().isPresent(), REQUIRED, observed.completed(), observed.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return context.transcriptComplete() && supportsRecordedEvidenceReevaluation(previous)
                ? read(context).outcome().flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next)) : Optional.empty();
    }
}
