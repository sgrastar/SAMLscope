package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;
import org.w3c.dom.Element;

class IdpErrorAssertionRecordedEvidenceTestCaseTest {
    static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS", PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    static final URI SSO = URI.create("https://idp.example/sso"), ACS = URI.create("https://suite.example/acs");
    static final String ENTITY = "https://idp.example/idp";
    @TempDir Path folder;
    PlanCredentials suite, target;
    List<TranscriptEntry> entries = new ArrayList<>();
    Map<String, byte[]> bytes = new HashMap<>();
    IdpErrorAssertionScenarioTestCase delegate;
    IdpErrorAssertionRecordedEvidenceTestCase test;
    final IdpErrorProbeConfiguration configuration = new IdpErrorProbeConfiguration(
            SSO, "https://suite.example/sp", ACS, Duration.ofMinutes(2), true, true, true);

    @BeforeEach void setup() {
        var keys = new FilePlanKeyStore(folder, Clock.fixed(NOW, ZoneOffset.UTC));
        suite = keys.getOrCreate(PLAN); target = keys.getOrCreate(PLAN, "target");
        delegate = new IdpErrorAssertionScenarioTestCase(run -> configuration);
        test = new IdpErrorAssertionRecordedEvidenceTestCase(delegate, run -> configuration,
                entry -> bytes.get(entry.id()), run -> Optional.of(suite),
                run -> Optional.of(ENTITY), run -> List.of(target.certificate()));
    }

    CaseContext context(boolean required, boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                new TestPlan.Parameters(180, 300, "", required ? TestPlan.RequestSigningMode.REQUIRED : TestPlan.RequestSigningMode.OPTIONAL),
                new TestPlan.Interaction(true, false), Reachability.CONFIRMED, new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return entries; }
                    public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new UnsupportedOperationException(); }
                }, complete);
    }

    TranscriptEntry request(String fixture, boolean signed) {
        var index = IdpErrorAssertionRecordedEvidenceTestCase.REQUIRED.indexOf(fixture);
        var action = ActionIds.derive(RUN, test.id(), "await-fixture-" + fixture, 0);
        byte[] raw = new SamlErrorProbeRequestFactory().build(SamlErrorProbeRequestFactory.Probe.valueOf(
                fixture.toUpperCase(Locale.ROOT).replace('-', '_')), "_" + action, SSO,
                configuration.suiteIssuer(), ACS, NOW.plusSeconds(index * 2));
        if (signed) raw = IdpErrorAssertionRecordedEvidenceTestCase.signRequest(raw, suite);
        var entry = new TranscriptEntry("tx_request_" + fixture, RUN, Direction.OUTBOUND, NOW.plusSeconds(index * 2),
                action, "POST", SSO.toString(), null, Map.of(), null, 0, "transcripts/" + RUN + "/tx_request_" + fixture + ".saml.xml",
                raw.length, "application/xml", null, Map.of("type", "AuthnRequest", "scenario_case_id", test.id(),
                        "fixture_id", fixture, "action_id", action));
        entries.add(entry); bytes.put(entry.id(), raw); return entry;
    }

    TranscriptEntry response(TranscriptEntry request, String status, String assertionKind, boolean signed) {
        var document = SecureXml.newDocument();
        var root = document.createElementNS(IdpErrorAssertionRecordedEvidenceTestCase.P, "samlp:Response");
        root.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:samlp", IdpErrorAssertionRecordedEvidenceTestCase.P);
        root.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", IdpErrorAssertionRecordedEvidenceTestCase.A);
        root.setAttribute("Version", "2.0"); root.setAttribute("ID", "_reply_" + request.id());
        root.setAttribute("InResponseTo", "_" + request.correlationId()); root.setAttribute("Destination", ACS.toString());
        document.appendChild(root);
        append(root, IdpErrorAssertionRecordedEvidenceTestCase.A, "saml:Issuer").setTextContent(ENTITY);
        var code = append(append(root, IdpErrorAssertionRecordedEvidenceTestCase.P, "samlp:Status"),
                IdpErrorAssertionRecordedEvidenceTestCase.P, "samlp:StatusCode");
        code.setAttribute("Value", IdpErrorAssertionRecordedEvidenceTestCase.STATUS + status);
        if (assertionKind != null) {
            var assertion = append(root, IdpErrorAssertionRecordedEvidenceTestCase.A, "saml:" + assertionKind);
            if (assertionKind.equals("Assertion")) {
                assertion.setAttribute("ID", "_assertion_" + request.id());
                append(assertion, IdpErrorAssertionRecordedEvidenceTestCase.A, "saml:Issuer").setTextContent(ENTITY);
            }
        }
        if (signed) new XmlSigner().sign(root, target, null);
        byte[] raw = SecureXml.serialize(document);
        var entry = new TranscriptEntry("tx_response_" + request.id(), RUN, Direction.INBOUND, request.timestamp().plusSeconds(1),
                "_" + request.correlationId(), "POST", ACS.toString(), 200, Map.of(), null, 0, "transcripts/" + RUN + "/tx_response_" + request.id() + ".saml.xml",
                raw.length, "application/xml", null, Map.of("type", "Response"));
        entries.add(entry); bytes.put(entry.id(), raw); return entry;
    }

    static Element append(Element parent, String namespace, String name) {
        var child = parent.getOwnerDocument().createElementNS(namespace, name); parent.appendChild(child); return child;
    }

    void full(boolean signedRequests, boolean signedResponses) {
        for (String fixture : IdpErrorAssertionRecordedEvidenceTestCase.REQUIRED) {
            var request = request(fixture, signedRequests);
            response(request, fixture.equals("baseline-success") ? "Success" : "Responder",
                    fixture.equals("baseline-success") ? "Assertion" : null, signedResponses);
        }
    }
    CaseOutcome outcome(boolean required) { return assertInstanceOf(CaseStep.Finish.class,
            test.resume(context(required, true), null, new CaseEvent.TranscriptReady())).outcome(); }

    @Test void completeOriginalSignedMatrixIsSatisfiedAndReevaluationIsPure() {
        full(true, true); var old = CaseOutcome.notVerified("old", "old");
        var result = test.reevaluateRecordedEvidence(context(true, true), old).orElseThrow();
        assertEquals(Outcome.SATISFIED, result.outcome()); assertEquals(8, result.evidence().size());
        assertEquals(false, result.details().get("same_authentication_session_asserted"));
        assertTrue(test.evidenceStatus(context(true, true)).ready());
        assertEquals(8, entries.size()); assertTrue(test.reevaluateRecordedEvidence(context(true, false), old).isEmpty());
        assertTrue(test.reevaluateRecordedEvidence(context(true, true), result).isEmpty());
    }

    @Test void optionalUnsignedRequestsAndResponsesRemainPermittedRatherThanAddingANewSignatureObligation() {
        full(false, false); assertEquals(Outcome.SATISFIED, outcome(false).outcome());
        assertEquals(Outcome.NOT_VERIFIED, outcome(true).outcome());
    }

    @Test void threeTriggersMustBeActualErrorsAndPassiveOnlyDoesNotSatisfyTheMatrix() {
        full(false, false);
        for (String fixture : List.of("unknown-nameid-format", "unrecognized-subject")) {
            var original = entries.stream().filter(entry -> entry.id().equals("tx_response_tx_request_" + fixture)).findFirst().orElseThrow();
            entries.remove(original);
            response(entries.stream().filter(entry -> entry.id().equals("tx_request_" + fixture)).findFirst().orElseThrow(), "Success", "Assertion", false);
        }
        assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
    }

    @Test void missingFixtureOrAResponseCannotSatisfyAndNoControlCannotViolate() {
        full(false, false); var original = List.copyOf(entries);
        for (String fixture : IdpErrorAssertionRecordedEvidenceTestCase.REQUIRED) {
            entries.clear(); entries.addAll(original); entries.removeIf(entry -> entry.id().equals("tx_request_" + fixture));
            assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome(), fixture);
        }
        entries.clear(); entries.addAll(original); entries.removeIf(entry -> entry.id().equals("tx_response_tx_request_baseline-success"));
        var bad = entries.stream().filter(entry -> entry.id().equals("tx_response_tx_request_unknown-nameid-format")).findFirst().orElseThrow();
        entries.remove(bad); response(entries.stream().filter(entry -> entry.id().equals("tx_request_unknown-nameid-format")).findFirst().orElseThrow(), "Responder", "Assertion", false);
        assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
    }

    @Test void plainAndEncryptedAssertionOnAnyActualErrorAreDetected() {
        for (String kind : List.of("Assertion", "EncryptedAssertion")) {
            entries.clear(); bytes.clear(); full(false, false);
            var bad = entries.stream().filter(entry -> entry.id().equals("tx_response_tx_request_unknown-nameid-format")).findFirst().orElseThrow();
            entries.remove(bad); response(entries.stream().filter(entry -> entry.id().equals("tx_request_unknown-nameid-format")).findFirst().orElseThrow(), "Responder", kind, false);
            assertEquals(Outcome.VIOLATED, outcome(false).outcome(), kind);
        }
    }

    @Test void foreignRunActionCaseAndDifferentOperationWindowAreRejected() {
        full(false, false); var original = List.copyOf(entries);
        var request = entries.get(2);
        for (String field : List.of("run", "action", "case", "time")) {
            entries.clear(); entries.addAll(original);
            var summary = new LinkedHashMap<>(request.samlSummary());
            if (field.equals("case")) summary.put("scenario_case_id", "IIP-SSO01-d-idp-01");
            entries.set(2, copy(request, field.equals("run") ? "run_other" : request.runId(),
                    field.equals("action") ? "action_other" : request.correlationId(),
                    field.equals("time") ? NOW.minusSeconds(1) : request.timestamp(), summary));
            assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome(), field);
        }
    }

    @Test void duplicateResponseContradictoryBrowserLandingAndEmptyBodyDoNotProvideErrorEvidence() {
        full(false, false); var original = List.copyOf(entries);
        entries.add(entries.get(3)); assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
        entries.clear(); entries.addAll(original);
        var request = entries.get(2);
        var browser = new TranscriptEntry("tx_browser", RUN, Direction.INBOUND, request.timestamp().plusSeconds(1), request.correlationId(),
                "BROWSER", SSO.toString(), 500, Map.of(), "browser.body", 0, null, 0, null, null,
                Map.of("type", "BrowserResponseObservation", "http_status", 500));
        entries.add(browser); assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
        entries.removeIf(entry -> entry.id().equals("tx_response_tx_request_unknown-nameid-format"));
        assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
        assertFalse(test.evidenceStatus(context(false, true)).ready());
    }

    @Test void corruptSignedOriginalsAndWrongIssuerOrDestinationCannotBePromoted() {
        full(true, true); var originalBytes = new HashMap<>(bytes);
        for (String field : List.of("signature", "issuer", "destination", "request-shape")) {
            bytes.clear(); bytes.putAll(originalBytes);
            var entry = entries.get(field.equals("request-shape") ? 2 : 3);
            var document = SecureXml.parse(bytes.get(entry.id())); var root = document.getDocumentElement();
            if (field.equals("signature")) {
                var signature = root.getElementsByTagNameNS(IdpErrorAssertionRecordedEvidenceTestCase.DS, "SignatureValue").item(0);
                var value = signature.getTextContent();
                signature.setTextContent((value.charAt(0) == 'A' ? 'B' : 'A') + value.substring(1));
            }
            if (field.equals("issuer")) root.getElementsByTagNameNS(IdpErrorAssertionRecordedEvidenceTestCase.A, "Issuer").item(0).setTextContent("https://idp.examplf/idp");
            if (field.equals("destination")) root.setAttribute("Destination", "https://suith.example/acs");
            if (field.equals("request-shape")) root.setAttribute("IsPassive", "true");
            bytes.put(entry.id(), SecureXml.serialize(document));
            assertEquals(Outcome.NOT_VERIFIED, outcome(true).outcome(), field);
        }
    }

    @Test void fabricatedDelegateEventsCannotKeepAnUnbackedSatisfiedOutcome() {
        var context = context(false, false);
        var step = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context));
        for (String fixture : IdpErrorAssertionRecordedEvidenceTestCase.REQUIRED) {
            String correlation = String.valueOf(step.next().data().get("expected_response_correlation"));
            String assertion = fixture.equals("baseline-success") ? "<saml:Assertion/>" : "";
            byte[] xml = ("<samlp:Response xmlns:samlp=\"" + IdpErrorAssertionRecordedEvidenceTestCase.P
                    + "\" xmlns:saml=\"" + IdpErrorAssertionRecordedEvidenceTestCase.A + "\" InResponseTo=\"" + correlation
                    + "\"><samlp:Status><samlp:StatusCode Value=\"" + IdpErrorAssertionRecordedEvidenceTestCase.STATUS
                    + (fixture.equals("baseline-success") ? "Success" : "Responder") + "\"/></samlp:Status>" + assertion + "</samlp:Response>")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            var next = test.resume(context, step.next(), new CaseEvent.InboundMessage(xml, new EvidenceRef("transcript", "not-an-original")));
            if (fixture.equals("passive-without-session")) assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class, next).outcome().outcome());
            else step = assertInstanceOf(CaseStep.AwaitInbound.class, next);
        }
    }

    @Test void anotherValidlySignedProbeCannotBorrowTheUnknownFormatAction() {
        full(true, true);
        var request = entries.get(2);
        var document = SecureXml.parse(bytes.get(request.id())); var root = document.getDocumentElement();
        var signatures = MetadataAlgorithmEvidence.children(root, IdpErrorAssertionRecordedEvidenceTestCase.DS, "Signature");
        signatures.forEach(root::removeChild);
        ((Element) root.getElementsByTagNameNS(IdpErrorAssertionRecordedEvidenceTestCase.P, "NameIDPolicy").item(0))
                .setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        byte[] different = IdpErrorAssertionRecordedEvidenceTestCase.signRequest(SecureXml.serialize(document), suite);
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(different).getDocumentElement(), suite.certificate()));
        bytes.put(request.id(), different);
        entries.set(2, new TranscriptEntry(request.id(), request.runId(), request.direction(), request.timestamp(), request.correlationId(),
                request.method(), request.url(), request.status(), request.headers(), request.bodyRef(), request.bodyBytes(), request.decodedSamlRef(),
                different.length, request.contentType(), request.rawQuery(), request.samlSummary()));
        assertEquals(Outcome.NOT_VERIFIED, outcome(true).outcome());
    }

    @Test void foreignOriginalFileCannotBeRelabeledByItsTranscriptEntry() {
        full(false, false); var entry = entries.get(3);
        entries.set(3, new TranscriptEntry(entry.id(), entry.runId(), entry.direction(), entry.timestamp(), entry.correlationId(),
                entry.method(), entry.url(), entry.status(), entry.headers(), entry.bodyRef(), entry.bodyBytes(),
                "transcripts/run_other/" + entry.id() + ".saml.xml", entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(), entry.samlSummary()));
        assertEquals(Outcome.NOT_VERIFIED, outcome(false).outcome());
    }

    static TranscriptEntry copy(TranscriptEntry entry, String run, String correlation, Instant at, Map<String, Object> summary) {
        return new TranscriptEntry(entry.id(), run, entry.direction(), at, correlation, entry.method(), entry.url(), entry.status(), entry.headers(),
                entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(), entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(), summary);
    }
}
