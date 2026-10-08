package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import com.samlscope.saml.binding.SignedRedirectEncoder;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

class IdpProtocolBindingScenarioTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String TARGET = "https://arbitrary-idp.example/entity";
    private static final URI SSO = URI.create("https://arbitrary-idp.example/sso");
    private static final URI ACS = URI.create("https://suite.example/p/test/sp/acs/0");
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    @TempDir Path folder;
    private PlanCredentials suite, target, foreign;
    private IdpAcsSelectionScenarioTestCase testCase;
    private final List<TranscriptEntry> entries = new ArrayList<>();
    private final Map<String, byte[]> originals = new HashMap<>();
    private final IdpErrorProbeConfiguration config = new IdpErrorProbeConfiguration(
            SSO, "https://suite.example/sp", ACS, Duration.ofMinutes(2), true, true, true);

    @BeforeEach void setup() throws Exception {
        var store = new FilePlanKeyStore(folder.resolve("keys"), Clock.fixed(NOW, ZoneOffset.UTC));
        suite = store.getOrCreate(PLAN);
        target = store.getOrCreate(PLAN, "target");
        foreign = store.getOrCreate(PLAN, "foreign");
        testCase = new IdpAcsSelectionScenarioTestCase(IdpAcsSelectionScenarioTestCase.BINDING_CASE,
                ignored -> config, entry -> originals.get(entry.id()), ignored -> Optional.of(TARGET),
                ignored -> List.of(target.certificate()), ignored -> Optional.of(suite));
    }

    @Test void matrixChangesProtocolBindingAndActionIdsAreStableAcrossRestarts() {
        var first = start();
        var repeat = start();
        assertArrayEquals(first.actions().getFirst().payload(), repeat.actions().getFirst().payload());
        assertEquals(first.actions().getFirst().actionId(), repeat.actions().getFirst().actionId());
        var xml = SecureXml.parse(first.actions().getFirst().payload()).getDocumentElement();
        assertEquals(SamlAcsSelectionRequestFactory.POST, xml.getAttribute("ProtocolBinding"));
        assertEquals(OutboundAction.RequestSigning.REQUIRE, first.actions().getFirst().requestSigning());
    }

    @Test void completeSignedBMatrixDoesNotPretendArtifactApplicabilityWasProven() {
        var step = start();
        for (var fixture : List.of("post-binding-control", "redirect-binding", "unsupported-binding")) {
            assertEquals(fixture, step.next().data().get("fixture_id"));
            var next = reply(step, fixture.equals("post-binding-control") ? "Success" : "Responder", "POST");
            if (fixture.equals("unsupported-binding")) {
                var outcome = assertInstanceOf(CaseStep.Finish.class, next).outcome();
                assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
                assertEquals("B", outcome.details().get("positive_protocol_binding_evidence"));
                assertEquals("unknown", outcome.details().get("artifact_applicability"));
                assertEquals("not_executed", outcome.details().get("artifact_switch_variant"));
                assertEquals("requires_artifact_runtime_evidence", outcome.details().get("artifact_resolution_transport"));
                assertEquals(6, outcome.evidence().size());
            } else step = assertInstanceOf(CaseStep.AwaitInbound.class, next);
        }
    }

    @Test void blanketRejectionFailsTheSuccessfulPostControl() {
        var outcome = assertInstanceOf(CaseStep.Finish.class, reply(start(), "Responder", "POST")).outcome();
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertEquals("control_failed", outcome.notVerifiedReason());
    }

    @Test void defaultOnlyOrSilentFallbackCannotProveBindingProcessing() {
        var step = start();
        for (int index = 0; index < 3; index++) {
            var next = reply(step, "Success", "POST");
            if (index < 2) step = assertInstanceOf(CaseStep.AwaitInbound.class, next);
            else {
                var outcome = assertInstanceOf(CaseStep.Finish.class, next).outcome();
                assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
                assertFalse(outcome.details().containsKey("positive_protocol_binding_evidence"));
            }
        }
    }

    @Test void realSignedRedirectResponseDetectsTheCoveredProhibitedBinding() {
        var redirect = assertInstanceOf(CaseStep.AwaitInbound.class, reply(start(), "Success", "POST"));
        var unsupported = assertInstanceOf(CaseStep.AwaitInbound.class, reply(redirect, "Responder", "GET"));
        var outcome = assertInstanceOf(CaseStep.Finish.class, reply(unsupported, "Responder", "POST")).outcome();
        assertEquals(Outcome.VIOLATED, outcome.outcome());
        assertEquals(List.of("redirect-binding"), outcome.details().get("violating_fixtures"));
    }

    @Test void recorderBackedHttp500AndSilenceNeverReplaceASamlStatus() {
        var redirect = assertInstanceOf(CaseStep.AwaitInbound.class, reply(start(), "Success", "POST"));
        var unsupported = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(context(true), redirect.next(),
                new CaseEvent.BrowserObservation(500, SSO.toString(), "failure",
                        new EvidenceRef("transcript", "browser-failure"))));
        var result = assertInstanceOf(CaseStep.Finish.class, testCase.resume(context(true), unsupported.next(),
                new CaseEvent.InboundUnavailable("no-saml-response"))).outcome();
        assertEquals(Outcome.NOT_VERIFIED, result.outcome());
        assertFalse(result.details().containsKey("positive_protocol_binding_evidence"));
    }

    @Test void noOriginalOrDifferentCallerBytesCannotAdvanceTheScenario() {
        var step = start();
        assertEquals("idp.binding-probe.observation-unbound", assertInstanceOf(CaseStep.Finish.class,
                testCase.resume(context(true), step.next(), new CaseEvent.InboundMessage(new byte[]{1},
                        new EvidenceRef("transcript", "fabricated")))).outcome().notVerifiedReason());
        var response = prepareReply(step, "Success", "POST");
        var raw = originals.get(response.id()).clone();
        raw[0] = 'x';
        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class,
                testCase.resume(context(true), step.next(), new CaseEvent.InboundMessage(raw,
                        new EvidenceRef("transcript", response.id())))).outcome().outcome());
    }

    @Test void duplicateForeignRunAndIncorrectRecorderCorrelationFailClosed() {
        for (var defect : List.of("duplicate", "foreign-run", "correlation")) {
            entries.clear(); originals.clear();
            var step = start(); var response = prepareReply(step, "Success", "POST");
            if (defect.equals("duplicate")) entries.add(response);
            else replace(response, defect.equals("foreign-run") ? "run_other" : RUN,
                    defect.equals("correlation") ? "_other-request" : response.correlationId(),
                    response.method(), response.url(), response.contentType(), response.rawQuery());
            assertEquals(Outcome.NOT_VERIFIED, finish(step, response).outcome().outcome(), defect);
        }
    }

    @Test void soapOrArtifactLikeTransportCannotBeMistakenForPostResponse() {
        for (var defect : List.of("SOAP", "HEAD", "SAMLart")) {
            entries.clear(); originals.clear();
            var step = start(); var response = prepareReply(step, "Success", "POST");
            replace(response, RUN, response.correlationId(), defect.equals("HEAD") ? "HEAD" : "POST",
                    response.url(), defect.equals("SOAP") ? "text/xml" : response.contentType(),
                    defect.equals("SAMLart") ? "SAMLart=opaque" : null);
            assertEquals(Outcome.NOT_VERIFIED, finish(step, response).outcome().outcome(), defect);
        }
    }

    @Test void signedRedirectQueryMustEncodeTheExactRecordedResponse() {
        var redirect = assertInstanceOf(CaseStep.AwaitInbound.class, reply(start(), "Success", "POST"));
        var response = prepareReply(redirect, "Responder", "GET");
        var changed = new String(originals.get(response.id()), StandardCharsets.UTF_8)
                .replace(":status:Responder", ":status:Requester").getBytes(StandardCharsets.UTF_8);
        originals.put(response.id(), changed);
        var mutated = new TranscriptEntry(response.id(), RUN, response.direction(), response.timestamp(),
                response.correlationId(), response.method(), response.url(), response.status(), response.headers(),
                response.bodyRef(), response.bodyBytes(), response.decodedSamlRef(), changed.length,
                response.contentType(), response.rawQuery(), response.samlSummary());
        entries.set(entries.indexOf(response), mutated);
        assertEquals(Outcome.NOT_VERIFIED, finish(redirect, mutated).outcome().outcome());
    }

    @Test void wrongTargetSignatureAndUnsignedRequestsAreNotProof() {
        var step = start(); var response = prepareReply(step, "Success", "POST");
        var req = entries.getFirst();
        var root = SecureXml.parse(originals.get(req.id())).getDocumentElement();
        root.removeChild(MetadataAlgorithmEvidence.children(root, "http://www.w3.org/2000/09/xmldsig#", "Signature").getFirst());
        var unsigned = SecureXml.serialize(root.getOwnerDocument());
        originals.put(req.id(), unsigned);
        entries.set(0, new TranscriptEntry(req.id(), RUN, req.direction(), req.timestamp(), req.correlationId(),
                req.method(), req.url(), req.status(), req.headers(), req.bodyRef(), req.bodyBytes(),
                req.decodedSamlRef(), unsigned.length, req.contentType(), req.rawQuery(), req.samlSummary()));
        assertEquals(Outcome.NOT_VERIFIED, finish(step, response).outcome().outcome());
        entries.clear(); originals.clear();
        target = foreign;
        // The trusted provider still contains the original certificate, independent of the sender.
        var originalTarget = new FilePlanKeyStore(folder.resolve("keys"), Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate(PLAN, "target");
        testCase = new IdpAcsSelectionScenarioTestCase(IdpAcsSelectionScenarioTestCase.BINDING_CASE,
                ignored -> config, entry -> originals.get(entry.id()), ignored -> Optional.of(TARGET),
                ignored -> List.of(originalTarget.certificate()), ignored -> Optional.of(suite));
        step = start(); response = prepareReply(step, "Success", "POST");
        assertEquals(Outcome.NOT_VERIFIED, finish(step, response).outcome().outcome());
    }

    @Test void incompatibleOldSingleFixtureStateAndBrowserDisabledCannotDispatch() {
        var step = start();
        var legacy = new CaseState("await-fixture-unsupported-binding", Map.of(
                "scenario_case_id", testCase.id(), "fixture_id", "unsupported-binding",
                "fixture_index", 0, "fixture_attempt", 0));
        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase.resume(context(true), legacy, new CaseEvent.RetryInbound()));
        assertEquals("idp.binding-probe.state-incompatible", finish.outcome().notVerifiedReason());
        assertInstanceOf(CaseStep.Finish.class, testCase.start(context(false)));
        assertTrue(entries.isEmpty());
    }

    @Test void signedRequestWithAnUnrelatedErrorTriggerCannotProveProtocolBindingHandling() {
        var step = start(); var response = prepareReply(step, "Success", "POST");
        var request = entries.getFirst();
        var root = SecureXml.parse(originals.get(request.id())).getDocumentElement();
        root.removeChild(MetadataAlgorithmEvidence.children(root, "http://www.w3.org/2000/09/xmldsig#", "Signature").getFirst());
        root.setAttribute("ForceAuthn", "true");
        new XmlSigner().sign(root, suite, null);
        var changed = SecureXml.serialize(root.getOwnerDocument());
        originals.put(request.id(), changed);
        entries.set(0, new TranscriptEntry(request.id(), RUN, request.direction(), request.timestamp(),
                request.correlationId(), request.method(), request.url(), request.status(), request.headers(),
                request.bodyRef(), request.bodyBytes(), request.decodedSamlRef(), changed.length,
                request.contentType(), request.rawQuery(), request.samlSummary()));
        assertEquals(Outcome.NOT_VERIFIED, finish(step, response).outcome().outcome());
    }

    private CaseStep.AwaitInbound start() {
        return assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context(true)));
    }
    private CaseStep reply(CaseStep.AwaitInbound step, String status, String method) {
        return finishOrAwait(step, prepareReply(step, status, method));
    }
    private CaseStep.Finish finish(CaseStep.AwaitInbound step, TranscriptEntry response) {
        return assertInstanceOf(CaseStep.Finish.class, finishOrAwait(step, response));
    }
    private CaseStep finishOrAwait(CaseStep.AwaitInbound step, TranscriptEntry response) {
        return testCase.resume(context(true), step.next(), new CaseEvent.InboundMessage(
                originals.get(response.id()), new EvidenceRef("transcript", response.id())));
    }
    private TranscriptEntry prepareReply(CaseStep.AwaitInbound step, String status, String method) {
        var action = step.actions().getFirst();
        var fixture = String.valueOf(step.next().data().get("fixture_id"));
        var requestDocument = SecureXml.parse(action.payload());
        new XmlSigner().sign(requestDocument.getDocumentElement(), suite, null);
        var requestBytes = SecureXml.serialize(requestDocument);
        var request = new TranscriptEntry("tx-request-" + fixture, RUN, Direction.OUTBOUND, NOW.plusSeconds(1),
                action.actionId(), "POST", SSO.toString(), null, Map.of(), null, 1,
                "decoded/request/" + fixture, requestBytes.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "AuthnRequest", "scenario_case_id", testCase.id(), "fixture_id", fixture,
                        "action_id", action.actionId(), "active_probe", true));
        entries.add(request); originals.put(request.id(), requestBytes);
        var doc = SecureXml.newDocument();
        var root = doc.createElementNS(P, "samlp:Response");
        root.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:samlp", P);
        root.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:saml", A);
        root.setAttribute("ID", "_reply_" + fixture);
        root.setAttribute("Version", "2.0");
        root.setAttribute("InResponseTo", "_" + action.actionId());
        root.setAttribute("Destination", ACS.toString());
        doc.appendChild(root);
        var issuer = doc.createElementNS(A, "saml:Issuer"); issuer.setTextContent(TARGET); root.appendChild(issuer);
        var st = doc.createElementNS(P, "samlp:Status"); root.appendChild(st);
        var code = doc.createElementNS(P, "samlp:StatusCode");
        code.setAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:" + status); st.appendChild(code);
        if (status.equals("Success")) {
            var assertion = doc.createElementNS(A, "saml:Assertion");
            assertion.setAttribute("ID", "_assertion_" + fixture); root.appendChild(assertion);
            assertion.setAttribute("Version", "2.0");
            var assertionIssuer = doc.createElementNS(A, "saml:Issuer");
            assertionIssuer.setTextContent(TARGET); assertion.appendChild(assertionIssuer);
        }
        new XmlSigner().sign(root, target, null);
        var raw = SecureXml.serialize(doc);
        String url = ACS.toString(), query = null;
        if (method.equals("GET")) {
            var encoded = new SignedRedirectEncoder().encode(ACS, raw, "test-relay", target);
            raw = encoded.decodedXml(); url = encoded.destination().toString(); query = encoded.rawQuery();
        }
        var response = new TranscriptEntry("tx-response-" + fixture, RUN, Direction.INBOUND, NOW.plusSeconds(2),
                "_" + action.actionId(), method, url, 200, Map.of(), null, method.equals("GET") ? 0 : 1,
                "decoded/response/" + fixture, raw.length,
                method.equals("GET") ? null : "application/x-www-form-urlencoded", query, Map.of("type", "Response"));
        entries.add(response); originals.put(response.id(), raw);
        return response;
    }
    private void replace(TranscriptEntry old, String run, String correlation, String method,
            String url, String contentType, String query) {
        var changed = new TranscriptEntry(old.id(), run, old.direction(), old.timestamp(), correlation,
                method, url, old.status(), old.headers(), old.bodyRef(), old.bodyBytes(), old.decodedSamlRef(),
                old.decodedSamlBytes(), contentType, query, old.samlSummary());
        entries.set(entries.indexOf(old), changed);
    }
    private CaseContext context(boolean browser) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), new TestPlan.Interaction(browser, false), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
                    public List<TranscriptEntry> list(String run) { return List.copyOf(entries); }
                }, false);
    }
}
