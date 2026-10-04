package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.*;

class LogoutAsyncScenarioTestCaseTest {
    private static final Instant NOW = Instant.parse("2026-09-15T00:00:00Z");
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String TARGET = "https://idp.example", SUITE = "https://suite.example";
    private static final String P = SamlLogoutRequestFactory.PROTOCOL, A = SamlLogoutRequestFactory.ASSERTION;
    private static final URI ACS = URI.create(SUITE + "/acs"), SLO = URI.create(SUITE + "/slo");
    private static final String UNPROVEN = "slo.async.feedback.own-session-failure-unproven";
    @TempDir Path directory;
    private PlanCredentials suite, target;

    private LogoutAsyncScenarioTestCase fixture(String caseId) {
        if (suite == null) {
            var keys = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC));
            suite = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "suite");
            target = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "target");
        }
        var configuration = new IdpBasicLogoutScenarioTestCase.Configuration(
                new IdpErrorProbeConfiguration(URI.create(TARGET + "/sso"), SUITE, ACS,
                        Duration.ofMinutes(5), true, true, true),
                URI.create(TARGET + "/slo"), SLO, TARGET, suite, List.of(target.certificate()));
        return new LogoutAsyncScenarioTestCase(caseId, ignored -> configuration, reference -> null);
    }

    private CaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) {
                        throw new UnsupportedOperationException();
                    }
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                }, true);
    }

    private CaseStep.AwaitInbound login(LogoutAsyncScenarioTestCase test, String evidence) {
        var first = assertInstanceOf(CaseStep.AwaitInbound.class, test.start(context()));
        assertTrue(test.requiresFreshSession(first.next()));
        return completeLogin(test, first, evidence);
    }

    private CaseStep.AwaitInbound completeLogin(LogoutAsyncScenarioTestCase test, CaseStep.AwaitInbound first,
            String evidence) {
        var response = response(first.next(), "Response", ACS, "Success",
                "<a:Assertion ID='_assertion' Version='2.0' IssueInstant='" + NOW + "'>"
                + "<a:Issuer>" + TARGET + "</a:Issuer><a:Subject><a:NameID>user</a:NameID></a:Subject>"
                + "<a:AuthnStatement AuthnInstant='" + NOW + "' SessionIndex='own-session'>"
                + "<a:AuthnContext><a:AuthnContextClassRef>urn:password</a:AuthnContextClassRef>"
                + "</a:AuthnContext></a:AuthnStatement></a:Assertion>");
        return assertInstanceOf(CaseStep.AwaitInbound.class,
                test.resume(context(), first.next(), inbound(response, evidence)));
    }

    private byte[] response(CaseState state, String type, URI destination, String status, String inner) {
        var root = SecureXml.parse(("<p:" + type + " xmlns:p='" + P + "' xmlns:a='" + A
                + "' ID='_response' Version='2.0' IssueInstant='" + NOW + "' Destination='" + destination
                + "' InResponseTo='" + state.data().get("request_id") + "'><a:Issuer>" + TARGET
                + "</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:"
                + status + "'/></p:Status>" + inner + "</p:" + type + ">")
                .getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        Element before = null;
        for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
            if (node instanceof Element element && !"Issuer".equals(element.getLocalName())) {
                before = element;
                break;
            }
        }
        new XmlSigner().sign(root, target, before);
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, target.certificate()));
        return SecureXml.serialize(root.getOwnerDocument());
    }

    private CaseEvent.InboundMessage inbound(byte[] response, String reference) {
        return new CaseEvent.InboundMessage(response, new EvidenceRef("transcript", reference));
    }

    private CaseStep.AwaitInbound feedbackValidProbe(LogoutAsyncScenarioTestCase test, int status, String body) {
        var mismatch = login(test, "login");
        var action = mismatch.actions().getFirst();
        var request = SecureXml.parse(action.payload()).getDocumentElement();
        assertEquals(TARGET + "/slo", action.target().toString());
        assertEquals("https://samlscope.invalid/sp/slo", request.getAttribute("Destination"));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(request, suite.certificate()));
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, test.resume(context(), mismatch.next(),
                new CaseEvent.BrowserObservation(status, TARGET + "/slo", body)));
        var validRequest = SecureXml.parse(valid.actions().getFirst().payload()).getDocumentElement();
        assertEquals(TARGET + "/slo", validRequest.getAttribute("Destination"));
        assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(validRequest, suite.certificate()));
        return valid;
    }

    private void assertFeedbackUnproven(CaseStep step) {
        var outcome = assertInstanceOf(CaseStep.Finish.class, step).outcome();
        assertEquals(Outcome.NOT_VERIFIED, outcome.outcome());
        assertEquals(UNPROVEN, outcome.notVerifiedReason());
        assertEquals(UNPROVEN, outcome.reasonCode());
    }

    @Test void wrongDestinationErrorAndDifferentSuccessfulPageDoNotProveOwnSessionFailure() {
        var test = fixture(LogoutAsyncScenarioTestCase.FEEDBACK_ID);
        var valid = feedbackValidProbe(test, 400, "Invalid destination. Logout request failed.");
        assertFeedbackUnproven(test.resume(context(), valid.next(),
                new CaseEvent.BrowserObservation(200, TARGET + "/slo", "Logout successful")));
    }

    @Test void wrongDestinationErrorAndCorrelatedSignedSuccessDoNotProveOwnSessionFailure() {
        var test = fixture(LogoutAsyncScenarioTestCase.FEEDBACK_ID);
        var valid = feedbackValidProbe(test, 400, "Message Security Error");
        var result = test.resume(context(), valid.next(),
                inbound(response(valid.next(), "LogoutResponse", SLO, "Success", ""), "success"));
        assertFeedbackUnproven(result);
        assertTrue(assertInstanceOf(CaseStep.Finish.class, result).outcome().evidence()
                .contains(new EvidenceRef("transcript", "success")));
    }

    @Test void pageAndLocalizationDifferencesDoNotProveOwnSessionFailure() {
        var test = fixture(LogoutAsyncScenarioTestCase.FEEDBACK_ID);
        for (var pages : List.of(List.of("Logout failed", "Logout complete"),
                List.of("ログアウトできません", "ログアウトしました"),
                List.of("Page A", "Page B"))) {
            var valid = feedbackValidProbe(test, 200, pages.getFirst());
            assertFeedbackUnproven(test.resume(context(), valid.next(),
                    new CaseEvent.BrowserObservation(200, TARGET + "/slo", pages.getLast())));
        }
    }

    @Test void fixedPageCannotProveViolationWithoutAnOwnSessionFailure() {
        var test = fixture(LogoutAsyncScenarioTestCase.FEEDBACK_ID);
        var valid = feedbackValidProbe(test, 200, "Logout failed");
        assertFeedbackUnproven(test.resume(context(), valid.next(),
                new CaseEvent.BrowserObservation(200, TARGET + "/slo", "Logout failed")));
    }

    @Test void BooleanClaimsInStateCannotReplaceAuthenticOwnSessionFailureEvidence() {
        var test = fixture(LogoutAsyncScenarioTestCase.FEEDBACK_ID);
        var valid = feedbackValidProbe(test, 400, "Error");
        var data = new LinkedHashMap<String, Object>(valid.next().data());
        data.put("own_session_failure", true);
        data.put("failure_indicated", true);
        assertFeedbackUnproven(test.resume(context(), new CaseState(valid.next().phase(), data),
                new CaseEvent.BrowserObservation(200, TARGET + "/slo", "Success")));
    }

    @Test void mismatchProcessingStillRequiresSignedSynchronousControl() {
        var test = fixture(LogoutAsyncScenarioTestCase.PROCESSING_ID);
        var mismatch = login(test, "login");
        var control = assertInstanceOf(CaseStep.AwaitInbound.class, test.resume(context(), mismatch.next(),
                new CaseEvent.BrowserObservation(400, TARGET + "/slo", "Invalid destination")));
        for (var status : List.of("Success", "Responder")) {
            var outcome = assertInstanceOf(CaseStep.Finish.class, test.resume(context(), control.next(),
                    inbound(response(control.next(), "LogoutResponse", SLO, status, ""), "control"))).outcome();
            assertEquals(status.equals("Success") ? Outcome.SATISFIED : Outcome.VIOLATED, outcome.outcome());
        }
    }

    @Test void noResponseCaseStillRequiresSynchronousControlAndDetectsReturnedSaml() {
        var test = fixture(LogoutAsyncScenarioTestCase.NO_RESPONSE_ID);
        var control = login(test, "login");
        var secondLogin = assertInstanceOf(CaseStep.AwaitInbound.class, test.resume(context(), control.next(),
                inbound(response(control.next(), "LogoutResponse", SLO, "Success", ""), "control")));
        var valid = completeLogin(test, secondLogin, "login2");
        assertEquals(Outcome.SATISFIED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), valid.next(), new CaseEvent.BrowserObservation(200, TARGET + "/slo", "Done")))
                .outcome().outcome());
        assertEquals(Outcome.VIOLATED, assertInstanceOf(CaseStep.Finish.class,
                test.resume(context(), valid.next(), inbound(response(valid.next(), "LogoutResponse", SLO,
                        "Success", ""), "unexpected-response"))).outcome().outcome());
    }
}
