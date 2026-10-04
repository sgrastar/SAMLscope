package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlLogoutRequestFactory;
import com.samlscope.saml.normal.SecureXml;

class LogoutRejectionScenarioTestCaseTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-09-15T00:00:00Z");
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String P = SamlLogoutRequestFactory.PROTOCOL;
    private static final String A = SamlLogoutRequestFactory.ASSERTION;
    private static final URI ACS = URI.create("https://suite.example/acs");
    private static final URI SLO = URI.create("https://suite.example/slo");
    private static final String TARGET = "https://idp.example";
    private static final String SUITE = "https://suite.example";
    private PlanCredentials suite, target;

    private LogoutRejectionScenarioTestCase fixture(String caseId) {
        var keys = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC));
        suite = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "suite");
        target = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "target");
        var configuration = new IdpBasicLogoutScenarioTestCase.Configuration(
                new IdpErrorProbeConfiguration(URI.create(TARGET + "/sso"), SUITE, ACS, Duration.ofMinutes(5),
                        true, true, true),
                URI.create(TARGET + "/slo"), SLO, TARGET, suite, List.of(target.certificate()));
        return new LogoutRejectionScenarioTestCase(caseId, ignored -> configuration, entry -> new byte[0]);
    }

    private CaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new UnsupportedOperationException(); }
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                }, true);
    }

    private byte[] login(CaseState state) {
        var assertion = SecureXml.parse(("<a:Assertion xmlns:a='" + A + "' ID='_assertion' Version='2.0' IssueInstant='"
                + NOW + "'><a:Issuer>" + TARGET + "</a:Issuer><a:Subject><a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient' NameQualifier='"
                + TARGET + "' SPNameQualifier='" + SUITE + "'>user</a:NameID></a:Subject>"
                + "<a:AuthnStatement AuthnInstant='" + NOW + "' SessionIndex='session-0'><a:AuthnContext>"
                + "<a:AuthnContextClassRef>urn:password</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>"
                + "</a:Assertion>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        new XmlSigner().sign(assertion, target, null);
        var root = SecureXml.parse(("<p:Response xmlns:p='" + P + "' xmlns:a='" + A + "' ID='_response' Version='2.0' IssueInstant='"
                + NOW + "' Destination='" + ACS + "' InResponseTo='" + state.data().get("request_id") + "'>"
                + "<a:Issuer>" + TARGET + "</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                + "</p:Status></p:Response>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        root.appendChild(root.getOwnerDocument().importNode(assertion, true));
        new XmlSigner().sign(root, target, null);
        return SecureXml.serialize(root.getOwnerDocument());
    }

    private byte[] logoutResponse(CaseState state, String statusValue) {
        var root = SecureXml.parse(("<p:LogoutResponse xmlns:p='" + P + "' xmlns:a='" + A + "' ID='_control' Version='2.0' IssueInstant='"
                + NOW + "' Destination='" + SLO + "' InResponseTo='" + state.data().get("request_id") + "'>"
                + "<a:Issuer>" + TARGET + "</a:Issuer><p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:" + statusValue + "'/>"
                + "</p:Status></p:LogoutResponse>").getBytes(StandardCharsets.UTF_8)).getDocumentElement();
        new XmlSigner().sign(root, target, null);
        return SecureXml.serialize(root.getOwnerDocument());
    }

    private CaseState loginState(CaseStep.AwaitInbound step) {
        return step.next();
    }

    private CaseStep.Finish finish(LogoutRejectionScenarioTestCase test, int httpStatus, String body, boolean control) {
        var step = (CaseStep.AwaitInbound) test.start(context());
        var afterLogin = (CaseStep.AwaitInbound) test.resume(context(), loginState(step),
                new CaseEvent.InboundMessage(login(loginState(step)), new EvidenceRef("transcript", "tx_login")));
        assertEquals(OutboundKind.LOGOUT_REQUEST, afterLogin.actions().getFirst().kind());
        assertTrue(Boolean.TRUE.equals(afterLogin.next().data().get("browser_observation")));
        var afterProbe = test.resume(context(), afterLogin.next(),
                new CaseEvent.BrowserObservation(httpStatus, TARGET + "/slo", body));
        if (afterProbe instanceof CaseStep.Finish finished) return finished;
        var controlStep = (CaseStep.AwaitInbound) afterProbe;
        assertEquals(OutboundKind.LOGOUT_REQUEST, controlStep.actions().getFirst().kind());
        return (CaseStep.Finish) test.resume(context(), controlStep.next(),
                new CaseEvent.InboundMessage(logoutResponse(controlStep.next(), control ? "Success" : "Responder"),
                        new EvidenceRef("transcript", "tx_control")));
    }

    private static String embeddedLogoutResponse(String statusValue) {
        var xml = ("<samlp:LogoutResponse xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_r'>"
                + "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:" + statusValue + "'/>"
                + "</samlp:Status></samlp:LogoutResponse>").getBytes(StandardCharsets.UTF_8);
        return "<html><body><form method='post' action='" + SLO + "'>"
                + "<input type='hidden' name='SAMLResponse' value='"
                + Base64.getEncoder().encodeToString(xml) + "'/></form></body></html>";
    }

    @Test void destinationMismatchFailsTheSessionControl() {
        var test = fixture(LogoutRejectionScenarioTestCase.DESTINATION_ID);
        var finished = finish(test, 200, "<html>logged out</html>", true);
        assertEquals(Outcome.SATISFIED, finished.outcome().outcome());
        assertEquals("slo.destination-mismatch.not-applied", finished.outcome().reasonCode());
        var step = (CaseStep.AwaitInbound) test.start(context());
        var afterLogin = (CaseStep.AwaitInbound) test.resume(context(), loginState(step),
                new CaseEvent.InboundMessage(login(loginState(step)), new EvidenceRef("transcript", "tx_login")));
        var xml = SecureXml.parse(afterLogin.actions().getFirst().payload()).getDocumentElement();
        assertEquals("https://samlscope.invalid/sp/slo", xml.getAttribute("Destination"));
        assertTrue(new com.samlscope.saml.crypto.XmlSignatureVerifier()
                .hasValidEnvelopedSignature(xml, suite.certificate()));
    }

    @Test void tamperedSignatureIsDetectedByTheControl() {
        var test = fixture(LogoutRejectionScenarioTestCase.SIGNATURE_ID);
        var finished = finish(test, 400, "<html>Message Security Error</html>", true);
        assertEquals(Outcome.SATISFIED_WITH_NOTE, finished.outcome().outcome());
        assertEquals("slo.tampered-signature.not-applied", finished.outcome().reasonCode());
    }

    @Test void probeSuccessResponseIsAViolation() {
        var test = fixture(LogoutRejectionScenarioTestCase.INVALID_SIGNATURE_ID);
        var finished = finish(test, 200, embeddedLogoutResponse("Success"), true);
        assertEquals(Outcome.VIOLATED, finished.outcome().outcome());
        assertEquals("slo.rejection.applied-to-session", finished.outcome().reasonCode());
    }

    @Test void controlFailureProvesTheCraftedRequestWasApplied() {
        var test = fixture(LogoutRejectionScenarioTestCase.EXCLUDED_CONTENT_ID);
        var finished = finish(test, 200, "<html>ignored</html>", false);
        assertEquals(Outcome.VIOLATED, finished.outcome().outcome());
        assertEquals("slo.rejection.session-not-preserved", finished.outcome().reasonCode());
    }

    @Test void errorObligationDistinguishesErrorSilenceAndSuccess() {
        var withError = finish(fixture(LogoutRejectionScenarioTestCase.ERROR_RESPONSE_ID), 200,
                embeddedLogoutResponse("Requester"), true);
        assertEquals(Outcome.SATISFIED_WITH_NOTE, withError.outcome().outcome());
        var silent = finish(fixture(LogoutRejectionScenarioTestCase.ERROR_RESPONSE_ID), 500,
                "<html>Server error</html>", true);
        assertEquals(Outcome.VIOLATED, silent.outcome().outcome());
        assertEquals("slo.invalid-signature.no-error-response", silent.outcome().reasonCode());
    }

    @Test void exclusionFixtureCarriesAnXPathTransformAndValidSignature() {
        var test = fixture(LogoutRejectionScenarioTestCase.EXCLUDED_CONTENT_ID);
        var step = (CaseStep.AwaitInbound) test.start(context());
        var afterLogin = (CaseStep.AwaitInbound) test.resume(context(), loginState(step),
                new CaseEvent.InboundMessage(login(loginState(step)), new EvidenceRef("transcript", "tx_login")));
        var xml = SecureXml.parse(afterLogin.actions().getFirst().payload()).getDocumentElement();
        assertEquals(1, xml.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "XPath").getLength());
        assertTrue(new com.samlscope.saml.crypto.XmlSignatureVerifier()
                .hasValidEnvelopedSignature(xml, suite.certificate()));
    }

    @Test void unknownDeliveryIsNeverARejectionSuccess() {
        var test = fixture(LogoutRejectionScenarioTestCase.DESTINATION_ID);
        var step = (CaseStep.AwaitInbound) test.start(context());
        var afterLogin = (CaseStep.AwaitInbound) test.resume(context(), loginState(step),
                new CaseEvent.InboundMessage(login(loginState(step)), new EvidenceRef("transcript", "tx_login")));
        var timedOut = (CaseStep.Finish) test.resume(context(), afterLogin.next(),
                new CaseEvent.InboundUnavailable("direct-probe-delivery-unknown"));
        assertEquals(Outcome.NOT_VERIFIED, timedOut.outcome().outcome());
        assertEquals("slo.rejection.probe-no-response", timedOut.outcome().reasonCode());
    }
}
