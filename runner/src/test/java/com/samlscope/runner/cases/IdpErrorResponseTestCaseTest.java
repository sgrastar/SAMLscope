package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

class IdpErrorResponseTestCaseTest {
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    private final IdpErrorResponseTestCase testCase = new IdpErrorResponseTestCase(configuration(true, true, true));

    @Test
    void runsThePositiveControlAndAllThreeProbesThroughDeterministicOutboxActions() {
        var first = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        assertAction(first, "await-fixture-passive-without-session");
        assertTrue(new String(first.actions().get(0).payload(), StandardCharsets.UTF_8).contains("IsPassive=\"true\""));

        var second = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), first.next(), inbound(error(first.next(), "Requester", null), "passive")));
        assertAction(second, "await-fixture-baseline-success");
        var baseline = new String(second.actions().get(0).payload(), StandardCharsets.UTF_8);
        assertTrue(!baseline.contains("NameIDPolicy") && !baseline.contains("RequestedAuthnContext"));

        var third = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), second.next(), inbound(error(second.next(), "Success", null), "baseline")));
        assertAction(third, "await-fixture-unknown-nameid-format");
        assertTrue(new String(third.actions().get(0).payload(), StandardCharsets.UTF_8).contains("NameIDPolicy"));

        var fourth = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), third.next(), inbound(error(third.next(), "Responder", null), "unknown-format")));
        assertAction(fourth, "await-fixture-unsatisfiable-authn-context");
        assertTrue(new String(fourth.actions().get(0).payload(), StandardCharsets.UTF_8).contains("RequestedAuthnContext"));

        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), fourth.next(), inbound(error(fourth.next(), "Responder", null), "authn-context")));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals(4, finish.outcome().evidence().size());
    }

    @Test
    void aSuccessResponseForAnErrorProbeProducesViolatedOnlyAfterAllControlsRun() {
        var first = (CaseStep.AwaitInbound) testCase.start(context());
        var second = (CaseStep.AwaitInbound) testCase.resume(
                context(), first.next(), inbound(error(first.next(), "Requester", null), "passive"));
        var third = (CaseStep.AwaitInbound) testCase.resume(
                context(), second.next(), inbound(error(second.next(), "Success", null), "baseline"));
        var fourth = (CaseStep.AwaitInbound) testCase.resume(
                context(), third.next(), inbound(error(third.next(), "Success", null), "unexpected-success"));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), fourth.next(), inbound(error(fourth.next(), "Responder", null), "expected-error"));

        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void aTargetThatActuallyReturnsTheProbeAuthnContextDoesNotGetAFalseViolation() {
        var first = (CaseStep.AwaitInbound) testCase.start(context());
        var second = (CaseStep.AwaitInbound) testCase.resume(
                context(), first.next(), inbound(error(first.next(), "Requester", null), "passive"));
        var third = (CaseStep.AwaitInbound) testCase.resume(
                context(), second.next(), inbound(error(second.next(), "Success", null), "baseline"));
        var fourth = (CaseStep.AwaitInbound) testCase.resume(
                context(), third.next(), inbound(error(third.next(), "Responder", null), "unknown-format"));
        var requestId = (String) fourth.next().data().get("expected_response_correlation");
        var requested = new com.samlscope.saml.normal.SamlErrorProbeRequestFactory().unavailableAuthnContext(requestId);
        var finish = (CaseStep.Finish) testCase.resume(
                context(), fourth.next(), inbound(error(fourth.next(), "Success", requested), "supported-context"));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void encryptedAuthnContextRemainsUnknownButVisibleWrongContextIsDetected() {
        for (boolean encrypted : new boolean[] {true, false}) {
            var passive = (CaseStep.AwaitInbound) testCase.start(context());
            var baseline = (CaseStep.AwaitInbound) testCase.resume(context(), passive.next(),
                    inbound(error(passive.next(), "Responder", null), "passive"));
            var nameId = (CaseStep.AwaitInbound) testCase.resume(context(), baseline.next(),
                    inbound(error(baseline.next(), "Success", null), "baseline"));
            var authn = (CaseStep.AwaitInbound) testCase.resume(context(), nameId.next(),
                    inbound(error(nameId.next(), "Responder", null), "nameid"));
            var response = encrypted
                    ? error(authn.next(), "Success", null).replace("<saml:Assertion/>",
                            "<saml:EncryptedAssertion xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">"
                                    + "<xenc:EncryptedData><xenc:CipherData>"
                                    + "<xenc:CipherValue>AQID</xenc:CipherValue>"
                                    + "</xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>")
                    : error(authn.next(), "Success", "urn:example:different-context");
            var finish = (CaseStep.Finish) testCase.resume(context(), authn.next(),
                    inbound(response, "authn-context"));
            assertEquals(encrypted ? Outcome.NOT_VERIFIED : Outcome.VIOLATED,
                    finish.outcome().outcome());
        }
    }

    @Test
    void blanketRejectionFailsThePositiveControlInsteadOfPassingTheTarget() {
        var passive = (CaseStep.AwaitInbound) testCase.start(context());
        var baseline = (CaseStep.AwaitInbound) testCase.resume(
                context(), passive.next(), inbound(error(passive.next(), "Requester", null), "passive"));

        var finish = (CaseStep.Finish) testCase.resume(
                context(), baseline.next(), inbound(error(baseline.next(), "Responder", null), "blanket-reject"));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
        assertEquals(2, finish.outcome().evidence().size());
    }

    @Test
    void anEmptySuccessResponseDoesNotSatisfyThePositiveControl() {
        var passive = (CaseStep.AwaitInbound) testCase.start(context());
        var baseline = (CaseStep.AwaitInbound) testCase.resume(
                context(), passive.next(), inbound(error(passive.next(), "Requester", null), "passive"));

        var finish = (CaseStep.Finish) testCase.resume(
                context(), baseline.next(), inbound(emptyResponse(baseline.next(), "Success"), "empty-success"));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
    }

    @Test
    void timeoutAndMissingPreconditionsNeverBecomeTargetViolations() {
        var waiting = (CaseStep.AwaitInbound) testCase.start(context());
        var timeout = (CaseStep.Finish) testCase.resume(
                context(), waiting.next(), new CaseEvent.TimedOut(Duration.ofMinutes(2)));
        var unavailable = (CaseStep.Finish) new IdpErrorResponseTestCase(configuration(true, true, false)).start(context());

        assertEquals(Outcome.NOT_VERIFIED, timeout.outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED, unavailable.outcome().outcome());
    }

    private void assertAction(CaseStep.AwaitInbound step, String phase) {
        assertEquals(phase, step.next().phase());
        assertEquals(ActionIds.derive(RUN_ID, testCase.id(), phase, 0), step.actions().get(0).actionId());
        assertEquals(step.actions().get(0).actionId(), step.matcher().criteria().get("ScenarioActionId"));
    }

    private CaseEvent.InboundMessage inbound(String xml, String evidence) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", evidence));
    }

    private String error(CaseState state, String status, String authnContext) {
        var context = authnContext == null
                ? ("Success".equals(status) ? "<saml:Assertion/>" : "")
                : """
                <saml:Assertion><saml:AuthnStatement><saml:AuthnContext>
                  <saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>
                </saml:AuthnContext></saml:AuthnStatement></saml:Assertion>
                """.formatted(authnContext);
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), status, context);
    }

    private String emptyResponse(CaseState state, String status) {
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), status);
    }

    private IdpErrorProbeConfiguration configuration(boolean agent, boolean location, boolean noSession) {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/acs"), Duration.ofMinutes(2), agent, location, noSession);
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return RUN_ID; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC); }
            @Override public com.samlscope.core.plan.TestPlan.Parameters parameters() { return null; }
            @Override public com.samlscope.core.plan.TestPlan.Interaction interaction() {
                return com.samlscope.core.plan.TestPlan.Interaction.defaults();
            }
            @Override public com.samlscope.core.run.Reachability reachability() { return null; }
            @Override public com.samlscope.core.transcript.TranscriptRecorder transcript() { return null; }
            @Override public boolean transcriptComplete() { return false; }
        };
    }
}
