package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

class IdpForceAuthnScenarioTestCaseTest {
    @Test
    void reusesTheObservedForceAuthnBehaviorForMechanismAccessWithoutAttestation() {
        var testCase = new IdpForceAuthnScenarioTestCase(
                IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE, ignored -> configuration());
        assertEquals(IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE, testCase.id());
        assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
    }

    @Test
    void freshAuthenticationAfterAnExistingSessionIsSatisfied() {
        var testCase = testCase();
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        assertTrue(testCase.requiresFreshSession(baseline.next()));
        var omitted = next(testCase, baseline, response(baseline.next(), "2026-08-30T00:00:00Z"));
        assertFalse(xml(omitted).contains("ForceAuthn="));
        var explicitFalse = next(testCase, omitted, response(omitted.next(), "2026-08-30T00:00:00Z"));
        assertTrue(xml(explicitFalse).contains("ForceAuthn=\"false\""));
        var explicitTrue = next(testCase, explicitFalse, response(explicitFalse.next(), "2026-08-30T00:00:00Z"));
        assertTrue(xml(explicitTrue).contains("ForceAuthn=\"true\""));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), explicitTrue.next(),
                inbound(response(explicitTrue.next(), "2026-08-30T00:00:01Z"))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void sameReportedInstantCannotProveSessionReuse() {
        var testCase = testCase();
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var omitted = next(testCase, baseline, response(baseline.next(), "2026-08-30T00:00:00Z"));
        var explicitFalse = next(testCase, omitted, response(omitted.next(), "2026-08-30T00:00:00Z"));
        var explicitTrue = next(testCase, explicitFalse, response(explicitFalse.next(), "2026-08-30T00:00:00Z"));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), explicitTrue.next(),
                inbound(response(explicitTrue.next(), "2026-08-30T00:00:00Z"))));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void reportedPrecisionDoesNotTurnFreshAuthenticationIntoAViolation() {
        assertFinalOutcome("2026-09-14T07:16:51Z", "2026-09-14T07:16:52.479385919Z",
                "2026-09-14T07:16:52Z", Outcome.NOT_VERIFIED);
        assertFinalOutcome("2026-09-14T07:16:51Z", "2026-09-14T07:16:52.479385919Z",
                "2026-09-14T07:16:52.479Z", Outcome.NOT_VERIFIED);
        assertFinalOutcome("2026-09-14T07:16:51Z", "2026-09-14T07:16:52.479385919Z",
                "2026-09-14T07:16:53Z", Outcome.SATISFIED);
        assertFinalOutcome("2026-09-14T07:16:51Z", "2026-09-14T07:16:52.479385919Z",
                "2026-09-14T07:16:51Z", Outcome.VIOLATED);
    }

    private void assertFinalOutcome(String baseline, String request, String authn, Outcome expected) {
        var state = new CaseState("await-force-authn-true-with-session", Map.of(
                "stage_index", 3, "stage", "true-with-session",
                "expected_response_correlation", "_request", "request_issue_instant", request,
                "baseline_authn_instant", baseline, "evidence", java.util.List.of("control")));
        var finish = assertInstanceOf(CaseStep.Finish.class,
                testCase().resume(context(), state, inbound(response(state, authn))));
        assertEquals(expected, finish.outcome().outcome());
    }

    private IdpForceAuthnScenarioTestCase testCase() {
        return new IdpForceAuthnScenarioTestCase(ignored -> configuration());
    }

    private CaseStep.AwaitInbound next(
            IdpForceAuthnScenarioTestCase testCase, CaseStep.AwaitInbound step, String response) {
        return assertInstanceOf(CaseStep.AwaitInbound.class,
                testCase.resume(context(), step.next(), inbound(response)));
    }

    private String xml(CaseStep.AwaitInbound step) {
        return new String(step.actions().getFirst().payload(), StandardCharsets.UTF_8);
    }

    private CaseEvent.InboundMessage inbound(String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "tx"));
    }

    private String response(CaseState state, String authnInstant) {
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"
                  InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion><saml:AuthnStatement AuthnInstant="%s"/></saml:Assertion>
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), authnInstant);
    }

    private IdpErrorProbeConfiguration configuration() {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/acs"), Duration.ofMinutes(2), true, true, true);
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return "run_0123456789ABCDEFGHJKMNPQRS"; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() {
                return Clock.fixed(Instant.parse("2026-08-30T00:00:00Z"), ZoneOffset.UTC);
            }
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
