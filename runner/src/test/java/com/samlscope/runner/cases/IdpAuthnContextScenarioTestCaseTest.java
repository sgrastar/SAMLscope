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
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory;

class IdpAuthnContextScenarioTestCaseTest {
    @Test
    void exactClassDeclarationAndUnsatisfiableControlsAreTranscriptJudged() {
        var testCase = testCase();
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        assertTrue(xml(baseline).contains("AuthnRequest"));
        var classRef = next(testCase, baseline, response(baseline.next(), true, null, null));
        assertTrue(xml(classRef).contains("AuthnContextClassRef"));
        var declaration = next(testCase, classRef, response(
                classRef.next(), true,
                "AuthnContextClassRef",
                SamlRequestedAuthnContextRequestFactory.PASSWORD_PROTECTED_TRANSPORT));
        assertTrue(xml(declaration).contains("AuthnContextDeclRef"));
        var unavailable = next(testCase, declaration, response(
                declaration.next(), true,
                "AuthnContextDeclRef",
                SamlRequestedAuthnContextRequestFactory.FIXTURE_DECLARATION));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), unavailable.next(), inbound(response(unavailable.next(), false, null, null))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void mismatchedExactClassReferenceIsAViolation() {
        var testCase = testCase();
        var baseline = (CaseStep.AwaitInbound) testCase.start(context());
        var classRef = next(testCase, baseline, response(baseline.next(), true, null, null));
        var declaration = next(testCase, classRef, response(
                classRef.next(), true, "AuthnContextClassRef", "urn:wrong"));
        var unavailable = next(testCase, declaration, response(
                declaration.next(), false, null, null));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), unavailable.next(), inbound(response(unavailable.next(), false, null, null)));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void encryptedContextCannotProveAnExactComparisonViolation() {
        var testCase = testCase();
        var step = (CaseStep.AwaitInbound) testCase.start(context());
        for (int index = 0; index < 3; index++) {
            step = next(testCase, step, encryptedResponse(step.next()));
        }
        var finish = (CaseStep.Finish) testCase.resume(
                context(), step.next(), inbound(encryptedResponse(step.next())));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    private String encryptedResponse(CaseState state) {
        return response(state, true, null, null)
                .replace("<saml:Assertion></saml:Assertion>", "<saml:EncryptedAssertion/>");
    }

    @Test
    void unavailableSatisfiableFixtureDoesNotFabricateTargetNonconformance() {
        var testCase = testCase();
        var baseline = (CaseStep.AwaitInbound) testCase.start(context());
        var classRef = next(testCase, baseline, response(baseline.next(), true, null, null));
        var declaration = next(testCase, classRef, response(classRef.next(), false, null, null));
        var unavailable = next(testCase, declaration, response(declaration.next(), false, null, null));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), unavailable.next(), inbound(response(unavailable.next(), false, null, null)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    private IdpAuthnContextScenarioTestCase testCase() {
        return new IdpAuthnContextScenarioTestCase(ignored -> configuration());
    }

    private CaseStep.AwaitInbound next(
            IdpAuthnContextScenarioTestCase testCase, CaseStep.AwaitInbound step, String response) {
        return assertInstanceOf(CaseStep.AwaitInbound.class,
                testCase.resume(context(), step.next(), inbound(response)));
    }

    private CaseEvent.InboundMessage inbound(String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "tx"));
    }

    private String xml(CaseStep.AwaitInbound step) {
        return new String(step.actions().getFirst().payload(), StandardCharsets.UTF_8);
    }

    private String response(CaseState state, boolean success, String refName, String refValue) {
        var context = refName == null ? "" : """
                <saml:AuthnStatement><saml:AuthnContext><saml:%s>%s</saml:%s>
                </saml:AuthnContext></saml:AuthnStatement>
                """.formatted(refName, refValue, refName);
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"),
                success ? "Success" : "Responder", success ? "<saml:Assertion>" + context + "</saml:Assertion>" : "");
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
