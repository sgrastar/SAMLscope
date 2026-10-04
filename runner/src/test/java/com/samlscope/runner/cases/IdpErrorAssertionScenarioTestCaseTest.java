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

class IdpErrorAssertionScenarioTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private final IdpErrorAssertionScenarioTestCase testCase =
            new IdpErrorAssertionScenarioTestCase(ignored -> configuration());

    @Test
    void runsPositiveAndThreeDifferentErrorPathsWithoutAnOperatorVerdict() {
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var unknownFormat = next(baseline, response(baseline.next(), true, true, false));
        assertTrue(xml(unknownFormat).contains("NameIDPolicy"));
        var unknownSubject = next(unknownFormat, response(unknownFormat.next(), false, false, false));
        assertTrue(xml(unknownSubject).contains("urn:samlscope:probe:unknown-subject"));
        var passive = next(unknownSubject, response(unknownSubject.next(), false, false, false));
        assertTrue(xml(passive).contains("IsPassive=\"true\""));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), passive.next(), inbound(response(passive.next(), false, false, false))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void anAssertionInsideAnyErrorResponseIsAViolation() {
        var baseline = (CaseStep.AwaitInbound) testCase.start(context());
        var unknownFormat = next(baseline, response(baseline.next(), true, true, false));
        var unknownSubject = next(unknownFormat, response(unknownFormat.next(), false, true, false));
        var passive = next(unknownSubject, response(unknownSubject.next(), false, false, false));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), passive.next(), inbound(response(passive.next(), false, false, false)));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void encryptedAssertionsAreAlsoForbiddenOnError() {
        var baseline = (CaseStep.AwaitInbound) testCase.start(context());
        var unknownFormat = next(baseline, response(baseline.next(), true, true, false));
        var unknownSubject = next(unknownFormat, response(unknownFormat.next(), false, false, true));
        var passive = next(unknownSubject, response(unknownSubject.next(), false, false, false));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), passive.next(), inbound(response(passive.next(), false, false, false)));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void subjectSpecificObligationUsesAControlAndTheUnrecognizedSubjectOnly() {
        var subjectCase = new IdpErrorAssertionScenarioTestCase(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE, ignored -> configuration());
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.start(context()));
        var subject = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.resume(
                context(), baseline.next(), inbound(response(baseline.next(), true, true, false))));
        assertTrue(xml(subject).contains("urn:samlscope:probe:unknown-subject"));
        var finish = assertInstanceOf(CaseStep.Finish.class, subjectCase.resume(
                context(), subject.next(), inbound(response(subject.next(), false, false, false))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void successfulUnknownSubjectResponseWithAssertionViolatesSubjectObligation() {
        assertSuccessfulUnknownSubjectIsViolation(true);
    }

    @Test
    void successfulUnknownSubjectResponseWithoutAssertionViolatesSubjectObligation() {
        assertSuccessfulUnknownSubjectIsViolation(false);
    }

    @Test
    void successfulUnknownSubjectResponseRemainsInconclusiveForGeneralAssertionAbsenceCase() {
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var unknownFormat = next(baseline, response(baseline.next(), true, true, false));
        var unknownSubject = next(unknownFormat, response(unknownFormat.next(), false, false, false));
        var passive = next(unknownSubject, response(unknownSubject.next(), true, true, false));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), passive.next(), inbound(response(passive.next(), false, false, false))));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void targetHttpErrorForUnknownSubjectViolatesTheRequiredSamlErrorResponse() {
        var subjectCase = new IdpErrorAssertionScenarioTestCase(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE, ignored -> configuration());
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.start(context()));
        var subject = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.resume(
                context(), baseline.next(), inbound(response(baseline.next(), true, true, false))));
        var finish = assertInstanceOf(CaseStep.Finish.class, subjectCase.resume(
                context(), subject.next(), browser(500, "https://IDP.example:443/local-error", true)));

        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
        assertEquals(2, finish.outcome().evidence().size());
    }

    @Test
    void subjectHttpObservationFailsClosedWithoutTheTargetOriginStatusOrRecorderEvidence() {
        for (var observation : java.util.List.of(
                browser(500, "https://idp.example/error", false),
                browser(399, "https://idp.example/error", true),
                browser(600, "https://idp.example/error", true),
                browser(500, "http://idp.example/error", true),
                browser(500, "https://idp.example:444/error", true),
                browser(500, "https://other.example/error?body=https://idp.example", true))) {
            var subjectCase = new IdpErrorAssertionScenarioTestCase(
                    IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE, ignored -> configuration());
            var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.start(context()));
            var subject = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.resume(
                    context(), baseline.next(), inbound(response(baseline.next(), true, true, false))));
            var finish = assertInstanceOf(CaseStep.Finish.class, subjectCase.resume(
                    context(), subject.next(), observation));
            assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome(), observation.toString());
        }
    }

    @Test
    void targetHttpErrorCannotReplaceTheExistingPrincipalControl() {
        var subjectCase = new IdpErrorAssertionScenarioTestCase(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE, ignored -> configuration());
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.start(context()));
        var finish = assertInstanceOf(CaseStep.Finish.class, subjectCase.resume(
                context(), baseline.next(), browser(500, "https://idp.example/error", true)));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
    }

    @Test
    void localHttpErrorDoesNotProveAssertionAbsenceForTheGeneralErrorCase() {
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var unknownFormat = next(baseline, response(baseline.next(), true, true, false));
        var unknownSubject = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), unknownFormat.next(),
                browser(500, "https://idp.example/error", true)));
        var passive = next(unknownSubject, response(unknownSubject.next(), false, false, false));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), passive.next(), inbound(response(passive.next(), false, false, false))));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    private void assertSuccessfulUnknownSubjectIsViolation(boolean assertion) {
        var subjectCase = new IdpErrorAssertionScenarioTestCase(
                IdpErrorAssertionScenarioTestCase.SUBJECT_ERROR_CASE, ignored -> configuration());
        var baseline = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.start(context()));
        var subject = assertInstanceOf(CaseStep.AwaitInbound.class, subjectCase.resume(
                context(), baseline.next(), inbound(response(baseline.next(), true, true, false))));
        var finish = assertInstanceOf(CaseStep.Finish.class, subjectCase.resume(
                context(), subject.next(), inbound(response(subject.next(), true, assertion, false))));

        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
        assertEquals("error_response_contains_assertion", finish.outcome().reasonCode());
        assertEquals(2, finish.outcome().evidence().size());
    }

    private CaseStep.AwaitInbound next(CaseStep.AwaitInbound step, String response) {
        return assertInstanceOf(CaseStep.AwaitInbound.class,
                testCase.resume(context(), step.next(), inbound(response)));
    }

    private CaseEvent.InboundMessage inbound(String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "tx"));
    }

    private CaseEvent.BrowserObservation browser(int status, String url, boolean evidence) {
        return new CaseEvent.BrowserObservation(status, url, "response body is ignored",
                evidence ? new EvidenceRef("transcript", "tx-browser-" + status) : null);
    }

    private String xml(CaseStep.AwaitInbound step) {
        return new String(step.actions().getFirst().payload(), StandardCharsets.UTF_8);
    }

    private String response(CaseState state, boolean success, boolean assertion, boolean encrypted) {
        var content = assertion ? "<saml:Assertion/>" : encrypted ? "<saml:EncryptedAssertion/>" : "";
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"),
                success ? "Success" : "Responder", content);
    }

    private IdpErrorProbeConfiguration configuration() {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/acs"), Duration.ofMinutes(2), true, true, true);
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return RUN; }
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
