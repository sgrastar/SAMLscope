package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;

class IdpSignedRequestScenarioTestCaseTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void rejectsEveryInvalidSignatureAfterTheValidControl() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.VERIFY_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var tampered = next(testCase, valid, response(valid.next(), true, false));
        var reference = next(testCase, tampered, response(tampered.next(), false, false));
        var signature = next(testCase, reference, response(reference.next(), false, false));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), signature.next(), inbound(response(signature.next(), false, false))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void acceptingAnInvalidSignatureIsAViolation() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.RELIANCE_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var tampered = next(testCase, valid, response(valid.next(), true, false));
        var reference = next(testCase, tampered, response(tampered.next(), true, false));
        var signature = next(testCase, reference, response(reference.next(), false, false));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), signature.next(), inbound(response(signature.next(), false, false))));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void targetSha256CreationAndInboundVerificationAreObservedTogether() {
        for (var id : java.util.List.of(
                IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,
                IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE)) {
            var testCase = testCase(id);
            var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
            var tampered = next(testCase, valid, response(valid.next(), true, true));
            var reference = next(testCase, tampered, response(tampered.next(), false, false));
            var signature = next(testCase, reference, response(reference.next(), false, false));
            var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                    context(), signature.next(), inbound(response(signature.next(), false, false))));
            assertEquals(Outcome.SATISFIED, finish.outcome().outcome(), id);
        }
    }

    @Test
    void missingCallbacksCannotProveAlgorithmVerification() {
        for (var id : java.util.List.of(
                IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,
                IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE)) {
            var testCase = testCase(id);
            var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
            CaseStep step = next(testCase, valid, response(valid.next(), true, true));
            while (step instanceof CaseStep.AwaitInbound current) {
                step = testCase.resume(context(), current.next(),
                        new CaseEvent.InboundUnavailable("operator-reported-no-saml-response"));
            }
            var finish = assertInstanceOf(CaseStep.Finish.class, step);
            assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome(), id);
            assertEquals("idp.signed-request.inconclusive", finish.outcome().reasonCode(), id);
        }
    }

    @Test
    void algorithmSupportRemainsNotVerifiedWhenTheDeploymentDoesNotEnforceRequestSignatures() {
        for (var id : java.util.List.of(
                IdpSignedRequestScenarioTestCase.SHA256_DIGEST_CASE,
                IdpSignedRequestScenarioTestCase.RSA_SHA256_CASE)) {
            var testCase = testCase(id);
            var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
            var tampered = next(testCase, valid, response(valid.next(), true, true));
            var reference = next(testCase, tampered, response(tampered.next(), true, false));
            var signature = next(testCase, reference, response(reference.next(), true, false));
            var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                    context(), signature.next(), inbound(response(signature.next(), true, false))));
            assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome(), id);
            assertEquals("signed_request_result_not_conclusive", finish.outcome().notVerifiedReason(), id);
            assertEquals("idp.signed-request.inconclusive", finish.outcome().reasonCode(), id);
        }
    }

    @Test
    void invalidSignaturesProduceSamlErrorResponsesForTheShouldCase() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.ERROR_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var tampered = next(testCase, valid, response(valid.next(), true, false));
        var reference = next(testCase, tampered, response(tampered.next(), false, false));
        var signature = next(testCase, reference, response(reference.next(), false, false));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), signature.next(), inbound(response(signature.next(), false, false))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void targetHttpErrorsForInvalidSignaturesViolateTheShouldCase() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.ERROR_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var tampered = next(testCase, valid, response(valid.next(), true, false));
        var reference = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), tampered.next(), browser(500, "https://IDP.example:443/error", true)));
        var signature = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), reference.next(), browser(400, "https://idp.example/rejected", true)));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), signature.next(), browser(503, "https://idp.example/unavailable", true)));

        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
        assertEquals(4, finish.outcome().evidence().size());
    }

    @Test
    void signatureHttpObservationFailsClosedWithoutTheTargetOriginStatusOrRecorderEvidence() {
        for (var observation : java.util.List.of(
                browser(500, "https://idp.example/error", false),
                browser(399, "https://idp.example/error", true),
                browser(600, "https://idp.example/error", true),
                browser(500, "http://idp.example/error", true),
                browser(500, "https://idp.example:444/error", true),
                browser(500, "https://other.example/error", true))) {
            var testCase = testCase(IdpSignedRequestScenarioTestCase.ERROR_CASE);
            var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
            var tampered = next(testCase, valid, response(valid.next(), true, false));
            var reference = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                    context(), tampered.next(), observation));
            var signature = next(testCase, reference, response(reference.next(), false, false));
            var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                    context(), signature.next(), inbound(response(signature.next(), false, false))));
            assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome(), observation.toString());
        }
    }

    @Test
    void targetHttpErrorCannotReplaceTheValidSignedControl() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.ERROR_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), valid.next(), browser(500, "https://idp.example/error", true)));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
    }

    @Test
    void localHttpErrorsRemainInconclusiveForOtherSignedRequestObligations() {
        var testCase = testCase(IdpSignedRequestScenarioTestCase.VERIFY_CASE);
        var valid = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        CaseStep step = next(testCase, valid, response(valid.next(), true, false));
        while (step instanceof CaseStep.AwaitInbound current) {
            step = testCase.resume(context(), current.next(),
                    browser(500, "https://idp.example/error", true));
        }

        assertEquals(Outcome.NOT_VERIFIED, assertInstanceOf(CaseStep.Finish.class, step)
                .outcome().outcome());
    }

    @Test
    void rejectsExcludedSignatureContentAndSignedObjectFixtures() {        for (var id : java.util.List.of(
                IdpSignedRequestScenarioTestCase.EXCLUDED_CONTENT_CASE,
                IdpSignedRequestScenarioTestCase.SIGNED_OBJECT_CASE)) {
            var testCase = testCase(id);
            CaseStep step = testCase.start(context());
            var waiting = assertInstanceOf(CaseStep.AwaitInbound.class, step);
            step = testCase.resume(context(), waiting.next(), inbound(response(waiting.next(), true, false)));
            while (step instanceof CaseStep.AwaitInbound current) {
                step = testCase.resume(
                        context(), current.next(), inbound(response(current.next(), false, false)));
            }
            var finish = assertInstanceOf(CaseStep.Finish.class, step);
            assertEquals(Outcome.SATISFIED, finish.outcome().outcome(), id);
        }
    }

    private IdpSignedRequestScenarioTestCase testCase(String id) {
        var credentials = credentials();
        return new IdpSignedRequestScenarioTestCase(
                id, ignored -> configuration(), ignored -> java.util.Optional.of(credentials));
    }

    private PlanCredentials credentials() {
        return new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
    }

    private CaseStep.AwaitInbound next(
            IdpSignedRequestScenarioTestCase testCase, CaseStep.AwaitInbound step, String response) {
        return assertInstanceOf(CaseStep.AwaitInbound.class,
                testCase.resume(context(), step.next(), inbound(response)));
    }

    private CaseEvent.InboundMessage inbound(String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8), new EvidenceRef("transcript", "tx"));
    }

    private CaseEvent.BrowserObservation browser(int status, String url, boolean evidence) {
        return new CaseEvent.BrowserObservation(status, url, "not examined",
                evidence ? new EvidenceRef("transcript", "tx-browser-" + status) : null);
    }

    private String response(CaseState state, boolean success, boolean sha256Signature) {
        var status = success ? "Success" : "Requester";
        var signature = sha256Signature ? """
                <ds:Signature><ds:SignedInfo>
                  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>
                </ds:SignedInfo></ds:Signature>
                """ : "";
        var assertion = success ? "<saml:Assertion/>" : "";
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Version="2.0"
                  InResponseTo="%s">%s
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), signature, status, assertion);
    }

    private IdpErrorProbeConfiguration configuration() {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/acs/0"), Duration.ofMinutes(2), true, true, true);
    }

    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return "run_0123456789ABCDEFGHJKMNPQRS"; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
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
