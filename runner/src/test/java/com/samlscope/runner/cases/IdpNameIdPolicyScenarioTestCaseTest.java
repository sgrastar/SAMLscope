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
import com.samlscope.saml.normal.SecureXml;

class IdpNameIdPolicyScenarioTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";

    @Test
    void processingMatrixExercisesAllNineApprovedShapesWithoutOperatorVerdicts() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE);
        CaseStep step = testCase.start(context());
        var fixtures = new java.util.ArrayList<String>();
        while (step instanceof CaseStep.AwaitInbound waiting) {
            fixtures.add(String.valueOf(waiting.next().data().get("fixture_id")));
            var xml = new String(waiting.actions().get(0).payload(), StandardCharsets.UTF_8);
            assertTrue(xml.contains("<samlp:AuthnRequest"));
            step = testCase.resume(context(), waiting.next(), inbound(
                    waiting.next(), response(waiting.next(), "Success", null, null)));
        }
        var finish = assertInstanceOf(CaseStep.Finish.class, step);
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals(9, fixtures.size());
        assertTrue(fixtures.containsAll(java.util.List.of(
                "policy-omitted", "allow-create-omitted", "format-omitted",
                "allow-create-false", "allow-create-true", "format-unspecified",
                "format-persistent", "format-transient", "sp-name-qualifier")));
    }

    @Test
    void rejectionMatrixNeedsAWorkingSupportedControlAndRejectsUnknownFormat() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.REJECTION_CASE);
        var supported = (CaseStep.AwaitInbound) testCase.start(context());
        var unknownQualifier = (CaseStep.AwaitInbound) testCase.resume(
                context(), supported.next(), inbound(supported.next(), response(
                        supported.next(), "Success",
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", null)));
        var unknownFormat = (CaseStep.AwaitInbound) testCase.resume(
                context(), unknownQualifier.next(), inbound(unknownQualifier.next(), response(
                        unknownQualifier.next(), "Responder", null, null)));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), unknownFormat.next(), inbound(unknownFormat.next(), response(
                        unknownFormat.next(), "Responder", null, null)));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());

        var blanketReject = testCase(IdpNameIdPolicyScenarioTestCase.REJECTION_CASE);
        var first = (CaseStep.AwaitInbound) blanketReject.start(context());
        var failed = (CaseStep.Finish) blanketReject.resume(
                context(), first.next(), inbound(first.next(), response(first.next(), "Responder", null, null)));
        assertEquals(Outcome.NOT_VERIFIED, failed.outcome().outcome());
        assertEquals("control_failed", failed.outcome().reasonCode());
    }

    @Test
    void successfulResponseThatSilentlyIgnoresRequestedFormatIsViolated() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE);
        var transientFixture = (CaseStep.AwaitInbound) testCase.start(context());
        var persistentFixture = (CaseStep.AwaitInbound) testCase.resume(
                context(), transientFixture.next(), inbound(transientFixture.next(), response(
                        transientFixture.next(), "Success",
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", null)));
        var qualifierFixture = (CaseStep.AwaitInbound) testCase.resume(
                context(), persistentFixture.next(), inbound(persistentFixture.next(), response(
                        persistentFixture.next(), "Success",
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", null)));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), qualifierFixture.next(), inbound(qualifierFixture.next(), response(
                        qualifierFixture.next(), "Responder", null, null)));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void implicitSameSpQualifierRemainsUnresolvedWhileExplicitMismatchStillFails() {
        assertQualifierOutcome(null, Outcome.NOT_VERIFIED);
        assertQualifierOutcome("https://wrong.example/sp", Outcome.VIOLATED);
    }

    private void assertQualifierOutcome(String returnedQualifier, Outcome expected) {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE);
        CaseStep step = testCase.start(context());
        while (step instanceof CaseStep.AwaitInbound waiting) {
            var document = SecureXml.parse(waiting.actions().getFirst().payload());
            var policy = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                    "urn:oasis:names:tc:SAML:2.0:protocol", "NameIDPolicy").item(0);
            step = testCase.resume(context(), waiting.next(), inbound(waiting.next(), response(
                    waiting.next(), "Success", policy.getAttribute("Format"),
                    policy.hasAttribute("SPNameQualifier") ? returnedQualifier : null)));
        }
        assertEquals(expected, assertInstanceOf(CaseStep.Finish.class, step).outcome().outcome());
    }

    @Test
    void omittedQualifierRequiresDirectAndExclusiveSpScope() {
        assertImplicitScope("https://suite.example/acs", "https://suite.example/sp", Outcome.SATISFIED);
        assertImplicitScope("https://other.example/acs", "https://suite.example/sp", Outcome.NOT_VERIFIED);
        assertImplicitScope("https://suite.example/acs", "https://other.example/sp", Outcome.NOT_VERIFIED);
        assertImplicitScope("https://suite.example/acs", null, Outcome.NOT_VERIFIED);
        assertImplicitScope("https://suite.example/acs", "https://suite.example/sp</saml:Audience><saml:Audience>https://other.example/sp", Outcome.NOT_VERIFIED);
    }

    private void assertImplicitScope(String destination, String audience, Outcome expected) {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE);
        CaseStep step = testCase.start(context());
        while (step instanceof CaseStep.AwaitInbound waiting) {
            var document = SecureXml.parse(waiting.actions().getFirst().payload());
            var policy = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                    "urn:oasis:names:tc:SAML:2.0:protocol", "NameIDPolicy").item(0);
            var xml = response(waiting.next(), "Success", policy.getAttribute("Format"), null)
                    .replace("InResponseTo=", "Destination=\"" + destination + "\" InResponseTo=");
            if (audience != null) xml = xml.replace("</saml:Assertion>",
                    "<saml:Conditions><saml:AudienceRestriction><saml:Audience>" + audience
                    + "</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>");
            step = testCase.resume(context(), waiting.next(), inbound(waiting.next(), xml));
        }
        assertEquals(expected, assertInstanceOf(CaseStep.Finish.class, step).outcome().outcome());
    }

    @Test
    void absentSamlResponseCanOnlyBecomeNotVerified() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE);
        var waiting = (CaseStep.AwaitInbound) testCase.start(context());
        var finish = (CaseStep.Finish) testCase.resume(
                context(), waiting.next(), new CaseEvent.Aborted("no-saml-response"));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void legacyQuestionnaireStateClosesSafelyInsteadOfBeingReinterpreted() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE);
        var legacy = new CaseState("await-browser", java.util.Map.of(
                "case_id", IdpNameIdPolicyScenarioTestCase.PROCESSING_CASE));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), legacy, new CaseEvent.BrowserReturned("legacy-operator-completed")));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("scenario_upgrade_requires_new_run", finish.outcome().notVerifiedReason());
        assertTrue(testCase.browserInstructionsEn().contains("Start a new Run"));
    }

    @Test
    void legacyQuestionnaireAbortCannotBecomeATargetViolation() {
        var testCase = testCase(IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE);
        var legacy = new CaseState("await-browser", java.util.Map.of(
                "case_id", IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), legacy, new CaseEvent.Aborted("operator-skipped")));

        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void decryptsAssertionsOnlyInMemoryBeforeComparingTheRequestedPolicy() throws Exception {
        var privateKey = java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        var testCase = new IdpNameIdPolicyScenarioTestCase(
                IdpNameIdPolicyScenarioTestCase.CONFORMANCE_CASE,
                ignored -> configuration(),
                ignored -> java.util.Optional.of(privateKey),
                new com.samlscope.saml.normal.SamlNameIdPolicyRequestFactory(),
                (wrapper, ignored) -> SecureXml.parse("""
                        <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                          <saml:Subject><saml:NameID Format="%s"%s>subject</saml:NameID></saml:Subject>
                        </saml:Assertion>
                        """.formatted(
                                wrapper.getAttribute("FixtureFormat"),
                                wrapper.hasAttribute("FixtureQualifier")
                                        ? " SPNameQualifier=\"" + wrapper.getAttribute("FixtureQualifier") + "\""
                                        : "").getBytes(StandardCharsets.UTF_8)).getDocumentElement());

        var transientFixture = (CaseStep.AwaitInbound) testCase.start(context());
        var persistentFixture = (CaseStep.AwaitInbound) testCase.resume(
                context(), transientFixture.next(), inbound(transientFixture.next(), encryptedResponse(
                        transientFixture.next(), "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", null)));
        var qualifierFixture = (CaseStep.AwaitInbound) testCase.resume(
                context(), persistentFixture.next(), inbound(persistentFixture.next(), encryptedResponse(
                        persistentFixture.next(), "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", null)));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), qualifierFixture.next(), inbound(qualifierFixture.next(), encryptedResponse(
                        qualifierFixture.next(), "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                        "https://suite.example/sp"))));

        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    private IdpNameIdPolicyScenarioTestCase testCase(String id) {
        return new IdpNameIdPolicyScenarioTestCase(id, configuration());
    }

    private CaseEvent.InboundMessage inbound(CaseState state, String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8),
                new EvidenceRef("transcript", "tx-" + state.data().get("fixture_id")));
    }

    private String response(CaseState state, String status, String format, String qualifier) {
        var assertion = format == null ? "" : """
                <saml:Assertion><saml:Subject><saml:NameID Format="%s"%s>subject</saml:NameID></saml:Subject></saml:Assertion>
                """.formatted(format, qualifier == null ? "" : " SPNameQualifier=\"" + qualifier + "\"");
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>%s
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), status, assertion);
    }

    private String encryptedResponse(CaseState state, String format, String qualifier) {
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:EncryptedAssertion FixtureFormat="%s"%s/>
                </samlp:Response>
                """.formatted(
                        state.data().get("expected_response_correlation"), format,
                        qualifier == null ? "" : " FixtureQualifier=\"" + qualifier + "\"");
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
            @Override public Clock clock() { return Clock.fixed(Instant.parse("2026-08-30T00:00:00Z"), ZoneOffset.UTC); }
            @Override public com.samlscope.core.plan.TestPlan.Parameters parameters() { return null; }
            @Override public com.samlscope.core.plan.TestPlan.Interaction interaction() { return com.samlscope.core.plan.TestPlan.Interaction.defaults(); }
            @Override public com.samlscope.core.run.Reachability reachability() { return null; }
            @Override public com.samlscope.core.transcript.TranscriptRecorder transcript() { return null; }
            @Override public boolean transcriptComplete() { return false; }
        };
    }
}
