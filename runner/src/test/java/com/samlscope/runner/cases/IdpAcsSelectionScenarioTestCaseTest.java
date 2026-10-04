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
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;

class IdpAcsSelectionScenarioTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final URI ACS0 = URI.create("https://suite.example/sp/acs/0");
    private static final URI ACS1 = URI.create("https://suite.example/sp/acs/1");

    @Test
    void indexScenarioUsesDefaultControlThenNonDefaultIndex() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.INDEX_CASE);
        var control = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var controlXml = new String(control.actions().getFirst().payload(), StandardCharsets.UTF_8);
        assertTrue(!controlXml.contains("AssertionConsumerServiceIndex"));
        var selected = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), control.next(), inbound(control.next(), response(control.next(), "Success", ACS0))));
        var selectedXml = new String(selected.actions().getFirst().payload(), StandardCharsets.UTF_8);
        assertTrue(selectedXml.contains("AssertionConsumerServiceIndex=\"1\""));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), selected.next(), inbound(selected.next(), response(selected.next(), "Success", ACS1))));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    @Test
    void fixedDefaultImplementationIsDetectedForUrlSelection() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.URL_CASE);
        var control = (CaseStep.AwaitInbound) testCase.start(context());
        var selected = (CaseStep.AwaitInbound) testCase.resume(
                context(), control.next(), inbound(control.next(), response(control.next(), "Success", ACS0)));
        var selectedXml = new String(selected.actions().getFirst().payload(), StandardCharsets.UTF_8);
        assertTrue(selectedXml.contains("AssertionConsumerServiceURL=\"" + ACS1 + "\""));
        var finish = (CaseStep.Finish) testCase.resume(
                context(), selected.next(), inbound(selected.next(), response(selected.next(), "Success", ACS0)));
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void unsupportedBindingNeedsAnErrorRatherThanSilentPostFallback() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.BINDING_CASE);
        var waiting = (CaseStep.AwaitInbound) testCase.start(context());
        assertTrue(new String(waiting.actions().getFirst().payload(), StandardCharsets.UTF_8)
                .contains("urn:samlscope:unsupported:response-binding"));
        var error = (CaseStep.Finish) testCase.resume(
                context(), waiting.next(), inbound(waiting.next(), response(waiting.next(), "Responder", ACS0)));
        assertEquals(Outcome.SATISFIED, error.outcome().outcome());

        var fallback = testCase(IdpAcsSelectionScenarioTestCase.BINDING_CASE);
        var second = (CaseStep.AwaitInbound) fallback.start(context());
        var inconclusive = (CaseStep.Finish) fallback.resume(
                context(), second.next(), inbound(second.next(), response(second.next(), "Success", ACS0)));
        assertEquals(Outcome.NOT_VERIFIED, inconclusive.outcome().outcome());
    }

    @Test
    void unknownIndexRecordsBothPermittedMayChoicesWithoutInventingAViolation() {
        var errorCase = testCase(IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE);
        var errorWait = (CaseStep.AwaitInbound) errorCase.start(context());
        assertTrue(new String(errorWait.actions().getFirst().payload(), StandardCharsets.UTF_8)
                .contains("AssertionConsumerServiceIndex=\"999999\""));
        var error = (CaseStep.Finish) errorCase.resume(
                context(), errorWait.next(), inbound(
                        errorWait.next(), response(errorWait.next(), "Responder", ACS0)));
        assertEquals(Outcome.SATISFIED, error.outcome().outcome());

        var defaultCase = testCase(IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE);
        var defaultWait = (CaseStep.AwaitInbound) defaultCase.start(context());
        var defaultResult = (CaseStep.Finish) defaultCase.resume(
                context(), defaultWait.next(), inbound(
                        defaultWait.next(), response(defaultWait.next(), "Success", ACS0)));
        assertEquals(Outcome.SATISFIED, defaultResult.outcome().outcome());

        var wrongCase = testCase(IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE);
        var wrongWait = (CaseStep.AwaitInbound) wrongCase.start(context());
        var wrong = (CaseStep.Finish) wrongCase.resume(
                context(), wrongWait.next(), inbound(
                        wrongWait.next(), response(wrongWait.next(), "Success", ACS1)));
        assertEquals(Outcome.NOT_VERIFIED, wrong.outcome().outcome());

        var alternateErrorCase = testCase(IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE);
        var alternateErrorWait = (CaseStep.AwaitInbound) alternateErrorCase.start(context());
        var alternateError = (CaseStep.Finish) alternateErrorCase.resume(context(),
                alternateErrorWait.next(), inbound(alternateErrorWait.next(),
                        response(alternateErrorWait.next(), "Requester", ACS1)));
        assertEquals(Outcome.SATISFIED, alternateError.outcome().outcome());
    }

    @Test
    void unknownIndexNeedsASamlResponseAndDoesNotTreatUnknownStatusAsAPermittedChoice() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.UNKNOWN_INDEX_CASE);
        var wait = (CaseStep.AwaitInbound) testCase.start(context());
        var http = (CaseStep.Finish) testCase.resume(context(), wait.next(),
                browser(wait.next(), 400, "https://idp.example/error", true));
        assertEquals(Outcome.NOT_VERIFIED, http.outcome().outcome());

        var unknown = (CaseStep.Finish) testCase.resume(context(), wait.next(),
                inbound(wait.next(), response(wait.next(), "Unknown", ACS0)));
        assertEquals(Outcome.NOT_VERIFIED, unknown.outcome().outcome());

        var foreign = (CaseStep.Finish) testCase.resume(context(), wait.next(),
                inbound(wait.next(), response(wait.next(), "Success", ACS0)
                        .replace((String) wait.next().data().get("expected_response_correlation"), "_foreign")));
        assertEquals(Outcome.NOT_VERIFIED, foreign.outcome().outcome());
    }

    @Test
    void associationScenarioCoversEveryVariantWithSignedAndUnsignedRequests() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.UNREGISTERED_URL_CASE);
        var control = (CaseStep.AwaitInbound) testCase.start(context());
        assertEquals("registered-url-signed-control", control.next().data().get("fixture_id"));
        assertEquals(OutboundAction.RequestSigning.REQUIRE,
                control.actions().getFirst().requestSigning());
        var current = (CaseStep.AwaitInbound) testCase.resume(
                context(), control.next(), inbound(control.next(), response(control.next(), "Success", ACS1)));
        var expected = java.util.List.of(
                new Expected("registered-url-unsigned", "AssertionConsumerServiceURL=\"" + ACS1 + "\"",
                        OutboundAction.RequestSigning.OMIT_FOR_IDP12_B),
                new Expected("unregistered-url-signed", "AssertionConsumerServiceURL=\"https://suite.example/sp/acs/999999\"",
                        OutboundAction.RequestSigning.REQUIRE),
                new Expected("unregistered-url-unsigned", "AssertionConsumerServiceURL=\"https://suite.example/sp/acs/999999\"",
                        OutboundAction.RequestSigning.OMIT_FOR_IDP12_B),
                new Expected("other-entity-url-signed", "AssertionConsumerServiceURL=\"https://suite.example/samlscope-other-sp/acs\"",
                        OutboundAction.RequestSigning.REQUIRE),
                new Expected("other-entity-url-unsigned", "AssertionConsumerServiceURL=\"https://suite.example/samlscope-other-sp/acs\"",
                        OutboundAction.RequestSigning.OMIT_FOR_IDP12_B),
                new Expected("unknown-index-signed", "AssertionConsumerServiceIndex=\"999999\"",
                        OutboundAction.RequestSigning.REQUIRE),
                new Expected("unknown-index-unsigned", "AssertionConsumerServiceIndex=\"999999\"",
                        OutboundAction.RequestSigning.OMIT_FOR_IDP12_B));
        for (var item : expected) {
            assertEquals(item.id(), current.next().data().get("fixture_id"));
            assertEquals(item.signing(), current.actions().getFirst().requestSigning());
            assertTrue(new String(current.actions().getFirst().payload(), StandardCharsets.UTF_8)
                    .contains(item.xml()));
            var next = testCase.resume(context(), current.next(),
                    "registered-url-unsigned".equals(item.id())
                            ? inbound(current.next(), response(current.next(), "Success", ACS1))
                            : browser(current.next(), 400, "https://idp.example/error", true));
            if (item == expected.getLast()) {
                var finish = assertInstanceOf(CaseStep.Finish.class, next);
                assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
                assertEquals(8, finish.outcome().evidence().size());
            } else {
                current = assertInstanceOf(CaseStep.AwaitInbound.class, next);
            }
        }
    }

    @Test
    void hostileAcsArrivalIsAProductViolationEvenWhenItEndsWithHttpError() {
        var finish = completeAssociationScenario((state, index) -> {
            if ("other-entity-url-signed".equals(state.data().get("fixture_id"))) {
                return browser(state, 404, "https://suite.example/samlscope-other-sp/acs", true);
            }
            return browser(state, 400, "https://idp.example/error", true);
        });
        assertEquals(Outcome.VIOLATED, finish.outcome().outcome());
    }

    @Test
    void terminalPageWithoutRecorderEvidenceCannotBeAdopted() {
        var finish = completeAssociationScenario((state, index) -> index == 2
                ? browser(state, 400, "https://idp.example/error", false)
                : browser(state, 400, "https://idp.example/error", true));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void terminalSuccessPageCannotSubstituteForProtocolEvidence() {
        var finish = completeAssociationScenario((state, index) -> index == 2
                ? browser(state, 200, "https://idp.example/error", true)
                : browser(state, 400, "https://idp.example/error", true));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
    }

    @Test
    void registeredSignedControlCannotPassOnAnIdpLocalErrorPage() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.UNREGISTERED_URL_CASE);
        var control = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), control.next(), browser(control.next(), 400, "https://idp.example/error", true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
    }

    @Test
    void registeredUnsignedControlCannotPassOnAnIdpLocalErrorPage() {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.UNREGISTERED_URL_CASE);
        var signed = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        var unsigned = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.resume(
                context(), signed.next(), inbound(signed.next(), response(signed.next(), "Success", ACS1))));
        var finish = assertInstanceOf(CaseStep.Finish.class, testCase.resume(
                context(), unsigned.next(), browser(unsigned.next(), 400, "https://idp.example/error", true)));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("control_failed", finish.outcome().reasonCode());
    }

    private CaseStep.Finish completeAssociationScenario(
            java.util.function.BiFunction<CaseState, Integer, CaseEvent.BrowserObservation> browserEvent) {
        var testCase = testCase(IdpAcsSelectionScenarioTestCase.UNREGISTERED_URL_CASE);
        var control = assertInstanceOf(CaseStep.AwaitInbound.class, testCase.start(context()));
        CaseStep step = testCase.resume(
                context(), control.next(), inbound(control.next(), response(control.next(), "Success", ACS1)));
        for (var index = 1; index < 8; index++) {
            var waiting = assertInstanceOf(CaseStep.AwaitInbound.class, step);
            var event = index == 1
                    ? inbound(waiting.next(), response(waiting.next(), "Success", ACS1))
                    : browserEvent.apply(waiting.next(), index);
            step = testCase.resume(context(), waiting.next(), event);
        }
        return assertInstanceOf(CaseStep.Finish.class, step);
    }

    private CaseEvent.BrowserObservation browser(CaseState state, int status, String url, boolean evidence) {
        return new CaseEvent.BrowserObservation(status, url, "bounded target page",
                evidence ? new EvidenceRef("transcript", "browser-" + state.data().get("fixture_id")) : null);
    }

    private record Expected(String id, String xml, OutboundAction.RequestSigning signing) {}

    private IdpAcsSelectionScenarioTestCase testCase(String id) {
        return new IdpAcsSelectionScenarioTestCase(id, ignored -> configuration());
    }

    private CaseEvent.InboundMessage inbound(CaseState state, String xml) {
        return new CaseEvent.InboundMessage(
                xml.getBytes(StandardCharsets.UTF_8),
                new EvidenceRef("transcript", "tx-" + state.data().get("fixture_id")));
    }

    private String response(CaseState state, String status, URI destination) {
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  InResponseTo="%s" Destination="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>
                </samlp:Response>
                """.formatted(state.data().get("expected_response_correlation"), destination, status);
    }

    private IdpErrorProbeConfiguration configuration() {
        return new IdpErrorProbeConfiguration(
                URI.create("https://idp.example/sso"), "https://suite.example/sp", ACS0,
                Duration.ofMinutes(2), true, true, true);
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
