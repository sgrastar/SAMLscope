package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

class LogoutTranscriptProfileCaseTest {
    @Test
    void detectsIdReuseOnlyForDifferentMessageObjects() {
        var fixture = fixture(
                inbound("a", request("_same", "2.0", ""), null),
                inbound("b", request("_same", "2.0", "<samlp:SessionIndex>x</samlp:SessionIndex>"), null));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(LogoutTranscriptProfileCase.Rule.UNIQUE_IDS));
        var retransmit = fixture(inbound("a", request("_same", "2.0", ""), null),
                inbound("b", request("_same", "2.0", ""), null));
        assertEquals(Outcome.SATISFIED, retransmit.evaluate(LogoutTranscriptProfileCase.Rule.UNIQUE_IDS));
    }

    @Test
    void correlatesResponseAndVersionRulesWithTheSuiteRequest() {
        var good = fixture(
                outbound("request", request("_request", "2.0", ""), null),
                inbound("response", response("_response", "2.0", "_request", success()), null));
        assertEquals(Outcome.SATISFIED, good.evaluate(LogoutTranscriptProfileCase.Rule.IN_RESPONSE_TO));
        assertEquals(Outcome.SATISFIED, good.evaluate(LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_CEILING));
        assertEquals(Outcome.SATISFIED, good.evaluate(LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_FLOOR));
        var wrong = fixture(
                outbound("request", request("_request", "2.0", ""), null),
                inbound("response", response("_response", "3.0", "_other", success()), null));
        assertEquals(Outcome.VIOLATED, wrong.evaluate(LogoutTranscriptProfileCase.Rule.IN_RESPONSE_TO));
    }

    @Test
    void consentRequiresXmlOrBindingSignatureAndTopStatusUsesOnlyTheCoreList() {
        var unsigned = fixture(inbound("response",
                response("_response", "2.0", "_request", success()).replace(
                        "Version=\"2.0\"", "Version=\"2.0\" Consent=\"urn:consent\""), null));
        assertEquals(Outcome.VIOLATED, unsigned.evaluate(LogoutTranscriptProfileCase.Rule.CONSENT_SIGNATURE));
        var redirectSigned = fixture(inbound("response",
                response("_response", "2.0", "_request", success()).replace(
                        "Version=\"2.0\"", "Version=\"2.0\" Consent=\"urn:consent\""), "Signature=abc"));
        assertEquals(Outcome.VIOLATED, redirectSigned.evaluate(LogoutTranscriptProfileCase.Rule.CONSENT_SIGNATURE));
        var secondaryAtTop = fixture(inbound("response",
                response("_response", "2.0", "_request", "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"), null));
        assertEquals(Outcome.VIOLATED, secondaryAtTop.evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
        var successAtTop = fixture(inbound("response",
                response("_response", "2.0", "_request", success()), null));
        assertEquals(Outcome.SATISFIED,
                successAtTop.evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
    }

    @Test
    void asyncExtensionMustBeDirectlyInsideLogoutRequestExtensions() {
        var proper = fixture(inbound("request", request("_request", "2.0",
                "<samlp:Extensions><aslo:Asynchronous/></samlp:Extensions>"), null));
        assertEquals(Outcome.SATISFIED, proper.evaluate(LogoutTranscriptProfileCase.Rule.ASYNC_PLACEMENT));
        var misplaced = fixture(inbound("response",
                response("_response", "2.0", "_request", success()).replace(
                        "</samlp:LogoutResponse>", "<aslo:Asynchronous/></samlp:LogoutResponse>"), null));
        assertEquals(Outcome.VIOLATED, misplaced.evaluate(LogoutTranscriptProfileCase.Rule.ASYNC_PLACEMENT));
    }

    @Test
    void targetIssuedMessagesExposeIssuerSignatureAndUtcExpiryWithoutQuestionnaires() {
        var entity = "https://idp.example/entity";
        var request = request("_request", "2.0", "").replace(
                "<saml:NameID>",
                "<saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">"
                        + entity + "</saml:Issuer><saml:NameID>").replace(
                "IssueInstant=\"2026-08-29T00:00:00Z\"",
                "IssueInstant=\"2026-08-29T00:00:00Z\" NotOnOrAfter=\"2026-08-29T00:05:00Z\"");
        var response = response("_response", "2.0", "_suite", success()).replace(
                "<samlp:Status>",
                "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                        + entity + "</saml:Issuer><samlp:Status>");
        var fixture = fixture(inbound("request", request, null), inbound("response", response, null));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_COUNT, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_VALUE, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_FORMAT, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_COUNT, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_VALUE, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.RESPONSE_ISSUER_FORMAT, entity));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER, entity));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_SIGNATURE, entity));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.RESPONSE_SIGNATURE, entity));
    }

    @Test
    void malformedIssuerAndNonUtcExpiryAreViolations() {
        var request = request("_request", "2.0", "").replace(
                "<saml:NameID>", "<saml:Issuer Format=\"wrong\">wrong</saml:Issuer><saml:NameID>")
                .replace("IssueInstant=\"2026-08-29T00:00:00Z\"",
                        "IssueInstant=\"2026-08-29T00:00:00Z\" NotOnOrAfter=\"2026-08-29T09:05:00+09:00\"");
        var fixture = fixture(inbound("request", request, null));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_VALUE, "https://idp.example/entity"));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_ISSUER_FORMAT, "https://idp.example/entity"));
        assertEquals(Outcome.VIOLATED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER, "https://idp.example/entity"));
    }

    @Test
    void targetLogoutRequestIsCorrelatedWithTheIssuedIdentifierAndSessionExpiry() {
        var assertion = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Assertion><saml:Subject><saml:NameID
                    Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">user</saml:NameID>
                  </saml:Subject><saml:Conditions NotOnOrAfter="2026-08-29T00:05:00Z"/></saml:Assertion>
                </samlp:Response>
                """;
        var logout = request("_request", "2.0", "")
                .replace("<saml:NameID>", "<saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">")
                .replace(
                "IssueInstant=\"2026-08-29T00:00:00Z\"",
                "IssueInstant=\"2026-08-29T00:00:00Z\" NotOnOrAfter=\"2026-08-29T00:05:00Z\"");
        var fixture = fixture(inbound("assertion", assertion, null), inbound("request", logout, null));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER_BOUND));

        var tooEarly = fixture(inbound("assertion", assertion, null), inbound("request", logout.replace(
                "NotOnOrAfter=\"2026-08-29T00:05:00Z\"",
                "NotOnOrAfter=\"2026-08-29T00:04:59Z\""), null));
        assertEquals(Outcome.VIOLATED, tooEarly.evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_NOT_ON_OR_AFTER_BOUND));

        var mismatch = logout.replace(">user</saml:NameID>", ">another-user</saml:NameID>");
        assertEquals(Outcome.VIOLATED, fixture(
                inbound("assertion", assertion, null),
                inbound("matching", logout, null),
                inbound("mismatching", mismatch, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));
        assertEquals(Outcome.VIOLATED, fixture(
                inbound("assertion", assertion, null), inbound("mismatching", mismatch, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));

        var encrypted = request("_encrypted", "2.0", "").replace(
                "<saml:NameID>user</saml:NameID>", "<saml:EncryptedID/>");
        assertEquals(Outcome.NOT_VERIFIED, fixture(
                inbound("assertion", assertion, null),
                inbound("matching", logout, null),
                inbound("encrypted", encrypted, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));

        var assertionWithSpProvidedId = assertion.replace(
                "nameid-format:persistent\">user", "nameid-format:persistent\" SPProvidedID=\"current\">user");
        var requestWithOldSpProvidedId = logout.replace(
                "nameid-format:persistent\">user", "nameid-format:persistent\" SPProvidedID=\"old\">user");
        assertEquals(Outcome.VIOLATED, fixture(
                inbound("assertion", assertionWithSpProvidedId, null),
                inbound("request", requestWithOldSpProvidedId, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));

        var assertionWithExtension = assertion.replace(
                "nameid-format:persistent\">user",
                "nameid-format:persistent\" xmlns:ext=\"urn:example:identifier\" ext:tenant=\"current\">user");
        var requestWithOtherExtension = logout.replace(
                "nameid-format:persistent\">user",
                "nameid-format:persistent\" xmlns:ext=\"urn:example:identifier\" ext:tenant=\"other\">user");
        assertEquals(Outcome.VIOLATED, fixture(
                inbound("assertion", assertionWithExtension, null),
                inbound("request", requestWithOtherExtension, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));

        var assertionA = assertion.replace(">user</saml:NameID>", ">user-a</saml:NameID>")
                .replace("</saml:Assertion>",
                        "<saml:AuthnStatement SessionIndex=\"session-a\"/></saml:Assertion>");
        var assertionB = assertion.replace(">user</saml:NameID>", ">user-b</saml:NameID>")
                .replace("</saml:Assertion>",
                        "<saml:AuthnStatement SessionIndex=\"session-b\"/></saml:Assertion>");
        var wrongSessionIdentifier = logout.replace(">user</saml:NameID>", ">user-a</saml:NameID>")
                .replace("</samlp:LogoutRequest>",
                        "<samlp:SessionIndex>session-b</samlp:SessionIndex></samlp:LogoutRequest>");
        assertEquals(Outcome.VIOLATED, fixture(
                inbound("assertion-a", assertionA, null),
                inbound("assertion-b", assertionB, null),
                inbound("request", wrongSessionIdentifier, null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));

        var rejectedAssertion = inboundResponse(
                "rejected-assertion", assertionA, Map.of("type", "Response", "normalFlowAccepted", false));
        var acceptedAssertion = inboundResponse(
                "accepted-assertion", assertionB, Map.of("type", "Response", "normalFlowAccepted", true));
        assertEquals(Outcome.VIOLATED, fixture(
                rejectedAssertion, acceptedAssertion,
                inbound("request", logout.replace(">user</saml:NameID>", ">user-a</saml:NameID>"), null)).evaluate(
                LogoutTranscriptProfileCase.Rule.REQUEST_IDENTIFIER_MATCH));
    }

    @Test
    void redirectLogoutRequestIsAcceptedOnlyWhenACorrelatedSuccessReturns() {
        var fixture = fixture(
                outboundRedirect("request", request("_request", "2.0", ""), redirectQuery(request("_request", "2.0", ""))),
                inbound("response", response("_response", "2.0", "_request", success()), null));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(
                LogoutTranscriptProfileCase.Rule.REDIRECT_LOGOUT_REQUEST_ACCEPTED));
    }

    @Test
    void suiteSelectedResponseBindingCannotViolateTheTargetsRedirectSupport() {
        for (var requestMethod : List.of("POST", "GET")) {
            var requestXml = request("_target-request", "2.0", "");
            var test = fixture(new Entry("target-request", Direction.INBOUND, requestMethod, requestXml,
                            requestMethod.equals("GET") ? redirectQuery(requestXml) : null,
                            Map.of("type", "LogoutRequest")),
                    new Entry("suite-response", Direction.OUTBOUND, "POST",
                            response("_suite-response", "2.0", "_target-request", success()), null,
                            Map.of("type", "LogoutResponse",
                                    "binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")));
            var outcome = test.result(LogoutTranscriptProfileCase.Rule.TARGET_REDIRECT_RESPONSE_CONSUMED, null);
            assertEquals(Outcome.NOT_VERIFIED, outcome.outcome(), requestMethod);
            assertEquals("slo.redirect-response.fixture-binding-unavailable", outcome.reasonCode());
        }
    }

    @Test
    void laterBrowserFailureDoesNotProveRefusalOfTheRedirectLogoutResponse() {
        for (var landing : List.of("https://unrelated.example/error", "https://target.example/logout")) {
            var test = fixture(new Entry("target-request", Direction.INBOUND, "POST",
                            request("_target-request", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                    new Entry("suite-response", Direction.OUTBOUND, "POST",
                            response("_suite-response", "2.0", "_target-request", success()), null,
                            Map.of("type", "LogoutResponse",
                                    "binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")),
                    new Entry("failed-page", Direction.INBOUND, "BROWSER", null, null,
                            Map.of("type", "BrowserResponseObservation", "http_status", 500,
                                    "failure_indicated", true), landing));
            var outcome = test.result(LogoutTranscriptProfileCase.Rule.TARGET_REDIRECT_RESPONSE_CONSUMED, null);
            assertEquals(Outcome.NOT_VERIFIED, outcome.outcome(), landing);
            assertEquals("slo.redirect-response.consumption-unobserved", outcome.reasonCode());
            org.junit.jupiter.api.Assertions.assertFalse(outcome.evidence().stream()
                    .anyMatch(ref -> ref.reference().equals("transcript:failed-page")));
        }
    }

    private String redirectQuery(String xml) {
        try {
            var output = new java.io.ByteArrayOutputStream();
            var deflater = new java.util.zip.Deflater(-1,true);
            try(var stream=new java.util.zip.DeflaterOutputStream(output,deflater)){stream.write(xml.getBytes(StandardCharsets.UTF_8));}
            finally{deflater.end();}
            return "SAMLRequest="+java.net.URLEncoder.encode(java.util.Base64.getEncoder().encodeToString(output.toByteArray()),StandardCharsets.UTF_8);
        } catch(java.io.IOException failure){throw new RuntimeException(failure);}
    }

    @Test void receiverRejectedSoapCannotBecomeSuccessfulPassiveEvidence() {
        var xml=request("_request","2.0","");
        for(var rule:LogoutTranscriptProfileCase.Rule.values())for(var payload:List.of(xml,
                "<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Body>"+xml+"</s:Body></s:Envelope>")) {
            var fixture=fixture(new Entry("rejected",Direction.INBOUND,"POST",payload,null,
                    Map.of("transport","SOAP","type","unparsed","parseStatus","invalid-soap-message-scope")));
            var result=fixture.result(rule,null);
            assertEquals(Outcome.NOT_VERIFIED,result.outcome());
            assertEquals("slo.evidence.incomplete",result.reasonCode());
            assertEquals(List.of("logout_message_scope_unresolved"),result.details().get("evidence_issues"));
        }
    }

    @Test void everyRuleRejectsDisagreementBetweenRedirectWireAndRecordedXmlAsSuiteUncertainty() {
        for(var rule:LogoutTranscriptProfileCase.Rule.values())for(var fault:List.of("different-xml","bad-deflate","two-messages")) {
            var xml=request("_request","2.0","");
            var query=switch(fault) {
                case "different-xml" -> redirectQuery(request("_other","2.0",""));
                case "bad-deflate" -> "SAMLRequest=abc";
                default -> redirectQuery(xml)+"&SAMLResponse=abc";
            };
            var fixture=fixture(outboundRedirect("request",xml,query),inbound("response",response("_response","2.0","_request",success()),null));
            var result=fixture.result(rule,null);
            assertEquals(Outcome.NOT_VERIFIED,result.outcome());
            assertEquals("slo.evidence.incomplete",result.reasonCode());
            assertEquals(List.of("redirect_message_mismatch"),result.details().get("evidence_issues"));
        }
    }

    @Test
    void everyRuleRequiresCompleteReadableRunScopedEvidence() {
        for (var rule : LogoutTranscriptProfileCase.Rule.values()) {
            for (var fault : List.of("missing", "length", "malformed", "foreign-run", "duplicate-id",
                    "missing-reference", "missing-logout-bytes", "history-limit", "type-mismatch")) {
                var fixture = fixture(inbound("response", response("_response", "2.0", "_request", success()), null));
                var original = fixture.entries.getFirst();
                switch (fault) {
                    case "missing" -> fixture.content.clear();
                    case "length" -> fixture.content.put(original.decodedSamlRef(), new byte[] {1});
                    case "malformed" -> {
                        var bytes = fixture.content.get(original.decodedSamlRef()).clone();
                        bytes[0] = '!'; fixture.content.put(original.decodedSamlRef(), bytes);
                    }
                    case "foreign-run" -> fixture.entries.set(0, altered(original, "another-run",
                            original.decodedSamlRef(), original.decodedSamlBytes(), original.samlSummary()));
                    case "duplicate-id" -> fixture.entries.add(original);
                    case "missing-reference" -> fixture.entries.set(0, altered(original, original.runId(),
                            null, original.decodedSamlBytes(), original.samlSummary()));
                    case "missing-logout-bytes" -> fixture.entries.set(0, altered(original, original.runId(),
                            null, 0, Map.of("type", "LogoutResponse")));
                    case "history-limit" -> fixture.historyUnavailable = true;
                    case "type-mismatch" -> fixture.entries.set(0, altered(original, original.runId(),
                            original.decodedSamlRef(), original.decodedSamlBytes(), Map.of("type", "LogoutRequest")));
                }
                var result = fixture.result(rule, null);
                assertEquals(Outcome.NOT_VERIFIED, result.outcome(), rule + ":" + fault);
                assertEquals("slo.evidence.incomplete", result.reasonCode(), rule + ":" + fault);
                if (fault.equals("foreign-run")) assertEquals(List.of(), result.evidence());
            }
        }
    }

    @Test
    void unreadableCompanionCannotBeDiscardedWhileTheRemainingResponsePasses() {
        var fixture = fixture(inbound("good", response("_good", "2.0", "_request", success()), null),
                inbound("bad", response("_bad", "2.0", "_request", success()), null));
        assertEquals(Outcome.SATISFIED, fixture.evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
        fixture.content.remove("decoded-bad");
        assertEquals(Outcome.NOT_VERIFIED, fixture.evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
    }

    @Test
    void soapUsesExactlyOneDirectBodyMessageAndIgnoresHeaderDecoys() {
        var good = response("_response", "2.0", "_request", success());
        var bad = response("_bad", "2.0", "_request", "urn:unexpected");
        for (var ns : List.of("http://schemas.xmlsoap.org/soap/envelope/", "http://www.w3.org/2003/05/soap-envelope")) {
            var start = "<e:Envelope xmlns:e=\"" + ns + "\">";
            var end = "</e:Envelope>";
            assertEquals(Outcome.SATISFIED, fixture(inbound("soap", start + "<e:Header>" + bad
                    + "</e:Header><e:Body>" + good + "</e:Body>" + end, null))
                    .evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
            assertEquals(Outcome.VIOLATED, fixture(inbound("soap", start + "<e:Header>" + good
                    + "</e:Header><e:Body>" + bad + "</e:Body>" + end, null))
                    .evaluate(LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS));
            for (var middle : List.of("<e:Header>" + good + "</e:Header><e:Body/>",
                    "<e:Body><wrapper>" + good + "</wrapper></e:Body>",
                    "<e:Body>" + good + bad + "</e:Body>",
                    "<e:Body>" + good + "</e:Body><e:Body>" + bad + "</e:Body>")) {
                for (var rule : LogoutTranscriptProfileCase.Rule.values())
                    assertEquals(Outcome.NOT_VERIFIED, fixture(inbound("soap", start + middle + end, null))
                            .evaluate(rule), ns + ":" + rule);
            }
        }
        for (var rule : LogoutTranscriptProfileCase.Rule.values()) {
            assertEquals(Outcome.NOT_VERIFIED, fixture(inbound("wrapped", "<wrapper>" + good + "</wrapper>", null))
                    .evaluate(rule), rule.name());
        }
    }

    @Test
    void propagationContinuesOnlyWithinOneCorrelatedLogoutProcessing() {
        var continued = fixture(propagationChain().toArray(Entry[]::new));
        assertEquals(Outcome.SATISFIED,
                continued.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // evidence after the correlated final response is outside the processing window
        var afterFinal = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"));
        assertEquals(Outcome.NOT_VERIFIED,
                afterFinal.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // a delayed request from a previous attempt is before the initiating request
        var delayed = fixture(
                new Entry("old", Direction.INBOUND, "POST",
                        request("_old", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                delayed.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // an arrival without the issued failure response is not a failure
        var arrivalOnly = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant"), "https://suite.example/sp/slo-fail"),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                arrivalOnly.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // a continuation that precedes the failure response is not continuation
        var beforeFailure = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                beforeFailure.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // overlapping processings cannot attribute the participants
        var overlapping = fixture(
                new Entry("init1", Direction.OUTBOUND, "POST",
                        request("_init1", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("init2", Direction.OUTBOUND, "POST",
                        request("_init2", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("final1", Direction.INBOUND, "POST",
                        response("_final1", "2.0", "_init1", success()), null, Map.of("type", "LogoutResponse")),
                new Entry("final2", Direction.INBOUND, "POST",
                        response("_final2", "2.0", "_init2", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                overlapping.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // a retry to the same failing endpoint is not a remaining participant
        var retry = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("retry", Direction.INBOUND, "POST",
                        request("_retry", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                retry.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // an unrelated PartialLogout is not the correlated final response
        var unrelatedPartial = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("other", Direction.INBOUND, "POST",
                        response("_other", "2.0", "_elsewhere",
                                "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"), null,
                        Map.of("type", "LogoutResponse")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"));
        assertEquals(Outcome.NOT_VERIFIED,
                unrelatedPartial.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
        // the Suite must have answered the remaining participant inside the processing
        var unanswered = fixture(
                new Entry("initiator", Direction.OUTBOUND, "POST",
                        request("_init", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail", Direction.INBOUND, "POST",
                        request("_fail", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("remain", Direction.INBOUND, "POST",
                        request("_remain", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("final", Direction.INBOUND, "POST",
                        response("_final", "2.0", "_init", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                unanswered.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void propagationIgnoresADelayedRequestFromAPreviousProcessing() {
        var straggler = fixture(
                new Entry("init1", Direction.OUTBOUND, "POST",
                        request("_init1", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("final1", Direction.INBOUND, "POST",
                        response("_final1", "2.0", "_init1", success()), null, Map.of("type", "LogoutResponse")),
                new Entry("straggler", Direction.INBOUND, "POST",
                        request("_old", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("init2", Direction.OUTBOUND, "POST",
                        request("_init2", "2.0", ""), null, Map.of("type", "LogoutRequest")),
                new Entry("fail2", Direction.INBOUND, "POST",
                        request("_fail2", "2.0", ""), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("remain2", Direction.INBOUND, "POST",
                        request("_remain2", "2.0", ""), null,
                        Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("answered2", Direction.OUTBOUND, "POST",
                        response("_answer2", "2.0", "_remain2", success()), null, Map.of("type", "LogoutResponse")),
                new Entry("final2", Direction.INBOUND, "POST",
                        response("_final2", "2.0", "_init2", success()), null, Map.of("type", "LogoutResponse")));
        assertEquals(Outcome.NOT_VERIFIED,
                straggler.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void continuationRequiresItsOwnResponseAndRecordedEndpoints() {
        for (var fault : List.of("unrelated-response", "wrong-response-endpoint",
                "wrong-request-endpoint", "duplicate-request-id", "false-http-status")) {
            var chain = new ArrayList<>(propagationChain());
            if (fault.equals("unrelated-response")) {
                var entry = chain.get(3);
                chain.set(3, new Entry(entry.id(), entry.direction(), entry.method(),
                        entry.xml().replace("InResponseTo=\"_remain\"", "InResponseTo=\"_other\""),
                        entry.rawQuery(), entry.samlSummary(), entry.url()));
            } else if (fault.equals("wrong-response-endpoint")) {
                var entry = chain.get(3);
                chain.set(3, new Entry(entry.id(), entry.direction(), entry.method(), entry.xml(),
                        entry.rawQuery(), entry.samlSummary(), "https://other.example/logout"));
            } else if (fault.equals("wrong-request-endpoint")) {
                var entry = chain.get(2);
                chain.set(2, new Entry(entry.id(), entry.direction(), entry.method(), entry.xml(),
                        entry.rawQuery(), entry.samlSummary(), "https://suite.example/other-participant"));
            } else if (fault.equals("duplicate-request-id")) {
                var entry = chain.get(2);
                chain.add(3, new Entry("duplicate", entry.direction(), entry.method(), entry.xml(),
                        entry.rawQuery(), entry.samlSummary(), entry.url()));
            }
            var test = fixture(chain.toArray(Entry[]::new));
            if (fault.equals("false-http-status")) {
                var entry = test.entries.get(1);
                test.entries.set(1, new TranscriptEntry(entry.id(), entry.runId(), entry.direction(),
                        entry.timestamp(), entry.correlationId(), entry.method(), entry.url(), 200,
                        entry.headers(), entry.bodyRef(), entry.bodyBytes(), entry.decodedSamlRef(),
                        entry.decodedSamlBytes(), entry.contentType(), entry.rawQuery(), entry.samlSummary()));
            }
            assertEquals(Outcome.NOT_VERIFIED,
                    test.evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE), fault);
        }
        var result = fixture(propagationChain().toArray(Entry[]::new)).result(
                LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE, null);
        assertEquals(Outcome.SATISFIED, result.outcome());
        org.junit.jupiter.api.Assertions.assertTrue(result.evidence().stream()
                .anyMatch(ref -> ref.reference().equals("transcript:answered")));
    }

    @Test
    void separateCompleteProcessingsWithTheirOwnParticipantsCanBeBatched() {
        var first = propagationChain();
        var batch = new ArrayList<>(first);
        for (var entry : first) {
            batch.add(new Entry(entry.id() + "2", entry.direction(), entry.method(),
                    entry.xml().replace("_init", "_init2").replace("_fail", "_fail2")
                            .replace("_remain", "_remain2").replace("_answer", "_answer2")
                            .replace("_final", "_final2").replace("suite.example/sp/", "suite.example/second/"),
                    entry.rawQuery(), entry.samlSummary(), entry.url() == null ? null
                            : entry.url().replace("suite.example/sp/", "suite.example/second/")));
        }
        assertEquals(Outcome.SATISFIED, fixture(batch.toArray(Entry[]::new))
                .evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void endpointsSharedAcrossLogoutProcessingsRemainAmbiguous() {
        var first = propagationChain();
        var batch = new ArrayList<>(first);
        for (var entry : first) {
            batch.add(new Entry(entry.id() + "2", entry.direction(), entry.method(),
                    entry.xml().replace("_init", "_init2").replace("_fail", "_fail2")
                            .replace("_remain", "_remain2").replace("_answer", "_answer2")
                            .replace("_final", "_final2").replace("other-sp-index", "another-session"),
                    entry.rawQuery(), entry.samlSummary(), entry.url()));
        }
        assertEquals(Outcome.NOT_VERIFIED, fixture(batch.toArray(Entry[]::new))
                .evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void unrelatedCompletedNormalLogoutDoesNotRequireFailureInduction() {
        var batch = new ArrayList<Entry>();
        batch.add(new Entry("normal-request", Direction.OUTBOUND, "POST", request("_normal", "2.0", ""),
                null, Map.of("type", "LogoutRequest")));
        batch.add(new Entry("normal-response", Direction.INBOUND, "POST",
                response("_normal-final", "2.0", "_normal", success()), null, Map.of("type", "LogoutResponse")));
        batch.addAll(propagationChain());
        assertEquals(Outcome.SATISFIED, fixture(batch.toArray(Entry[]::new))
                .evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void targetLocalActivityWithoutProcessingBoundaryStaysUnverified() {
        var chain = new ArrayList<>(propagationChain());
        chain.removeLast();
        chain.removeFirst();
        assertEquals(Outcome.NOT_VERIFIED, fixture(chain.toArray(Entry[]::new))
                .evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    @Test
    void uncompletedOlderInitiatorCannotBeMixedWithLaterProcessing() {
        var chain = new ArrayList<>(propagationChain());
        chain.addFirst(new Entry("older", Direction.OUTBOUND, "POST", request("_older", "2.0", ""),
                null, Map.of("type", "LogoutRequest"), "https://target.example/logout"));
        assertEquals(Outcome.NOT_VERIFIED, fixture(chain.toArray(Entry[]::new))
                .evaluate(LogoutTranscriptProfileCase.Rule.TARGET_PROPAGATION_CONTINUE));
    }

    private List<Entry> propagationChain() {
        return List.of(
                new Entry("initiator", Direction.OUTBOUND, "POST", request("_init", "2.0", ""),
                        null, Map.of("type", "LogoutRequest"), "https://target.example/logout"),
                new Entry("fail", Direction.INBOUND, "POST", withDestination(request("_fail", "2.0", ""),
                        "https://suite.example/sp/slo-fail"), null,
                        Map.of("type", "SloFailParticipant", "http_status", 500), "https://suite.example/sp/slo-fail"),
                new Entry("remain", Direction.INBOUND, "POST", withDestination(request("_remain", "2.0",
                        "<samlp:SessionIndex>other-sp-index</samlp:SessionIndex>"), "https://suite.example/sp/slo"),
                        null, Map.of("type", "LogoutRequest"), "https://suite.example/sp/slo"),
                new Entry("answered", Direction.OUTBOUND, "POST", withDestination(
                        response("_answer", "2.0", "_remain", success()), "https://target.example/logout"),
                        null, Map.of("type", "LogoutResponse"), "https://target.example/logout"),
                new Entry("final", Direction.INBOUND, "POST", response("_final", "2.0", "_init", success()),
                        null, Map.of("type", "LogoutResponse")));
    }

    private String withDestination(String xml, String destination) {
        return xml.replace(" IssueInstant=", " Destination=\"" + destination + "\" IssueInstant=");
    }

    private TranscriptEntry altered(TranscriptEntry e, String run, String decodedRef, int bytes, Map<String, Object> summary) {
        return new TranscriptEntry(e.id(), run, e.direction(), e.timestamp(), e.correlationId(), e.method(), e.url(),
                e.status(), e.headers(), e.bodyRef(), e.bodyBytes(), decodedRef, bytes, e.contentType(), e.rawQuery(), summary);
    }

    private Fixture fixture(Entry... entries) { return new Fixture(List.of(entries)); }
    private Entry inbound(String id, String xml, String query) {
        var summary = xml.contains("<samlp:Response")
                ? Map.<String, Object>of("type", "Response", "normalFlowAccepted", true)
                : Map.<String, Object>of();
        return new Entry(id, Direction.INBOUND, "POST", xml, query, summary);
    }
    private Entry inboundResponse(String id, String xml, Map<String, Object> summary) {
        return new Entry(id, Direction.INBOUND, "POST", xml, null, summary);
    }
    private Entry outbound(String id, String xml, String query) {
        return new Entry(id, Direction.OUTBOUND, "POST", xml, query, Map.of());
    }
    private Entry outboundRedirect(String id, String xml, String query) {
        return new Entry(id, Direction.OUTBOUND, "GET", xml, query, Map.of());
    }

    private String request(String id, String version, String extra) {
        return "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
                + "xmlns:aslo=\"urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo\" "
                + "ID=\"" + id + "\" Version=\"" + version + "\" IssueInstant=\"2026-08-29T00:00:00Z\">"
                + extra + "<saml:NameID>user</saml:NameID></samlp:LogoutRequest>";
    }

    private String response(String id, String version, String inResponseTo, String status) {
        return "<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:aslo=\"urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo\" "
                + "ID=\"" + id + "\" Version=\"" + version + "\" IssueInstant=\"2026-08-29T00:00:00Z\" "
                + "InResponseTo=\"" + inResponseTo + "\"><samlp:Status><samlp:StatusCode Value=\"" + status
                + "\"/></samlp:Status></samlp:LogoutResponse>";
    }
    private String success() { return "urn:oasis:names:tc:SAML:2.0:status:Success"; }

    private record Entry(
            String id, Direction direction, String method, String xml, String rawQuery,
            Map<String, Object> samlSummary, String url) {
        Entry(String id, Direction direction, String method, String xml, String rawQuery,
                Map<String, Object> samlSummary) {
            this(id, direction, method, xml, rawQuery, samlSummary, null);
        }
    }

    private static final class Fixture {
        private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
        private final List<TranscriptEntry> entries = new ArrayList<>();
        private final Map<String, byte[]> content = new HashMap<>();
        private boolean historyUnavailable;

        private Fixture(List<Entry> values) {
            var sequence = 0;
            for (var value : values) {
                var reference = value.xml() == null ? null : "decoded-" + value.id();
                var bytes = value.xml() == null ? new byte[0] : value.xml().getBytes(StandardCharsets.UTF_8);
                entries.add(new TranscriptEntry(
                        value.id(), RUN, value.direction(), Instant.parse("2026-08-29T00:00:00Z").plusSeconds(sequence++),
                        "corr", value.method(),
                        value.url() == null ? "https://suite.example/slo" : value.url(),
                        Integer.valueOf(500).equals(value.samlSummary().get("http_status")) ? 500 : 200,
                        Map.of(), null, 0,
                        reference, bytes.length, "application/xml", value.rawQuery(), value.samlSummary()));
                content.put(reference, bytes);
            }
        }

        private Outcome evaluate(LogoutTranscriptProfileCase.Rule rule) {
            return evaluate(rule, null);
        }

        private Outcome evaluate(LogoutTranscriptProfileCase.Rule rule, String entityId) {
            return result(rule, entityId).outcome();
        }

        private com.samlscope.core.evaluation.CaseOutcome result(LogoutTranscriptProfileCase.Rule rule, String entityId) {
            TranscriptRecorder recorder = new TranscriptRecorder() {
                @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                @Override public TranscriptEntry updateSamlAnalysis(
                        String entryId, String correlationId, Map<String, Object> samlSummary) {
                    throw new UnsupportedOperationException();
                }
                @Override public List<TranscriptEntry> list(String runId) {
                    if (historyUnavailable) throw new com.samlscope.core.transcript.TranscriptHistoryLimitExceeded(runId, 1);
                    return entries;
                }
            };
            TranscriptContentReader reader = entry -> content.get(entry.decodedSamlRef());
            return new LogoutTranscriptProfileCase(rule, List.of(), entityId)
                    .evaluate(RUN, recorder, reader);
        }
    }
}
