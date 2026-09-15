package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SecureXml;

class NormalFlowBrowserObservationTest {
    @TempDir java.nio.file.Path directory;
    @Test
    void autoCompletesOnlyTheApprovedNormalFlowCases() {
        assertTrue(NormalFlowBrowserObservation.supports("IIP-SSO03-a-idp-01"));
        assertTrue(NormalFlowBrowserObservation.supports("IIP-SSO01-g-idp-01"));
        assertTrue(NormalFlowBrowserObservation.supports("IIP-SSO01-a-idp-01"));
        assertTrue(NormalFlowBrowserObservation.supports("IIP-SSO01-d-idp-01"));
    }

    @Test
    void correlatedSuccessWithAnAssertionProvesTheSpInitiatedProfileFlow() {
        var request = request("https://idp.example/sso", "2.0", "_request");
        assertOutcome("IIP-SSO01-a-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)));
        assertEmpty("IIP-SSO01-a-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "",
                        assertion("issuer", null, null)));
    }

    @Test
    void redirectAndPostAuthnRequestsTogetherProveBothInboundBindings() {
        assertEmpty("IIP-SSO02-a-idp-01",
                message("GET", "https://idp.example/sso", """
                        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          ID="_redirect" Version="2.0"/>
                        """));
        assertOutcome("IIP-SSO02-a-idp-01", Outcome.SATISFIED,
                message("GET", "https://idp.example/sso", """
                        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          ID="_redirect" Version="2.0"/>
                        """),
                message("POST", "https://idp.example/sso", """
                        <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          ID="_post" Version="2.0"/>
                        """));
    }

    @Test
    void subjectTriggeredErrorsMustNotContainAssertions() {
        var controlRequest = request("https://idp.example/sso", "2.0", "_control");
        var controlResponse = response(
                "POST", "https://suite.example/acs", "2.0", "_control",
                assertion("issuer", null, null));
        var subjectRequest = message("GET", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_subject" Version="2.0"><saml:Subject><saml:NameID>missing</saml:NameID></saml:Subject>
                </samlp:AuthnRequest>
                """);
        assertOutcome("IIP-SSO01-d-idp-01", Outcome.SATISFIED,
                controlRequest, controlResponse, subjectRequest, errorResponse("POST", "_subject"));
        var assertionErrorXml = new String(response(
                "POST", "https://suite.example/acs", "2.0", "_subject",
                assertion("issuer", null, null)).xml(), StandardCharsets.UTF_8)
                .replace("urn:oasis:names:tc:SAML:2.0:status:Success",
                        "urn:oasis:names:tc:SAML:2.0:status:Responder");
        assertOutcome("IIP-SSO01-d-idp-01", Outcome.VIOLATED,
                controlRequest, controlResponse, subjectRequest,
                message("POST", "https://suite.example/acs", assertionErrorXml));
    }

    @Test
    void successfulPostResponseProvesPostResponseSupport() {
        assertOutcome("IIP-SSO03-a-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
        assertEmpty("IIP-SSO03-a-idp-01",
                response("GET", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
    }

    @Test
    void successfulResponsesNeedAssertionsForBothInitiationPaths() {
        var spInitiated = response(
                "POST", "https://suite.example/acs", "2.0", "_request",
                assertion("issuer", null, null));
        assertEmpty("IIP-SSO01-g-idp-01", spInitiated);
        assertOutcome("IIP-SSO01-g-idp-01", Outcome.SATISFIED, spInitiated,
                response("POST", "https://suite.example/acs", "2.0", "",
                        assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-g-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_request", ""));
    }

    @Test
    void multipleCorrelatedErrorPathsProvePostErrorResponseSupport() {
        var passive = message("POST", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_passive" Version="2.0" IsPassive="true"/>
                """);
        var format = message("POST", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_format" Version="2.0"><samlp:NameIDPolicy
                  Format="urn:samlscope:probe:unknown-nameid-format:test"/></samlp:AuthnRequest>
                """);
        assertEmpty("IIP-SSO03-b-idp-01", passive,
                errorResponse("POST", "_passive"));
        assertOutcome("IIP-SSO03-b-idp-01", Outcome.SATISFIED,
                passive, errorResponse("POST", "_passive"), format, errorResponse("POST", "_format"));
        assertOutcome("IIP-SSO03-b-idp-01", Outcome.VIOLATED,
                passive, errorResponse("GET", "_passive"), format, errorResponse("POST", "_format"));
    }

    @Test
    void redirectDeliveryIsRejectedAndDiversePostPathsProveTheRedirectAcsControl() {
        assertEmpty("IIP-SSO01-x-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-x-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)),
                errorResponse("POST", "_error"));
        assertOutcome("IIP-SSO01-x-idp-01", Outcome.VIOLATED,
                response("GET", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
    }

    @Test
    void tlsUsesTheUrlsOfBothActualExchanges() {
        var request = request("https://idp.example/sso", "2.0", "_request");
        var response = response("POST", "https://suite.example/acs", "2.0", "_request",
                assertion("issuer", null, null));
        assertOutcome("IIP-SSO01-ad-idp-01", Outcome.SATISFIED, request, response);
        assertOutcome("IIP-SSO01-ad-idp-01", Outcome.VIOLATED,
                request("http://idp.example/sso", "2.0", "_request"), response);
        assertEmpty("IIP-SSO01-ad-idp-01", response);
    }

    @Test
    void responseVersionIsComparedWithItsCorrelatedRequest() {
        var request = request("https://idp.example/sso", "2.0", "_request");
        assertOutcome("IIP-SSO01-en-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-en-idp-01", Outcome.VIOLATED, request,
                response("POST", "https://suite.example/acs", "2.1", "_request", assertion("issuer", null, null)));
        assertEmpty("IIP-SSO01-en-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "", assertion("issuer", null, null)));
    }

    @Test
    void lowerResponseVersionsNeedTheNarrowTooHighException() {
        var request = request("https://idp.example/sso", "2.0", "_request");
        assertOutcome("IIP-SSO01-eo-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-eo-idp-01", Outcome.VIOLATED, request,
                response("POST", "https://suite.example/acs", "1.1", "_request", ""));
    }

    @Test
    void unsupportedVersionResponsesUseTheVersionMismatchTopLevelStatus() {
        var request = request("https://idp.example/sso", "1.1", "_old");
        assertOutcome("IIP-SSO01-ep-idp-01", Outcome.SATISFIED, request,
                versionError("_old", "VersionMismatch"));
        assertOutcome("IIP-SSO01-ep-idp-01", Outcome.VIOLATED, request,
                versionError("_old", "Responder"));
    }

    @Test
    void responseIssuerIsCheckedAgainstTheTargetEntityWhenPresent() {
        var expected = "https://idp.example/realms/samlscope";
        assertEquals(
                Outcome.SATISFIED,
                NormalFlowBrowserObservation.evaluate(
                                "IIP-SSO01-h-idp-01",
                                List.of(responseWithIssuer(expected, null)),
                                expected)
                        .orElseThrow().outcome());
        assertEquals(
                Outcome.SATISFIED_WITH_NOTE,
                NormalFlowBrowserObservation.evaluate(
                                "IIP-SSO01-h-idp-01",
                                List.of(response("POST", "https://suite.example/acs", "2.0", "_request",
                                        assertion("issuer", null, null))),
                                expected)
                        .orElseThrow().outcome());
        assertEquals(
                Outcome.VIOLATED,
                NormalFlowBrowserObservation.evaluate(
                                "IIP-SSO01-h-idp-01",
                                List.of(responseWithIssuer(expected, "urn:example:wrong-format")),
                                expected)
                        .orElseThrow().outcome());
        assertEquals(
                Outcome.VIOLATED,
                NormalFlowBrowserObservation.evaluate(
                                "IIP-SSO01-h-idp-01",
                                List.of(responseWithIssuer("https://wrong.example/idp", null)),
                                expected)
                        .orElseThrow().outcome());
        assertTrue(NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-h-idp-01", List.of(responseWithIssuer(expected, null)), null).isEmpty());
    }

    @Test
    void signedOrEncryptedResponsesRequireAResponseIssuer() {
        assertOutcome("IIP-SSO01-h1-idp-01", Outcome.SATISFIED,
                message("POST", "https://suite.example/acs", """
                        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                          xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_r" Version="2.0">
                          <saml:Issuer>https://idp.example</saml:Issuer><ds:Signature/>
                          <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                        </samlp:Response>
                        """));
        assertOutcome("IIP-SSO01-h1-idp-01", Outcome.VIOLATED,
                message("POST", "https://suite.example/acs", """
                        <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0">
                          <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                          <saml:EncryptedAssertion/>
                        </samlp:Response>
                        """));
        assertEmpty("IIP-SSO01-h1-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("https://idp.example", null, null)));
    }

    @Test
    void everyAssertionIssuerIdentifiesTheRespondingIdp() {
        var expected = "https://idp.example/realms/samlscope";
        assertEquals(Outcome.SATISFIED,
                NormalFlowBrowserObservation.evaluate(
                        "IIP-SSO01-i-idp-01",
                        List.of(response("POST", "https://suite.example/acs", "2.0", "_request",
                                assertion(expected, null, null))), expected).orElseThrow().outcome());
        assertEquals(Outcome.VIOLATED,
                NormalFlowBrowserObservation.evaluate(
                        "IIP-SSO01-i-idp-01",
                        List.of(response("POST", "https://suite.example/acs", "2.0", "_request",
                                assertion("https://upstream.example/idp", null, null))), expected)
                        .orElseThrow().outcome());
    }

    @Test
    void authnStatementsAreCorrelatedAndRequireAValidAuthenticationInstant() {
        var request = message("GET", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_request" Version="2.0" IssueInstant="2026-08-30T00:00:01Z"/>
                """);
        assertOutcome("IIP-SSO01-l-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)));
        // AuthnInstant identifies when authentication occurred. SAML2Prof 4.1 does not require
        // it to precede the AuthnRequest IssueInstant; a fresh authentication normally follows
        // the request. Keep the passive oracle from rejecting that conforming behavior.
        assertOutcome("IIP-SSO01-l-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null).replace(
                                "2026-08-30T00:00:00Z", "2026-08-30T00:00:02Z")));
        assertOutcome("IIP-SSO01-l-idp-01", Outcome.VIOLATED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null).replace(
                                "2026-08-30T00:00:00Z", "not-a-date")));
        assertOutcome("IIP-SSO01-l-idp-01", Outcome.VIOLATED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null).replaceAll("(?s)<saml:AuthnStatement.*?/>", "")));
    }

    @Test
    void bearerNotBeforeCheckDoesNotConfuseConditionsNotBefore() {
        assertOutcome("IIP-SSO01-k1-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, "2026-08-30T00:00:00Z")));
        assertOutcome("IIP-SSO01-k1-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", "2026-08-30T00:00:00Z", "2026-08-30T00:00:00Z")));
    }

    @Test
    void bearerRecipientAndExpiryNeedTheActualAcsAndAnAlternateAcsControl() {
        var first = responseAt(
                "https://suite.example/acs/0", "_one", "https://suite.example/acs/0",
                "2026-08-30T00:05:00Z");
        assertEmpty("IIP-SSO01-k-idp-01", first);
        assertOutcome("IIP-SSO01-k-idp-01", Outcome.SATISFIED, first,
                responseAt(
                        "https://suite.example/acs/1", "_two", "https://suite.example/acs/1",
                        "2026-08-30T00:05:00Z"));
        assertOutcome("IIP-SSO01-k-idp-01", Outcome.VIOLATED, first,
                responseAt(
                        "https://suite.example/acs/1", "_two", "https://suite.example/acs/0",
                        "2026-08-30T00:05:00Z"));
        assertOutcome("IIP-SSO01-k-idp-01", Outcome.VIOLATED, first,
                responseAt(
                        "https://suite.example/acs/1", "_two", "https://suite.example/acs/1", ""));
    }

    @Test
    void everyIssuedAssertionNeedsABearerConfirmation() {
        assertOutcome("IIP-SSO01-j-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-j-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null) + assertionWithoutBearer("issuer")));
    }

    @Test
    void everyBearerAssertionNeedsTheExactRequesterAudience() {
        var request = request("https://idp.example/sso", "2.0", "_request");
        var requestTwo = message("GET", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_request-two" Version="2.0">
                  <saml:Issuer>https://suite.example/sp</saml:Issuer>
                </samlp:AuthnRequest>
                """);
        assertEmpty("IIP-SSO01-m-idp-01", request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithAudience("issuer", "https://suite.example/sp")));
        assertOutcome("IIP-SSO01-m-idp-01", Outcome.SATISFIED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithAudience("issuer", "https://suite.example/sp")),
                requestTwo,
                response("POST", "https://suite.example/acs", "2.0", "_request-two",
                        assertionWithAudience("issuer", "https://suite.example/sp")
                                .replace("_assertion", "_assertion-two")));
        assertOutcome("IIP-SSO01-m-idp-01", Outcome.VIOLATED, request,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithAudience("issuer", "https://suite.example/sp/")));
    }

    @Test
    void twoConsecutiveFlowsProveBothResponseAndBearerCorrelation() {
        var requestOne = request("https://idp.example/sso", "2.0", "_one");
        var requestTwo = request("https://idp.example/sso", "2.0", "_two");
        var responseOne = response("POST", "https://suite.example/acs", "2.0", "_one",
                assertionWithConfirmation("issuer", "_one"));
        var responseTwo = response("POST", "https://suite.example/acs", "2.0", "_two",
                assertionWithConfirmation("issuer", "_two"));
        assertEmpty("IIP-SSO01-k2-idp-01", requestOne, responseOne);
        assertOutcome("IIP-SSO01-k2-idp-01", Outcome.SATISFIED,
                requestOne, responseOne, requestTwo, responseTwo);
        assertOutcome("IIP-SSO01-ap-idp-01", Outcome.SATISFIED,
                requestOne, responseOne, requestTwo, responseTwo);
        assertOutcome("IIP-SSO01-k2-idp-01", Outcome.VIOLATED,
                requestOne, response("POST", "https://suite.example/acs", "2.0", "_one",
                        assertionWithConfirmation("issuer", "_stale")));
        assertOutcome("IIP-SSO01-ap-idp-01", Outcome.VIOLATED,
                requestOne, response("POST", "https://suite.example/acs", "2.0", "_unknown",
                        assertionWithConfirmation("issuer", "_unknown")));
    }

    @Test
    void aSingleAssertionIsReportedAsTheApprovedVacuousCase() {
        assertOutcome("IIP-SSO01-i1-idp-01", Outcome.SATISFIED_WITH_NOTE,
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)));
        assertOutcome("IIP-SSO01-i1-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer-a", null, null) + assertion("issuer-b", null, null)));
        assertOutcome("IIP-SSO01-i1-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null) + assertion("issuer", null, null)));
    }

    @Test
    void nameIdLimitsCountUnicodeCodePointsAndRequireTheRelevantFormat() {
        var within = "x".repeat(255) + "\uD83D\uDE00";
        var over = within + "y";
        assertOutcome("IIP-SSO05-b1-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, within)));
        assertOutcome("IIP-SSO05-b1-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, over)));
        assertEmpty("IIP-SSO05-a2-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "value")));
    }

    @Test
    void correlatedPolicyRequestProvesPersistentAndTransientSupport() {
        var persistentRequest = requestWithNameId("_persistent", NormalFlowBrowserObservation.PERSISTENT);
        var persistentResponse = response(
                "POST", "https://suite.example/acs", "2.0", "_persistent",
                assertionWithNameId("issuer", NormalFlowBrowserObservation.PERSISTENT, "persistent-id"));
        assertOutcome("IIP-SSO05-a-idp-01", Outcome.SATISFIED,
                persistentRequest, persistentResponse);

        var transientRequest = requestWithNameId("_transient", NormalFlowBrowserObservation.TRANSIENT);
        assertOutcome("IIP-SSO05-b-idp-01", Outcome.SATISFIED, transientRequest,
                response("POST", "https://suite.example/acs", "2.0", "_transient",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "transient-id")));
        assertOutcome("IIP-SSO05-b-idp-01", Outcome.VIOLATED, transientRequest,
                response("POST", "https://suite.example/acs", "2.0", "_transient",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.PERSISTENT, "wrong-id")));
        assertEmpty("IIP-SSO05-a-idp-01", persistentResponse);

        assertTrue(NormalFlowBrowserObservation.acceptsActiveScenarioEvidence("IIP-SSO05-a-idp-01"));
        assertTrue(NormalFlowBrowserObservation.acceptsActiveScenarioEvidence("IIP-SSO01-h-idp-01"));
        assertTrue(NormalFlowBrowserObservation.acceptsActiveScenarioEvidence("IIP-SSO01-x-idp-01"));
    }

    @Test
    void transientIdentifiersAreLexicallyValidAndChangeAcrossLogins() {
        assertEmpty("IIP-SSO05-b2-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_one",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "_one")));
        assertOutcome("IIP-SSO05-b2-idp-01", Outcome.SATISFIED,
                response("POST", "https://suite.example/acs", "2.0", "_one",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "_one")),
                response("POST", "https://suite.example/acs", "2.0", "_two",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "nämé")));
        assertOutcome("IIP-SSO05-b2-idp-01", Outcome.VIOLATED,
                response("POST", "https://suite.example/acs", "2.0", "_one",
                        assertionWithNameId("issuer", NormalFlowBrowserObservation.TRANSIENT, "1invalid")));
    }

    @Test
    void optionalEncryptionIsRecordedWithoutFabricatingAViolation() {
        var outcome = evaluate("IIP-IDP09-b-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null))).orElseThrow();
        assertEquals(Outcome.SATISFIED_WITH_NOTE, outcome.outcome());
        assertEquals(0, outcome.details().get("encrypted_ids"));
        assertEquals(0, outcome.details().get("encrypted_attributes"));
        assertEmpty("IIP-IDP09-b-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        "<saml:EncryptedAssertion/>"));
    }

    @Test
    void postAssertionsAreProtectedByAValidResponseOrAssertionSignature() {
        var credentials = new FilePlanKeyStore(
                directory, java.time.Clock.fixed(
                        Instant.parse("2026-08-30T00:00:00Z"), java.time.ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var signed = signedResponse(credentials);
        assertEquals(Outcome.SATISFIED,
                NormalFlowBrowserObservation.evaluate(
                        "IIP-SSO01-v-idp-01", List.of(signed), null,
                        List.of(credentials.certificate())).orElseThrow().outcome());
        assertEquals(Outcome.VIOLATED,
                NormalFlowBrowserObservation.evaluate(
                        "IIP-SSO01-v-idp-01",
                        List.of(response("POST", "https://suite.example/acs", "2.0", "_request",
                                assertion("issuer", null, null))), null,
                        List.of(credentials.certificate())).orElseThrow().outcome());
        assertTrue(NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-v-idp-01", List.of(signed), null, List.of()).isEmpty());
        assertTrue(NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-v-idp-01",
                List.of(response("POST", "https://suite.example/acs", "2.0", "_request",
                        "<saml:EncryptedAssertion/>")), null,
                List.of(credentials.certificate())).isEmpty());
    }

    @Test
    void browserSignatureRecommendationsUseCryptographicEvidenceWithoutAQuestionnaire() {
        var credentials = new FilePlanKeyStore(
                directory, java.time.Clock.fixed(
                        Instant.parse("2026-08-30T00:00:00Z"), java.time.ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var signed = signedResponse(credentials);
        var certificates = List.of(credentials.certificate());

        assertEquals(Outcome.SATISFIED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-et-idp-01", List.of(signed), null, certificates).orElseThrow().outcome());
        assertEquals(Outcome.SATISFIED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-es-idp-01", List.of(signed), null, certificates).orElseThrow().outcome());
        var unsigned = response("POST", "https://suite.example/acs", "2.0", "_request",
                assertion("issuer", null, null));
        assertEquals(Outcome.VIOLATED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-et-idp-01", List.of(unsigned), null, certificates).orElseThrow().outcome());
        assertEquals(Outcome.VIOLATED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-es-idp-01", List.of(unsigned), null, certificates).orElseThrow().outcome());
    }

    @Test
    void consentSignatureCheckAppliesOnlyToValuesThatIndicateObtainedConsent() {
        var credentials = new FilePlanKeyStore(
                directory, java.time.Clock.fixed(
                        Instant.parse("2026-08-30T00:00:00Z"), java.time.ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var certificates = List.of(credentials.certificate());
        assertEquals(Outcome.SATISFIED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-au-idp-01", List.of(signedConsentResponse(credentials)), null, certificates)
                .orElseThrow().outcome());
        var unsignedObtained = withConsent(
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)),
                "urn:oasis:names:tc:SAML:2.0:consent:current-explicit");
        assertEquals(Outcome.VIOLATED, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-au-idp-01", List.of(unsignedObtained), null, certificates)
                .orElseThrow().outcome());
        var unavailable = withConsent(unsignedObtained,
                "urn:oasis:names:tc:SAML:2.0:consent:unavailable");
        assertEquals(Outcome.SATISFIED_WITH_NOTE, NormalFlowBrowserObservation.evaluate(
                "IIP-SSO01-au-idp-01", List.of(unavailable), null, certificates)
                .orElseThrow().outcome());
    }

    @Test
    void idpInitiatedLoginCompletesChoiceAndCorrelationCasesFromTheTranscript() {
        var unsolicited = response("POST", "https://suite.example/acs", "2.0", "",
                assertion("issuer", null, null));
        assertOutcome("IIP-SSO01-y-idp-01", Outcome.SATISFIED, unsolicited);
        assertOutcome("IIP-SSO01-z-idp-01", Outcome.SATISFIED_WITH_NOTE, unsolicited);
        assertEmpty("IIP-SSO01-y-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)));
    }

    @Test
    void malformedEvidenceNeverGetsSilentlyDroppedFromAnAutomaticPass() {
        assertEmpty("IIP-SSO01-x-idp-01",
                response("POST", "https://suite.example/acs", "2.0", "_request", assertion("issuer", null, null)),
                message("POST", "https://suite.example/acs", "<broken"));
    }

    @Test
    void malformedOutboundProbesDoNotDisableUnrelatedNormalFlowObservations() {
        var malformedOutbound = new NormalFlowBrowserObservation.Message(
                "doctype-probe", "POST", "https://idp.example/sso",
                Instant.parse("2026-08-30T00:00:01Z"),
                "<!DOCTYPE AuthnRequest [<!ELEMENT AuthnRequest EMPTY>]><AuthnRequest/>"
                        .getBytes(StandardCharsets.UTF_8), false);
        assertOutcome("IIP-SSO01-a-idp-01", Outcome.SATISFIED,
                request("https://idp.example/sso", "2.0", "_request"),
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)),
                malformedOutbound);

        var malformedInbound = new NormalFlowBrowserObservation.Message(
                "malformed-response", "POST", "https://suite.example/acs",
                Instant.parse("2026-08-30T00:00:01Z"),
                "<!DOCTYPE Response [<!ELEMENT Response EMPTY>]><Response/>"
                        .getBytes(StandardCharsets.UTF_8), true);
        assertEmpty("IIP-SSO01-a-idp-01",
                request("https://idp.example/sso", "2.0", "_request"),
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)),
                malformedInbound);
    }

    private void assertOutcome(String caseId, Outcome expected, NormalFlowBrowserObservation.Message... messages) {
        assertEquals(expected, evaluate(caseId, messages).orElseThrow().outcome());
    }

    private void assertEmpty(String caseId, NormalFlowBrowserObservation.Message... messages) {
        assertTrue(evaluate(caseId, messages).isEmpty());
    }

    private java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> evaluate(
            String caseId, NormalFlowBrowserObservation.Message... messages) {
        return NormalFlowBrowserObservation.evaluate(caseId, List.of(messages));
    }

    private NormalFlowBrowserObservation.Message request(String url, String version, String id) {
        return message("GET", url, """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="%s">
                  <saml:Issuer>https://suite.example/sp</saml:Issuer>
                </samlp:AuthnRequest>
                """.formatted(id, version));
    }

    private NormalFlowBrowserObservation.Message response(
            String method, String url, String version, String inResponseTo, String assertions) {
        return message(method, url, """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_response" Version="%s" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  %s
                </samlp:Response>
                """.formatted(version, inResponseTo, assertions));
    }

    private NormalFlowBrowserObservation.Message errorResponse(String method, String inResponseTo) {
        return message(method, "https://suite.example/acs", """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_error" Version="2.0" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status>
                </samlp:Response>
                """.formatted(inResponseTo));
    }

    private NormalFlowBrowserObservation.Message versionError(String inResponseTo, String status) {
        return message("POST", "https://suite.example/acs", """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_error" Version="2.0" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></samlp:Status>
                </samlp:Response>
                """.formatted(inResponseTo, status));
    }

    private NormalFlowBrowserObservation.Message requestWithNameId(String id, String format) {
        return message("POST", "https://idp.example/sso", """
                <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0">
                  <saml:Issuer>https://suite.example/sp</saml:Issuer>
                  <samlp:NameIDPolicy Format="%s"/>
                </samlp:AuthnRequest>
                """.formatted(id, format));
    }

    private NormalFlowBrowserObservation.Message responseWithIssuer(String issuer, String format) {
        var formatAttribute = format == null ? "" : " Format=\"" + format + "\"";
        return message("POST", "https://suite.example/acs", """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_response" Version="2.0" InResponseTo="_request">
                  <saml:Issuer%s>%s</saml:Issuer>
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  %s
                </samlp:Response>
                """.formatted(formatAttribute, issuer, assertion(issuer, null, null)));
    }

    private NormalFlowBrowserObservation.Message responseAt(
            String actualAcs, String inResponseTo, String recipient, String notOnOrAfter) {
        return message("POST", actualAcs, """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_response" Version="2.0" IssueInstant="2026-08-30T00:00:00Z" InResponseTo="%s">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
                  <saml:Assertion ID="_assertion">
                    <saml:Issuer>issuer</saml:Issuer>
                    <saml:Subject><saml:NameID>subject</saml:NameID>
                      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                        <saml:SubjectConfirmationData Recipient="%s" NotOnOrAfter="%s" InResponseTo="%s"/>
                      </saml:SubjectConfirmation>
                    </saml:Subject>
                    <saml:AuthnStatement AuthnInstant="2026-08-30T00:00:00Z"/>
                  </saml:Assertion>
                </samlp:Response>
                """.formatted(inResponseTo, recipient, notOnOrAfter, inResponseTo));
    }

    private String assertion(String issuer, String subjectNotBefore, String conditionsNotBefore) {
        var subjectAttribute = subjectNotBefore == null ? "" : " NotBefore=\"" + subjectNotBefore + "\"";
        var conditions = conditionsNotBefore == null ? "" : "<saml:Conditions NotBefore=\"" + conditionsNotBefore + "\"/>";
        return """
                <saml:Assertion ID="_assertion" Version="2.0">
                  <saml:Issuer>%s</saml:Issuer>
                  <saml:Subject><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData%s/>
                  </saml:SubjectConfirmation></saml:Subject>
                  <saml:AuthnStatement AuthnInstant="2026-08-30T00:00:00Z"/>
                  %s
                </saml:Assertion>
                """.formatted(issuer, subjectAttribute, conditions);
    }

    private String assertionWithNameId(String issuer, String format, String value) {
        return """
                <saml:Assertion ID="_assertion" Version="2.0">
                  <saml:Issuer>%s</saml:Issuer>
                  <saml:Subject><saml:NameID Format="%s">%s</saml:NameID></saml:Subject>
                </saml:Assertion>
                """.formatted(issuer, format, value);
    }

    private String assertionWithoutBearer(String issuer) {
        return """
                <saml:Assertion ID="_assertion-other" Version="2.0">
                  <saml:Issuer>%s</saml:Issuer>
                  <saml:Subject><saml:SubjectConfirmation Method="urn:example:holder-of-key"/></saml:Subject>
                  <saml:AuthnStatement AuthnInstant="2026-08-30T00:00:00Z"/>
                </saml:Assertion>
                """.formatted(issuer);
    }

    private String assertionWithAudience(String issuer, String audience) {
        return assertion(issuer, null, null).replace("</saml:Assertion>", """
                  <saml:Conditions><saml:AudienceRestriction><saml:Audience>%s</saml:Audience>
                  </saml:AudienceRestriction></saml:Conditions>
                </saml:Assertion>
                """.formatted(audience));
    }

    private String assertionWithConfirmation(String issuer, String inResponseTo) {
        return assertion(issuer, null, null).replace(
                "<saml:SubjectConfirmationData/>",
                "<saml:SubjectConfirmationData InResponseTo=\"" + inResponseTo + "\"/>");
    }

    private NormalFlowBrowserObservation.Message message(String method, String url, String xml) {
        return new NormalFlowBrowserObservation.Message(
                "entry-" + Math.abs(xml.hashCode()), method, url,
                Instant.parse("2026-08-30T00:00:01Z"), xml.getBytes(StandardCharsets.UTF_8));
    }

    private NormalFlowBrowserObservation.Message signedResponse(
            com.samlscope.saml.crypto.PlanCredentials credentials) {
        var unsigned = response("POST", "https://suite.example/acs", "2.0", "_request",
                assertion("issuer", null, null));
        var document = SecureXml.parse(unsigned.xml());
        var status = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Status").item(0);
        new XmlSigner().sign(document.getDocumentElement(), credentials, status);
        return new NormalFlowBrowserObservation.Message(
                "signed-response", "POST", "https://suite.example/acs",
                Instant.parse("2026-08-30T00:00:01Z"), SecureXml.serialize(document));
    }

    private NormalFlowBrowserObservation.Message signedConsentResponse(
            com.samlscope.saml.crypto.PlanCredentials credentials) {
        var unsigned = withConsent(
                response("POST", "https://suite.example/acs", "2.0", "_request",
                        assertion("issuer", null, null)),
                "urn:oasis:names:tc:SAML:2.0:consent:current-explicit");
        var document = SecureXml.parse(unsigned.xml());
        var status = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Status").item(0);
        new XmlSigner().sign(document.getDocumentElement(), credentials, status);
        return new NormalFlowBrowserObservation.Message(
                "signed-consent-response", "POST", "https://suite.example/acs",
                Instant.parse("2026-08-30T00:00:01Z"), SecureXml.serialize(document));
    }

    private NormalFlowBrowserObservation.Message withConsent(
            NormalFlowBrowserObservation.Message source, String consent) {
        var document = SecureXml.parse(source.xml());
        document.getDocumentElement().setAttribute("Consent", consent);
        return new NormalFlowBrowserObservation.Message(
                source.evidenceRef() + "-consent", source.method(), source.url(),
                source.timestamp(), SecureXml.serialize(document));
    }
}
