package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.crypto.SamlXmlDecrypter;

class TranscriptConfigurationObservationTest {
    @Test
    void emptyEncryptedWrapperDoesNotProveCapabilityButItsPlacementCanBeObserved() {
        var message = response("<saml:EncryptedAssertion/>");
        assertTrue(evaluate("IIP-IDP09-a-idp-01", message).isEmpty());
        assertOutcome("IIP-SSO01-ez-idp-01", Outcome.SATISFIED, message);
        assertOutcome("IIP-SSO01-ez-idp-01", Outcome.VIOLATED,
                response("<saml:Assertion/><saml:EncryptedAssertion/>"));
    }

    @Test
    void absenceDoesNotClaimEncryptionCapabilityButClosesPassivePlacementRules() {
        var message = response("<saml:Assertion><saml:Subject><saml:NameID>alice</saml:NameID>"
                + "</saml:Subject></saml:Assertion>");
        assertTrue(evaluate("IIP-IDP09-a-idp-01", message).isEmpty());
        assertOutcome("IIP-SSO01-ez-idp-01", Outcome.SATISFIED_WITH_NOTE, message);
        assertOutcome("IIP-SSO01-fd-idp-01", Outcome.SATISFIED_WITH_NOTE, message);
        assertOutcome("IIP-SSO01-fe-idp-01", Outcome.SATISFIED_WITH_NOTE, message);
    }

    @Test
    void encryptedIdentifiersAndAttributesMustReplacePlaintextInTheirSchemaLocation() {
        assertOutcome("IIP-SSO01-fd-idp-01", Outcome.SATISFIED,
                response("<saml:Assertion><saml:Subject><saml:EncryptedID/></saml:Subject></saml:Assertion>"));
        assertOutcome("IIP-SSO01-fd-idp-01", Outcome.VIOLATED,
                response("<saml:Assertion><saml:Subject><saml:NameID>alice</saml:NameID>"
                        + "<saml:EncryptedID/></saml:Subject></saml:Assertion>"));
        assertOutcome("IIP-SSO01-fe-idp-01", Outcome.SATISFIED,
                response("<saml:Assertion><saml:AttributeStatement><saml:EncryptedAttribute/>"
                        + "</saml:AttributeStatement></saml:Assertion>"));
        assertOutcome("IIP-SSO01-fe-idp-01", Outcome.VIOLATED,
                response("<saml:Assertion><saml:AttributeStatement><saml:Attribute Name=\"a\"/>"
                        + "<saml:EncryptedAttribute/></saml:AttributeStatement></saml:Assertion>"));
    }

    @Test
    void malformedOrMissingTranscriptKeepsApprovedQuestionnaireFallback() {
        assertTrue(evaluate("IIP-SSO01-ez-idp-01", "<broken".getBytes(StandardCharsets.UTF_8)).isEmpty());
        assertTrue(TranscriptConfigurationObservation.evaluate(
                "IIP-SSO01-ez-idp-01", List.of(), null, new SamlXmlDecrypter()).isEmpty());
    }

    private void assertOutcome(String caseId, Outcome expected, byte[] message) {
        assertEquals(expected, evaluate(caseId, message).orElseThrow().outcome());
    }

    private java.util.Optional<com.samlscope.core.evaluation.CaseOutcome> evaluate(
            String caseId, byte[] message) {
        return TranscriptConfigurationObservation.evaluate(
                caseId,
                List.of(new TranscriptConfigurationObservation.Message("transcript:one", message)),
                null,
                new SamlXmlDecrypter());
    }

    private byte[] response(String contents) {
        return ("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
                + contents + "</samlp:Response>").getBytes(StandardCharsets.UTF_8);
    }
}
