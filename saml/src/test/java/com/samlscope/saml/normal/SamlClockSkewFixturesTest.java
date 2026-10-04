package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class SamlClockSkewFixturesTest {
    @TempDir Path data;
    private static final Instant NOW = Instant.parse("2026-10-03T09:00:00Z");
    private static final Duration T = Duration.ofSeconds(75), DELTA = Duration.ofSeconds(25);
    private static final String A = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private PlanCredentials key() { return new FilePlanKeyStore(data, Clock.fixed(NOW, ZoneOffset.UTC))
            .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS"); }

    @Test void requestsHaveActualSignaturesAndOnlyTheExplicitTargetPolicyChangesTheTime() {
        var factory = new SamlClockSkewFixtures(); var key = key();
        var expected = Map.of(SamlClockSkewFixtures.IssueInstantShift.CONTROL, NOW,
                SamlClockSkewFixtures.IssueInstantShift.WITHIN_PAST, NOW.minusSeconds(50),
                SamlClockSkewFixtures.IssueInstantShift.WITHIN_FUTURE, NOW.plusSeconds(50),
                SamlClockSkewFixtures.IssueInstantShift.OUTSIDE_PAST, NOW.minusSeconds(100),
                SamlClockSkewFixtures.IssueInstantShift.OUTSIDE_FUTURE, NOW.plusSeconds(100));
        for (var row : expected.entrySet()) {
            var raw = factory.request(row.getKey(), "_same-input", URI.create("https://idp.example/sso"),
                    "https://suite.example/sp", URI.create("https://suite.example/acs"), NOW, T, DELTA, key);
            var root = SecureXml.parse(raw).getDocumentElement();
            assertEquals(row.getValue(), Instant.parse(root.getAttribute("IssueInstant")));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, key.certificate()));
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedReferenceDigests(root));
            assertFalse(root.hasAttribute("ForceAuthn")); assertFalse(root.hasAttribute("IsPassive"));
            assertEquals("https://suite.example/sp", root.getElementsByTagNameNS(A,"Issuer").item(0).getTextContent());
            assertEquals(0, root.getElementsByTagNameNS(P,"Extensions").getLength());
        }
    }
    @Test void conditionBoundariesAreSeparateValidIntervalsAndActuallyResigned() {
        var key = key(); var factory = new SamlClockSkewFixtures();
        for (var shift : SamlClockSkewFixtures.ConditionShift.values()) {
            var raw = factory.assertion(assertionTemplate(), shift, NOW, T, DELTA, key);
            var root = SecureXml.parse(raw).getDocumentElement();
            var conditions = (Element)root.getElementsByTagNameNS(A,"Conditions").item(0);
            var lower = Instant.parse(conditions.getAttribute("NotBefore"));
            var upper = Instant.parse(conditions.getAttribute("NotOnOrAfter"));
            assertTrue(lower.isBefore(upper));
            assertEquals(shift == SamlClockSkewFixtures.ConditionShift.NOT_BEFORE_WITHIN_FUTURE
                    ? NOW.plusSeconds(50) : NOW.minusSeconds(175), lower);
            assertEquals(shift == SamlClockSkewFixtures.ConditionShift.NOT_ON_OR_AFTER_WITHIN_PAST
                    ? NOW.minusSeconds(50) : NOW.plusSeconds(175), upper);
            assertEquals("https://suite.example/sp", root.getElementsByTagNameNS(A,"Audience").item(0).getTextContent());
            assertEquals("same-principal", root.getElementsByTagNameNS(A,"NameID").item(0).getTextContent());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,key.certificate()));
        }
    }
    @Test void metadataOriginalKeepsTheRoleAndKeysWhileExpiryIsSigned() {
        var key = key(); var factory = new SamlClockSkewFixtures();
        var template = ("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"_md\" entityID=\"https://suite.example/sp\"><md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://suite.example/acs\" index=\"0\"/></md:SPSSODescriptor></md:EntityDescriptor>").getBytes(StandardCharsets.UTF_8);
        for (boolean shifted : List.of(false,true)) {
            var root = SecureXml.parse(factory.metadata(template,shifted,NOW,T,DELTA,key)).getDocumentElement();
            assertEquals(shifted ? NOW.minusSeconds(50) : NOW.plusSeconds(175),Instant.parse(root.getAttribute("validUntil")));
            assertEquals(1,root.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata","SPSSODescriptor").getLength());
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root,key.certificate()));
        }
    }
    @Test void missingZeroOrInvalidTargetToleranceNeverFallsBackToSuiteDefaults() {
        var factory = new SamlClockSkewFixtures();var key=key();
        for(var tolerance:List.of(Duration.ZERO,Duration.ofSeconds(-1),DELTA))
            assertThrows(IllegalArgumentException.class,()->factory.assertion(assertionTemplate(),SamlClockSkewFixtures.ConditionShift.CONTROL,NOW,tolerance,DELTA,key));
        assertThrows(NullPointerException.class,()->factory.assertion(assertionTemplate(),SamlClockSkewFixtures.ConditionShift.CONTROL,NOW,null,DELTA,key));
        assertThrows(IllegalArgumentException.class,()->factory.assertion("<AuthnRequest/>".getBytes(StandardCharsets.UTF_8),SamlClockSkewFixtures.ConditionShift.CONTROL,NOW,T,DELTA,key));
    }
    private static byte[] assertionTemplate() {
        return ("<saml:Assertion xmlns:saml=\""+A+"\" ID=\"_assertion\" Version=\"2.0\" IssueInstant=\""+NOW+"\"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>same-principal</saml:NameID></saml:Subject><saml:Conditions><saml:AudienceRestriction><saml:Audience>https://suite.example/sp</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>").getBytes(StandardCharsets.UTF_8);
    }
}
