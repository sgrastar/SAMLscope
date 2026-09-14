package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;

class SamlStringValueCaseTest {
    private final SamlStringValueCase rule = new SamlStringValueCase();

    @Test
    void acceptsNonEmptySchemaTypedStrings() {
        assertEquals(Outcome.SATISFIED, rule.evaluate(List.of(message("good", response("2.0", "accepted")))).outcome());
    }

    @Test
    void rejectsWhitespaceOnlyStringAttributesAndElements() {
        var attribute = rule.evaluate(List.of(message("attribute", response(" ", "accepted"))));
        var element = rule.evaluate(List.of(message("element", response("2.0", " \t "))));

        assertEquals(Outcome.VIOLATED, attribute.outcome());
        assertEquals(Outcome.VIOLATED, element.outcome());
    }

    @Test
    void permitsTheExplicitEmptyAttributeValueExceptionButNotWhitespaceOnlyContent() {
        var empty = rule.evaluate(List.of(message("empty", assertion(""))));
        var whitespace = rule.evaluate(List.of(message("whitespace", assertion("   "))));

        assertEquals(Outcome.SATISFIED, empty.outcome());
        assertEquals(Outcome.VIOLATED, whitespace.outcome());
    }

    @Test
    void schemaFailureIsNotMisreportedAsThisObligationViolation() {
        assertEquals(Outcome.NOT_VERIFIED, rule.evaluate(List.of(message("bad-schema", """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>
                """))).outcome());
    }

    @Test
    void observesNameIdSimpleContentAndDoesNotApplyAttributeValueEmptyExceptionToIt() {
        for (var fixture : com.samlscope.saml.normal.SamlTypedStringFixtures.matrix()) {
            if (fixture.placement() != com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.PERSISTENT_NAMEID
                    && fixture.placement() != com.samlscope.saml.normal.SamlTypedStringFixtures.Placement.TRANSIENT_NAMEID) continue;
            var root = fixture.create();
            var xml = new String(com.samlscope.saml.normal.SecureXml.serialize(root.getOwnerDocument()), StandardCharsets.UTF_8);
            assertEquals(Outcome.SATISFIED, rule.evaluate(List.of(message(fixture.id(), xml))).outcome(), fixture.id());
            for (var invalid : List.of("", " \t\n")) {
                root.setTextContent(invalid);
                xml = new String(com.samlscope.saml.normal.SecureXml.serialize(root.getOwnerDocument()), StandardCharsets.UTF_8);
                assertEquals(Outcome.VIOLATED, rule.evaluate(List.of(message(fixture.id(), xml))).outcome(), fixture.id());
            }
        }
    }

    private String response(String version, String statusMessage) {
        return """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  ID="_response" Version="%s" IssueInstant="2026-08-29T00:00:00Z">
                  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                    <samlp:StatusMessage>%s</samlp:StatusMessage>
                  </samlp:Status>
                </samlp:Response>
                """.formatted(version, statusMessage);
    }

    private String assertion(String value) {
        return """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:xs="http://www.w3.org/2001/XMLSchema"
                  ID="_assertion" Version="2.0" IssueInstant="2026-08-29T00:00:00Z">
                  <saml:Issuer>https://idp.example</saml:Issuer>
                  <saml:AttributeStatement><saml:Attribute Name="urn:test">
                    <saml:AttributeValue xsi:type="xs:string">%s</saml:AttributeValue>
                  </saml:Attribute></saml:AttributeStatement>
                </saml:Assertion>
                """.formatted(value);
    }

    private TargetTranscriptMessages.Message message(String ref, String xml) {
        return new TargetTranscriptMessages.Message(ref, xml.getBytes(StandardCharsets.UTF_8));
    }
}
