package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.normal.SamlErrorProbeRequestFactory.Probe;

class SamlErrorProbeRequestFactoryTest {
    private final SamlErrorProbeRequestFactory factory = new SamlErrorProbeRequestFactory();

    @Test
    void buildsSchemaValidRequestsWithRegisteredResponseLocation() {
        for (var probe : Probe.values()) {
            if (probe == Probe.DTD_AUTHN_REQUEST || probe == Probe.DTD_EXTERNAL_ENTITY_AUTHN_REQUEST) {
                continue;
            }
            var document = SecureXml.parse(factory.build(
                    probe,
                    "_request",
                    URI.create("https://idp.example/sso"),
                    "https://suite.example/sp",
                    URI.create("https://suite.example/acs"),
                    Instant.parse("2026-08-29T00:00:00Z")));

            assertTrue(SamlSchemaValidation.isValid(
                    document.getDocumentElement(), SamlSchemaValidation.SchemaKind.PROTOCOL), probe.name());
            if (probe == Probe.ACS_SELECTION_OMITTED) {
                assertFalse(document.getDocumentElement().hasAttribute("AssertionConsumerServiceURL"));
                assertFalse(document.getDocumentElement().hasAttribute("ProtocolBinding"));
            } else {
                assertEquals("https://suite.example/acs",
                        document.getDocumentElement().getAttribute("AssertionConsumerServiceURL"));
            }
        }
    }

    @Test
    void stringMatrixPreservesCodePointsAndXmlEscapingAcrossParsing() {
        assertEquals(20, SamlErrorProbeRequestFactory.stringProbes().size());
        for (var probe : SamlErrorProbeRequestFactory.stringProbes()) {
            var bytes = factory.build(probe, "_request", URI.create("https://idp.example/sso"),
                    "https://suite.example/sp", URI.create("https://suite.example/acs"), Instant.EPOCH);
            var xml = new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
            var value = SecureXml.parse(bytes).getDocumentElement().getAttribute("ProviderName");
            int length = probe.name().endsWith("255") ? 255 : 256;
            assertEquals(length, value.codePointCount(0, value.length()), probe.name());
            assertEquals(SamlErrorProbeRequestFactory.parsedStringValue(probe), value);
            assertTrue(value.codePoints().noneMatch(point -> point >= 0xD800 && point <= 0xDFFF));
            if (probe.name().contains("SUPPLEMENTARY")) assertEquals(length * 2, value.length());
            if (probe.name().contains("COMBINING")) {
                assertTrue(java.text.Normalizer.normalize(value, java.text.Normalizer.Form.NFC).length() < length);
            }
            if (probe.name().contains("XML_SPECIAL")) {
                for (var point : new int[]{'<', '&', '\"', '\'', '>'}) assertTrue(value.indexOf(point) >= 0);
                assertTrue(xml.contains("&amp;"));
                assertTrue(xml.contains("&lt;"));
            }
            if (probe.name().contains("TAB_REFERENCE") || probe.name().contains("LF_REFERENCE")) {
                char whitespace = probe.name().contains("TAB") ? '\t' : '\n';
                assertTrue(value.indexOf(whitespace) >= 0, probe.name());
                var reference = whitespace == '\t' ? "&#9;" : "&#10;";
                var hexReference = whitespace == '\t' ? "&#x9;" : "&#xA;";
                assertTrue(xml.contains(reference) || xml.contains(hexReference), probe.name());
                var literal = xml.replace(reference, String.valueOf(whitespace))
                        .replace(hexReference, String.valueOf(whitespace));
                var normalized = SecureXml.parse(literal.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                        .getDocumentElement().getAttribute("ProviderName");
                assertEquals(value.replace(whitespace, ' '), normalized,
                        "Literal attribute whitespace and character references exercise different parsed values");
            }
        }
    }

    @Test
    void buildsIntentionalDtdFixturesWithoutParsingThemInTheSuite() {
        for (var probe : java.util.List.of(
                Probe.DTD_AUTHN_REQUEST, Probe.DTD_EXTERNAL_ENTITY_AUTHN_REQUEST)) {
            var xml = new String(factory.build(
                    probe, "_request", URI.create("https://idp.example/sso"),
                    "https://suite.example/sp", URI.create("https://suite.example/acs"),
                    Instant.parse("2026-08-29T00:00:00Z")), java.nio.charset.StandardCharsets.UTF_8);
            assertTrue(xml.contains("<!DOCTYPE samlp:AuthnRequest"));
            assertThrows(SamlException.class, () -> SecureXml.parse(
                    xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        }
    }

    @Test
    void eachProbeChangesOnlyItsApprovedTrigger() {
        var unknown = request(Probe.UNKNOWN_NAMEID_FORMAT);
        var context = request(Probe.UNSATISFIABLE_AUTHN_CONTEXT);
        var passive = request(Probe.PASSIVE_WITHOUT_SESSION);

        assertEquals(1, unknown.getElementsByTagNameNS(protocol(), "NameIDPolicy").getLength());
        assertEquals(0, unknown.getElementsByTagNameNS(protocol(), "RequestedAuthnContext").getLength());
        assertFalse(unknown.getDocumentElement().hasAttribute("IsPassive"));
        assertEquals(1, context.getElementsByTagNameNS(protocol(), "RequestedAuthnContext").getLength());
        assertEquals("true", passive.getDocumentElement().getAttribute("IsPassive"));
        assertEquals("2026-08-29T00:00:00.000123456Z",
                request(Probe.SUBMILLISECOND_ISSUE_INSTANT).getDocumentElement().getAttribute("IssueInstant"));
    }

    @Test
    void extensionAndAnyAttributeProbesCoverEveryApprovedPlacement() {
        var protocol = request(Probe.UNKNOWN_EXTENSION);
        var advice = request(Probe.UNKNOWN_ADVICE_EXTENSION);
        var metadata = request(Probe.UNKNOWN_METADATA_EXTENSION);
        var confirmation = request(Probe.UNKNOWN_ANY_ATTRIBUTE);
        var attribute = request(Probe.UNKNOWN_ATTRIBUTE_ANY_ATTRIBUTE);

        assertEquals("protocol-extensions", onlyUnknown(protocol).getAttribute("placement"));
        assertEquals(1, advice.getElementsByTagNameNS(assertion(), "Advice").getLength());
        assertEquals("assertion-advice", onlyUnknown(advice).getAttribute("placement"));
        assertEquals(1, metadata.getElementsByTagNameNS(metadata(), "Extensions").getLength());
        assertEquals("metadata-extensions", onlyUnknown(metadata).getAttribute("placement"));
        assertEquals(1, confirmation.getElementsByTagNameNS(assertion(), "SubjectConfirmationData").getLength());
        assertTrue(((org.w3c.dom.Element) confirmation.getElementsByTagNameNS(
                assertion(), "SubjectConfirmationData").item(0)).hasAttributeNS(
                        "urn:samlscope:probe:unknown-attribute", "fixture"));
        assertEquals(1, attribute.getElementsByTagNameNS(assertion(), "Attribute").getLength());
        assertTrue(((org.w3c.dom.Element) attribute.getElementsByTagNameNS(
                assertion(), "Attribute").item(0)).hasAttributeNS(
                        "urn:samlscope:probe:unknown-attribute", "fixture"));
    }

    private org.w3c.dom.Element onlyUnknown(org.w3c.dom.Document document) {
        var values = document.getElementsByTagNameNS(
                "urn:samlscope:probe:unknown-extension", "UnknownExtension");
        assertEquals(1, values.getLength());
        return (org.w3c.dom.Element) values.item(0);
    }

    private org.w3c.dom.Document request(Probe probe) {
        return SecureXml.parse(factory.build(
                probe, "_request", URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/acs"), Instant.parse("2026-08-29T00:00:00Z")));
    }

    private String protocol() { return "urn:oasis:names:tc:SAML:2.0:protocol"; }
    private String assertion() { return "urn:oasis:names:tc:SAML:2.0:assertion"; }
    private String metadata() { return "urn:oasis:names:tc:SAML:2.0:metadata"; }
}
