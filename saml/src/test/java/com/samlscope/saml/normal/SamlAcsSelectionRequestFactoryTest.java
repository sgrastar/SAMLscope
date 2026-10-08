package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SamlAcsSelectionRequestFactoryTest {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final URI DESTINATION = URI.create("https://idp.example/sso");
    private static final URI DEFAULT = URI.create("https://suite.example/p/test/sp/acs/0");
    private static final URI SECONDARY = URI.create("https://suite.example/p/test/sp/acs/1");

    @Test
    void bindingMatrixKeepsTheSameRegisteredAcsAndChangesOnlyProtocolBinding() {
        var bindings = Map.of(
                SamlAcsSelectionRequestFactory.Fixture.POST_BINDING, SamlAcsSelectionRequestFactory.POST,
                SamlAcsSelectionRequestFactory.Fixture.REDIRECT_BINDING, SamlAcsSelectionRequestFactory.REDIRECT,
                SamlAcsSelectionRequestFactory.Fixture.ARTIFACT_BINDING, SamlAcsSelectionRequestFactory.ARTIFACT,
                SamlAcsSelectionRequestFactory.Fixture.UNSUPPORTED_BINDING, SamlAcsSelectionRequestFactory.UNSUPPORTED);
        for (var entry : bindings.entrySet()) {
            var first = build(entry.getKey());
            assertArrayEquals(first, build(entry.getKey()));
            var root = SecureXml.parse(first).getDocumentElement();
            assertEquals(PROTOCOL, root.getNamespaceURI());
            assertEquals("AuthnRequest", root.getLocalName());
            assertEquals("_stable-request", root.getAttribute("ID"));
            assertEquals("2.0", root.getAttribute("Version"));
            assertEquals(DESTINATION.toString(), root.getAttribute("Destination"));
            assertEquals(DEFAULT.toString(), root.getAttribute("AssertionConsumerServiceURL"));
            assertEquals(entry.getValue(), root.getAttribute("ProtocolBinding"));
            assertFalse(root.hasAttribute("AssertionConsumerServiceIndex"));
        }
    }

    @Test
    void defaultControlOmitsAllSelectionAttributes() {
        var root = SecureXml.parse(build(SamlAcsSelectionRequestFactory.Fixture.DEFAULT)).getDocumentElement();
        assertFalse(root.hasAttribute("AssertionConsumerServiceIndex"));
        assertFalse(root.hasAttribute("AssertionConsumerServiceURL"));
        assertFalse(root.hasAttribute("ProtocolBinding"));
    }

    private byte[] build(SamlAcsSelectionRequestFactory.Fixture fixture) {
        return new SamlAcsSelectionRequestFactory().build(fixture, "_stable-request", DESTINATION,
                "https://suite.example/sp", DEFAULT, SECONDARY, Instant.parse("2026-10-08T00:00:00Z"));
    }
}
