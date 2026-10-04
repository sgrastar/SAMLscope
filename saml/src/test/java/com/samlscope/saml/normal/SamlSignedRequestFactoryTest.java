package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URI;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;

class SamlSignedRequestFactoryTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");

    @Test
    void omissionProbeDoesNotRequireANameIdAndRemainsFullySigned() throws Exception {
        var credentials = new FilePlanKeyStore(Files.createTempDirectory("nameid-omission-request"),
                Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var factory = new SamlSignedRequestFactory();
        var verifier = new XmlSignatureVerifier();
        for (var fixture : java.util.List.of(SamlSignedRequestFactory.Fixture.VALID,
                SamlSignedRequestFactory.Fixture.VALID_NO_NAMEID_POLICY)) {
            var request = SecureXml.parse(factory.build(fixture, "_omission_request", URI.create("https://idp.example/sso"),
                    "https://suite.example/sp", URI.create("https://suite.example/acs"), NOW, credentials)).getDocumentElement();
            assertEquals(fixture == SamlSignedRequestFactory.Fixture.VALID ? 1 : 0,
                    request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol", "NameIDPolicy").getLength());
            assertTrue(verifier.hasValidEnvelopedSignature(request, credentials.certificate()));
            request.setAttribute("AssertionConsumerServiceURL", "https://other.example/acs");
            assertFalse(verifier.hasValidEnvelopedSignature(request, credentials.certificate()));
        }
        assertEquals(SamlSignedRequestFactory.Fixture.VALID_NO_NAMEID_POLICY,
                com.samlscope.saml.metadata.MetadataService.Variant.NAMEID_OMISSION.requestFixture());
    }

    @Test
    void attributeServiceSelectionIsSignedAndIndependentOfAssertionConsumerService() throws Exception {
        var credentials = new FilePlanKeyStore(Files.createTempDirectory("attribute-request"),
                Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var factory = new SamlSignedRequestFactory();
        var verifier = new XmlSignatureVerifier();
        for (int index : new int[]{0, 1, 65535}) {
            var document = SecureXml.parse(factory.build(SamlSignedRequestFactory.Fixture.VALID,
                    "_attribute_request", URI.create("https://idp.example/sso"), "https://suite.example/sp",
                    URI.create("https://suite.example/sp/acs/0"), NOW, credentials, index));
            var request = document.getDocumentElement();
            assertEquals(Integer.toString(index), request.getAttribute("AttributeConsumingServiceIndex"));
            assertEquals("https://suite.example/sp/acs/0", request.getAttribute("AssertionConsumerServiceURL"));
            assertFalse(request.hasAttribute("AssertionConsumerServiceIndex"));
            assertTrue(verifier.hasValidEnvelopedSignature(request, credentials.certificate()));
            request.setAttribute("AttributeConsumingServiceIndex", Integer.toString(index == 0 ? 1 : 0));
            assertFalse(verifier.hasValidEnvelopedSignature(request, credentials.certificate()));
        }
        for (int invalid : new int[]{-1, 65536}) {
            assertThrows(IllegalArgumentException.class, () -> factory.build(SamlSignedRequestFactory.Fixture.VALID,
                    "_attribute_request", URI.create("https://idp.example/sso"), "https://suite.example/sp",
                    URI.create("https://suite.example/sp/acs/0"), NOW, credentials, invalid));
        }
        var omitted = SecureXml.parse(factory.build(SamlSignedRequestFactory.Fixture.VALID,
                "_attribute_request", URI.create("https://idp.example/sso"), "https://suite.example/sp",
                URI.create("https://suite.example/sp/acs/0"), NOW, credentials)).getDocumentElement();
        assertFalse(omitted.hasAttribute("AttributeConsumingServiceIndex"));
    }

    @Test
    void producesOneValidAndThreeCryptographicallyInvalidFixtures() throws Exception {
        var credentials = new FilePlanKeyStore(
                Files.createTempDirectory("signed-request"),
                Clock.fixed(NOW, ZoneOffset.UTC)).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var factory = new SamlSignedRequestFactory();
        var verifier = new XmlSignatureVerifier();
        for (var fixture : SamlSignedRequestFactory.Fixture.values()) {
            var document = SecureXml.parse(factory.build(
                    fixture, "_request", URI.create("https://idp.example/sso"),
                    "https://suite.example/sp", URI.create("https://suite.example/sp/acs/0"),
                    NOW, credentials));
            if (fixture == SamlSignedRequestFactory.Fixture.DEFAULT_ACS) {
                for (var attribute : java.util.List.of("AssertionConsumerServiceURL",
                        "AssertionConsumerServiceIndex", "ProtocolBinding")) {
                    assertFalse(document.getDocumentElement().hasAttribute(attribute), attribute);
                }
            }
            var valid = verifier.hasValidEnvelopedSignature(
                    document.getDocumentElement(), credentials.certificate());
            var deliberatelyInvalid = java.util.Set.of(
                    SamlSignedRequestFactory.Fixture.TAMPERED_ACS,
                    SamlSignedRequestFactory.Fixture.BAD_REFERENCE,
                    SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE).contains(fixture);
            if (deliberatelyInvalid) assertFalse(valid, fixture.name());
            else assertTrue(valid, fixture.name());
        }
    }
}
