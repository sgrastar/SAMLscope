package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
