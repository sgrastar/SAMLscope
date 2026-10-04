package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.SamlEncryptionFixtureFactory;
import com.samlscope.saml.crypto.SamlXmlDecrypter;
import com.samlscope.saml.crypto.XmlSignatureVerifier;

class SamlLogoutRequestFactoryTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-09-15T00:00:00Z");
    private static final URI DESTINATION = URI.create("https://idp.example/slo");
    private static final String ISSUER = "https://suite.example/sp";
    private final SamlLogoutRequestFactory factory = new SamlLogoutRequestFactory();

    @Test void signedControlMatrixPreservesIdentifiersIndexesExpiryAndAsyncPlacement() {
        var keys = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC));
        var credentials = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var verifier = new XmlSignatureVerifier();
        for (var format : List.of("persistent", "transient")) {
            for (var value : List.of("user", " User & <😀>\t\n", "\u754c".repeat(256))) {
                var nameId = identifier(format, value);
                var before = SecureXml.serialize(nameId.getOwnerDocument());
                for (var indexes : List.of(List.<String>of(), List.of("session"), List.of("one", "two", "three"))) {
                    for (var async : List.of(false, true)) {
                        for (var expiry : List.of(NOW.minusSeconds(1), NOW.plusSeconds(600))) {
                            var xml = factory.build("_stable", DESTINATION, ISSUER, nameId, indexes, NOW, expiry, async);
                            assertArrayEquals(xml, factory.build("_stable", DESTINATION, ISSUER, nameId, indexes, NOW, expiry, async));
                            var root = SecureXml.parse(xml).getDocumentElement();
                            assertTrue(SamlSchemaValidation.isValid(root, SamlSchemaValidation.SchemaKind.PROTOCOL));
                            assertEquals(expiry.toString(), root.getAttribute("NotOnOrAfter"));
                            assertEquals(value, root.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION, "NameID").item(0).getTextContent());
                            var sessions = root.getElementsByTagNameNS(SamlLogoutRequestFactory.PROTOCOL, "SessionIndex");
                            assertEquals(indexes.size(), sessions.getLength());
                            for (int i=0;i<indexes.size();i++) assertEquals(indexes.get(i), sessions.item(i).getTextContent());
                            var extensions = root.getElementsByTagNameNS(SamlLogoutRequestFactory.ASYNC, "Asynchronous");
                            assertEquals(async ? 1 : 0, extensions.getLength());
                            if (async) assertEquals("Extensions", extensions.item(0).getParentNode().getLocalName());
                            var signed = factory.sign(xml, credentials);
                            var signedRoot = SecureXml.parse(signed).getDocumentElement();
                            assertTrue(SamlSchemaValidation.isValid(signedRoot, SamlSchemaValidation.SchemaKind.PROTOCOL));
                            assertTrue(verifier.hasValidEnvelopedSignature(signedRoot, credentials.certificate()));
                            assertThrows(IllegalArgumentException.class, () -> factory.sign(signed, credentials));
                            signedRoot.setAttribute("Destination", "https://other.example/slo");
                            assertFalse(verifier.hasValidEnvelopedSignature(signedRoot, credentials.certificate()));
                        }
                    }
                }
                assertArrayEquals(before, SecureXml.serialize(nameId.getOwnerDocument()));
            }
        }
    }

    @Test void encryptedIdentifiersUseEachSelectedRecipientAndAlgorithmWithoutChangingSessionReferences() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var recipients = List.of(generator.generateKeyPair(), generator.generateKeyPair());
        var nameId = identifier("persistent", "User & 😀");
        var before = SecureXml.serialize(nameId.getOwnerDocument());
        var decrypter = new SamlXmlDecrypter();
        for (var algorithms : SamlEncryptionFixtureFactory.matrix()) {
            for (int selected=0;selected<recipients.size();selected++) {
                var recipient = recipients.get(selected); var other = recipients.get(1-selected);
                var encrypted = factory.encryptedIdentifier(nameId, recipient.getPublic(), algorithms);
                var xml = factory.build("_encrypted", DESTINATION, ISSUER, encrypted, List.of("session"), NOW, null, false);
                var root = SecureXml.parse(xml).getDocumentElement();
                assertTrue(SamlSchemaValidation.isValid(root, SamlSchemaValidation.SchemaKind.PROTOCOL), algorithms.id());
                assertEquals(0, root.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION, "NameID").getLength());
                assertFalse(root.hasAttribute("NotOnOrAfter"));
                var ciphertext = (Element)root.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION, "EncryptedID").item(0);
                var decoded = decrypter.decrypt(ciphertext, recipient.getPrivate());
                assertEquals(nameId.getTextContent(), decoded.getTextContent());
                for (var attribute : List.of("Format", "NameQualifier", "SPNameQualifier", "SPProvidedID"))
                    assertEquals(nameId.getAttribute(attribute), decoded.getAttribute(attribute));
                assertThrows(SamlException.class, () -> decrypter.decrypt(ciphertext, other.getPrivate()));
                assertEquals("session", root.getElementsByTagNameNS(SamlLogoutRequestFactory.PROTOCOL, "SessionIndex").item(0).getTextContent());
            }
        }
        assertArrayEquals(before, SecureXml.serialize(nameId.getOwnerDocument()));
    }

    @Test void differentIdentifierSessionAndDestinationRemainIndependentFixtures() {
        var nameId = identifier("transient", "original");
        var normal = factory.build("_id", DESTINATION, ISSUER, nameId, List.of("original-session"), NOW, null, false);
        var changedSession = SecureXml.parse(factory.build("_id", DESTINATION, ISSUER, nameId,
                List.of("different-session"), NOW, null, false)).getDocumentElement();
        assertEquals("original", changedSession.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION,"NameID").item(0).getTextContent());
        var changedName = SecureXml.parse(factory.build("_id", DESTINATION, ISSUER, identifier("transient","different"),
                List.of("original-session"), NOW, null, false)).getDocumentElement();
        assertEquals("original-session", changedName.getElementsByTagNameNS(SamlLogoutRequestFactory.PROTOCOL,"SessionIndex").item(0).getTextContent());
        assertEquals("different", changedName.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION,"NameID").item(0).getTextContent());
        assertEquals("_id", SecureXml.parse(normal).getDocumentElement().getAttribute("ID"));
        var changedDestination = SecureXml.parse(factory.build("_id", URI.create("https://different.example/slo"), ISSUER,
                nameId,List.of("original-session"),NOW,null,false)).getDocumentElement();
        assertEquals("https://different.example/slo",changedDestination.getAttribute("Destination"));
        assertEquals("urn:fixture:qname", changedDestination.getElementsByTagNameNS(SamlLogoutRequestFactory.ASSERTION,"NameID").item(0).lookupNamespaceURI("custom"));
        assertThrows(IllegalArgumentException.class, () -> factory.build("",DESTINATION,ISSUER,nameId,List.of(),NOW,null,false));
        assertThrows(IllegalArgumentException.class, () -> factory.build("_id",URI.create("/relative"),ISSUER,nameId,List.of(),NOW,null,false));
        assertThrows(IllegalArgumentException.class, () -> factory.encryptedIdentifier(changedDestination,null,null));
    }

    private Element identifier(String format, String value) {
        var document = SecureXml.parse(("<parent xmlns:custom='urn:fixture:qname'><saml:NameID xmlns:saml='"
                + SamlLogoutRequestFactory.ASSERTION + "' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:"
                + format + "' NameQualifier='https://idp.example' SPNameQualifier='https://suite.example/sp' SPProvidedID='provided'/></parent>")
                .getBytes(StandardCharsets.UTF_8));
        var result = (Element)document.getDocumentElement().getFirstChild(); result.setTextContent(value); return result;
    }
}
