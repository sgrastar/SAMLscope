package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;

class SamlProtocolServiceTest {
    @TempDir java.nio.file.Path directory;

    @Test
    void requiredPlanAdvertisesAndSignsBootstrapUsingRawRedirectBytes() {
        var original = SamlTestFixtures.idpPlan();
        var plan = new com.samlscope.core.plan.TestPlan(original.id(), original.name(), original.profile(),
                original.target(), original.suiteMetadataDelivery(), original.declaredFeatures(),
                new com.samlscope.core.plan.TestPlan.Parameters(180, 300, "",
                        com.samlscope.core.plan.TestPlan.RequestSigningMode.REQUIRED),
                original.interaction(), original.createdAt(), original.updatedAt());
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keys = new FilePlanKeyStore(directory, clock);
        var service = new SamlProtocolService(URI.create("https://peer.example"), keys,
                new XmlSigner(), new OpenSamlReader(), clock);
        var request = service.buildAuthnRequest(plan, URI.create("https://idp.example/sso"), "a+b /\u65e5\u672c\u8a9e");
        var verifier = new com.samlscope.saml.binding.RedirectSignatureVerifier();
        assertTrue(verifier.isValid(request.redirect().getRawQuery(), keys.getOrCreate(plan.id()).certificate()));
        org.junit.jupiter.api.Assertions.assertFalse(verifier.isValid(
                request.redirect().getRawQuery().replace("RelayState=", "RelayState=tampered"),
                keys.getOrCreate(plan.id()).certificate()));
        var ecp = service.buildEcpAuthnRequest(plan, URI.create("https://idp.example/ecp"),
                URI.create("https://peer.example/paos"), "relay");
        assertTrue(new com.samlscope.saml.crypto.XmlSignatureVerifier().hasValidEnvelopedSignature(
                SecureXml.parse(ecp.xml()).getDocumentElement(), keys.getOrCreate(plan.id()).certificate()));
        // This named negative control must stay unsigned even in a required Plan.
        var negative = service.buildEcpChannelBindingAuthnRequest(plan, URI.create("https://idp.example/ecp"),
                URI.create("https://peer.example/paos"), "relay", "tls-server-end-point", "YWJj", false);
        assertEquals(0, SecureXml.parse(negative.xml()).getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").getLength());
        var metadata = new com.samlscope.saml.metadata.MetadataService(URI.create("https://peer.example"), keys, new XmlSigner(), clock);
        var root = SecureXml.parse(metadata.generate(plan));
        assertEquals("true", ((org.w3c.dom.Element) root.getElementsByTagNameNS(
                com.samlscope.saml.metadata.MetadataService.MD, "SPSSODescriptor").item(0)).getAttribute("AuthnRequestsSigned"));
    }

    @Test
    void redirectAuthnRequestRoundTripsWithoutReconstructingTheRawQuery() {
        var plan = SamlTestFixtures.idpPlan();
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var request = service.buildAuthnRequest(plan, URI.create("https://idp.example/sso"), "run_0123456789ABCDEFGHJKMNPQRS");
        var decoded = service.decodeRedirect(request.redirect().getRawQuery(), "SAMLRequest");
        assertEquals(request.id(), decoded.parsed().summary().get("id"));
        assertEquals("run_0123456789ABCDEFGHJKMNPQRS", decoded.relayState());
        assertTrue(new String(decoded.xml(), java.nio.charset.StandardCharsets.UTF_8).contains("AuthnRequest"));
    }

    @Test
    void generatedResponseRetainsAValidAssertionSignatureAfterSerialization() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var service = new SamlProtocolService(URI.create("https://peer.example"),
                keyStore, new XmlSigner(), new OpenSamlReader(), clock);
        var request = service.buildAuthnRequest(plan, URI.create("https://idp.example/sso"), "relay");
        var decoded = service.decodeRedirect(request.redirect().getRawQuery(), "SAMLRequest");
        var response = service.buildResponse(plan, decoded, URI.create("https://sp.example/acs"), "subject");
        var document = SecureXml.parse(response.xml());
        var assertion = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
        assertion.setIdAttribute("ID", true);
        var signatureElement = (org.w3c.dom.Element) assertion.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        var signature = new XMLSignature(signatureElement, "");
        assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()));
    }

    @Test
    void secondaryIdpResponseUsesItsOwnIssuerAndKey() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var service = new SamlProtocolService(URI.create("https://peer.example"),
                keyStore, new XmlSigner(), new OpenSamlReader(), clock);
        var request = service.buildAuthnRequest(plan, URI.create("https://idp.example/sso"), "relay");
        var decoded = service.decodeRedirect(request.redirect().getRawQuery(), "SAMLRequest");
        var response = service.buildSecondaryIdpResponse(
                plan, decoded, URI.create("https://sp.example/acs"), "subject");
        var document = SecureXml.parse(response.xml());
        var issuer = document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer").item(0).getTextContent();
        assertEquals("https://peer.example/p/plan_0123456789ABCDEFGHJKMNPQRS/idp/secondary", issuer);
        var assertion = (org.w3c.dom.Element) document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion").item(0);
        assertion.setIdAttribute("ID", true);
        var signatureElement = (org.w3c.dom.Element) assertion.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        var signature = new XMLSignature(signatureElement, "");
        assertTrue(signature.checkSignatureValue(keyStore.getOrCreate(plan.id(), "secondary-idp").certificate()));
        assertNotEquals(keyStore.getOrCreate(plan.id()).certificate(),
                keyStore.getOrCreate(plan.id(), "secondary-idp").certificate());
    }

    @Test
    void channelBindingAuthnRequestContainsTheExtensionAndAValidSignature() throws Exception {
        var plan = SamlTestFixtures.idpPlan();
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var keyStore = new FilePlanKeyStore(directory, clock);
        var service = new SamlProtocolService(URI.create("https://peer.example"),
                keyStore, new XmlSigner(), new OpenSamlReader(), clock);
        var request = service.buildEcpChannelBindingAuthnRequest(
                plan, URI.create("https://idp.example/ecp"), URI.create("https://peer.example/paos"),
                "relay", "tls-server-end-point", "YWJj", true);
        var document = SecureXml.parse(request.xml());
        var root = document.getDocumentElement();
        root.setIdAttribute("ID", true);
        assertEquals("YWJj", document.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:protocol:ext:channel-binding", "ChannelBindings")
                .item(0).getTextContent());
        var signatureElement = (org.w3c.dom.Element) root.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        assertTrue(new XMLSignature(signatureElement, "")
                .checkSignatureValue(keyStore.getOrCreate(plan.id()).certificate()));
    }

    @Test
    void bindingDecodePreservesDtdBytesBeforeSecureXmlParsingRejectsThem() {
        var plan = SamlTestFixtures.idpPlan();
        var clock = Clock.fixed(Instant.parse("2026-08-29T00:00:00Z"), ZoneOffset.UTC);
        var service = new SamlProtocolService(URI.create("https://peer.example"),
                new FilePlanKeyStore(directory, clock), new XmlSigner(), new OpenSamlReader(), clock);
        var xml = "<!DOCTYPE Response [<!ELEMENT Response EMPTY>]><Response/>"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var body = "SAMLResponse=" + java.net.URLEncoder.encode(
                Base64.getEncoder().encodeToString(xml), java.nio.charset.StandardCharsets.UTF_8);

        var raw = service.decodePostRaw(body.getBytes(java.nio.charset.StandardCharsets.UTF_8), "SAMLResponse");

        assertTrue(java.util.Arrays.equals(xml, raw.xml()));
        assertThrows(SamlException.class, () -> service.parse(raw));
    }
}
