package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class AttributePolicyAttributeReaderTest {
    @TempDir java.nio.file.Path directory;
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
    private record Fixture(Element response, Element metadata, PlanCredentials key) {}

    private String attribute(String name, String value) {
        return "<s:Attribute Name='urn:samlscope:test:policy:" + name + "' NameFormat='" + FORMAT
                + "'><s:AttributeValue>" + value + "</s:AttributeValue></s:Attribute>";
    }
    private Element parse(String xml) { return SecureXml.parse(xml.getBytes(StandardCharsets.UTF_8)).getDocumentElement(); }

    private Fixture fixture(String attributes, boolean encrypted) throws Exception {
        var key = new FilePlanKeyStore(directory, Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");
        var metadata = parse("<md:EntityDescriptor xmlns:md='" + MD + "' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='https://sp.example'>"
                + "<md:SPSSODescriptor><md:KeyDescriptor use='encryption'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + Base64.getEncoder().encodeToString(key.certificate().getEncoded())
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:SPSSODescriptor></md:EntityDescriptor>");
        var assertion = parse("<s:Assertion xmlns:s='" + S + "' ID='_assertion'><s:Issuer>https://idp.example</s:Issuer><s:AttributeStatement>"
                + attributes + "</s:AttributeStatement></s:Assertion>");
        new XmlSigner().sign(assertion, key, null);
        if (encrypted) {
            assertion = new SamlEncryptionFixtureFactory().encrypt(SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion,
                    assertion, key.certificate().getPublicKey(), new SamlEncryptionFixtureFactory.Algorithms(
                            SamlEncryptionFixtureFactory.Content.AES128_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,
                            SamlEncryptionFixtureFactory.Digest.SHA256, SamlEncryptionFixtureFactory.Mgf.DEFAULT));
        }
        var response = parse("<p:Response xmlns:p='" + P + "' xmlns:s='" + S + "' ID='_response'><s:Issuer>https://idp.example</s:Issuer>"
                + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status></p:Response>");
        response.appendChild(response.getOwnerDocument().importNode(assertion, true));
        new XmlSigner().sign(response, key, null);
        return new Fixture(response, metadata, key);
    }
    private AttributePolicyAttributeReader.Observation read(Fixture f, String run) {
        return AttributePolicyAttributeReader.read(run, f.response(), "https://idp.example", List.of(f.key().certificate()),
                f.metadata(), Optional.of(f.key()));
    }

    @Test void encryptedAndPlainEvidenceAgreeWithoutPersistingAttributeValues() throws Exception {
        String attributes = attribute("anchor", "synthetic-user") + attribute("required", "synthetic-user");
        var plain = read(fixture(attributes, false), "run_test");
        var encrypted = read(fixture(attributes, true), "run_test");
        assertEquals(plain, encrypted);
        assertEquals(Set.of("anchor", "required"), plain.markers());
        assertFalse(plain.toString().contains("synthetic-user"));
        assertFalse(plain.toString().contains(plain.attributeInputFingerprint()));
        assertNotEquals(plain.attributeInputFingerprint(), read(fixture(attributes, true), "another_run").attributeInputFingerprint());
        assertNotEquals(plain.attributeInputFingerprint(), read(fixture(attribute("anchor", "other-user"), true), "run_test").attributeInputFingerprint());
    }

    @Test void incompleteOrAmbiguousAttributesCannotProveAbsenceOrSameInput() throws Exception {
        for (String attributes : List.of(
                attribute("required", "synthetic-user"),
                attribute("anchor", "synthetic-user") + attribute("required", "other-user"),
                attribute("anchor", "synthetic-user") + attribute("anchor", "synthetic-user"),
                attribute("anchor", ""),
                attribute("anchor", "<s:Nested/>"),
                attribute("anchor", "synthetic-user") + "<s:EncryptedAttribute/>",
                attribute("anchor", "synthetic-user") + attribute("unknown", "synthetic-user"),
                attribute("anchor", "synthetic-user").replace(FORMAT, "urn:unexpected"))) {
            var f = fixture(attributes, true);
            var exception = assertThrows(IllegalArgumentException.class, () -> read(f, "run_test"));
            assertFalse(exception.toString().contains("synthetic-user"));
            assertNull(exception.getCause());
        }
    }

    @Test void signatureOrMatchingEncryptionKeyFailureCannotProduceMarkers() throws Exception {
        var f = fixture(attribute("anchor", "synthetic-user"), true);
        f.response().setAttribute("Destination", "https://tampered.example");
        assertThrows(IllegalArgumentException.class, () -> read(f, "run_test"));
        var valid = fixture(attribute("anchor", "synthetic-user"), true);
        assertThrows(IllegalArgumentException.class, () -> AttributePolicyAttributeReader.read("run_test", valid.response(),
                "https://idp.example", List.of(valid.key().certificate()), valid.metadata(), Optional.empty()));
        var other = new FilePlanKeyStore(directory, Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "other");
        assertThrows(IllegalArgumentException.class, () -> AttributePolicyAttributeReader.read("run_test", valid.response(),
                "https://idp.example", List.of(valid.key().certificate()), valid.metadata(), Optional.of(other)));
    }
}
