package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Independent semantic controls: no manifest mismatch or signature gate can mask these checks. */
class NativeConfigurationSourceMetadataIdentityIndependentTest {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String TARGET = "http://localhost:18380/idp";
    private static final String LOGOUT = "http://localhost:18380/simplesaml/module.php/saml/idp/singleLogout";
    private static final String REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private static final String POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    @TempDir static Path temporaryKeys;
    private static byte[] addedDer, restoredDer;
    private static String addedCertificate, restoredCertificate, source, recipient;
    private static ObjectNode before, restored;

    @BeforeAll static void fixture() throws Exception {
        var keys = new FilePlanKeyStore(temporaryKeys, Clock.systemUTC());
        var oldKey = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "old");
        var newKey = keys.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "new");
        restoredDer = oldKey.certificate().getEncoded(); addedDer = newKey.certificate().getEncoded();
        restoredCertificate = Base64.getEncoder().encodeToString(restoredDer);
        addedCertificate = Base64.getEncoder().encodeToString(addedDer);
        var json = new JsonCodec().mapper(); before = json.createObjectNode(); restored = json.createObjectNode();
        before.putArray("baselineKeys").addObject().put("spkiSha256", hash(newKey.certificate().getPublicKey().getEncoded()));
        ((com.fasterxml.jackson.databind.node.ArrayNode) before.path("baselineKeys")).addObject()
                .put("spkiSha256", hash(oldKey.certificate().getPublicKey().getEncoded()));
        restored.putArray("keys").addObject().put("spkiSha256", hash(oldKey.certificate().getPublicKey().getEncoded()));
        source = metadata(key("signing", addedCertificate) + key("encryption", addedCertificate)
                + key("signing", restoredCertificate) + service(REDIRECT));
        recipient = metadata(key("signing", restoredCertificate) + key("encryption", restoredCertificate)
                + service(REDIRECT) + service(POST));
    }

    private static String metadata(String changingChildren) {
        return "<md:EntityDescriptor xmlns:md=\"" + MD + "\" xmlns:ds=\"" + DS + "\" entityID=\"" + TARGET
                + "\"><md:IDPSSODescriptor protocolSupportEnumeration=\"" + P + "\" errorURL=\"https://target.example/error\">"
                + changingChildren + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                + "<md:SingleSignOnService Binding=\"" + REDIRECT + "\" Location=\"https://target.example/sso\"/>"
                + "<md:SingleSignOnService Binding=\"" + POST + "\" Location=\"https://target.example/sso\"/>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    private static String key(String use, String certificate) {
        return "<md:KeyDescriptor use=\"" + use + "\"><ds:KeyInfo xmlns:ds=\"" + DS + "\"><ds:X509Data>"
                + "<ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
    }
    private static String service(String binding) {
        return "<md:SingleLogoutService Binding=\"" + binding + "\" Location=\"" + LOGOUT + "\"/>";
    }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static String hash(byte[] value) throws Exception { return NativeConfigurationSourceRunEvidence.hash(value); }
    private static JsonNode identity(String a, String b) throws Exception {
        return NativeConfigurationSourceRunEvidence.targetIdentity(bytes(a), bytes(b), addedDer, before, restored);
    }
    private static void rejected(String label, String a, String b) {
        assertThrows(Exception.class, () -> identity(a, b), label);
    }

    @Test void permitsOnlyTheRecordedKeyRotationAndSameUrlPostWithBothRawDigestsRetained() throws Exception {
        var identity = identity(source, recipient);
        assertEquals(hash(bytes(source)), identity.path("sourceTargetMetadataSha256").textValue());
        assertEquals(hash(bytes(recipient)), identity.path("recipientTargetMetadataSha256").textValue());
        assertNotEquals(identity.path("sourceTargetMetadataSha256"), identity.path("recipientTargetMetadataSha256"));
        assertEquals(hash(addedDer), identity.path("generatedCertificateSha256").textValue());
        assertEquals(hash(restoredDer), identity.path("restoredCertificateSha256").textValue());
        assertTrue(identity.path("nativeConfigurationOnly").booleanValue());
        assertFalse(identity.path("metadataConsumptionClaimed").booleanValue());
    }

    @Test void certificateIdentityCannotBeReplacedByEqualSpkiOrSelfDeclaredNativeRows() throws Exception {
        byte[] alteredDer = restoredDer.clone(); alteredDer[alteredDer.length - 1] ^= 1;
        var certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(alteredDer));
        assertArrayEquals(CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(restoredDer)).getPublicKey().getEncoded(),
                certificate.getPublicKey().getEncoded(), "Same key, different certificate fixture");
        rejected("same SPKI different DER", source,
                recipient.replace(restoredCertificate, Base64.getEncoder().encodeToString(alteredDer)));
        rejected("generated certificate replaced", source.replace(addedCertificate, restoredCertificate), recipient);
        assertThrows(Exception.class, () -> NativeConfigurationSourceRunEvidence.targetIdentity(
                bytes(source), bytes(recipient), restoredDer, before, restored));
        var changedBefore = before.deepCopy();
        ((ObjectNode) changedBefore.path("baselineKeys").get(0)).put("spkiSha256", "0".repeat(64));
        assertThrows(Exception.class, () -> NativeConfigurationSourceRunEvidence.targetIdentity(
                bytes(source), bytes(recipient), addedDer, changedBefore, restored));
        var changedRestored = restored.deepCopy();
        ((ObjectNode) changedRestored.path("keys").get(0)).put("spkiSha256", "0".repeat(64));
        assertThrows(Exception.class, () -> NativeConfigurationSourceRunEvidence.targetIdentity(
                bytes(source), bytes(recipient), addedDer, before, changedRestored));
    }

    @Test void omittedDuplicatedOrExtendedKeyNodesCannotHideBehindTheAllowedRotation() {
        var variations = new LinkedHashMap<String, String>();
        variations.put("old key role", recipient.replace("use=\"encryption\"", "use=\"signing\""));
        variations.put("additional key", recipient.replace(service(REDIRECT), key("signing", restoredCertificate) + service(REDIRECT)));
        variations.put("omitted encryption key", recipient.replace(key("encryption", restoredCertificate), ""));
        variations.put("KeyDescriptor extra attribute", recipient.replace("use=\"signing\"", "use=\"signing\" ID=\"extra\""));
        variations.put("KeyInfo unknown child", recipient.replace("</ds:KeyInfo>", "<ds:KeyName>unbound</ds:KeyName></ds:KeyInfo>"));
        variations.put("X509Data extra attribute", recipient.replace("<ds:X509Data>", "<ds:X509Data ID=\"extra\">"));
        variations.put("certificate nested child", recipient.replace("</ds:X509Certificate>", "<ds:KeyName>unbound</ds:KeyName></ds:X509Certificate>"));
        variations.forEach((label, value) -> rejected(label, source, value));
        rejected("source rotation order", source.replace(key("signing", addedCertificate) + key("encryption", addedCertificate),
                key("encryption", addedCertificate) + key("signing", addedCertificate)), recipient);
    }

    @Test void logoutAllowanceDoesNotAdmitDifferentUrlBindingResponseLocationOrExtraService() {
        var variations = new LinkedHashMap<String, String>();
        variations.put("POST different URL", recipient.replace(service(POST), service(POST).replace(LOGOUT, LOGOUT + "/other")));
        variations.put("POST different binding", recipient.replace(service(POST), service("urn:oasis:names:tc:SAML:2.0:bindings:SOAP")));
        variations.put("extra ResponseLocation", recipient.replace(service(POST), service(POST).replace("/>", " ResponseLocation=\"" + LOGOUT + "\"/>")));
        variations.put("extra service", recipient.replace(service(POST), service(POST) + service(POST)));
        variations.put("omitted POST", recipient.replace(service(POST), ""));
        variations.put("service order", recipient.replace(service(REDIRECT) + service(POST), service(POST) + service(REDIRECT)));
        variations.forEach((label, value) -> rejected(label, source, value));
        rejected("coherently changed transport URL", source.replace(LOGOUT, LOGOUT + "/other"), recipient.replace(LOGOUT, LOGOUT + "/other"));
    }

    @Test void allRetainedXmlFactsAndMeaningfulTextOrderRemainExact() {
        var variations = new LinkedHashMap<String, String>();
        variations.put("target entity", recipient.replace("entityID=\"" + TARGET, "entityID=\"https://foreign.example/idp"));
        variations.put("protocol attribute", recipient.replace(P, P + ":other"));
        variations.put("descriptor attribute", recipient.replace("https://target.example/error", "https://foreign.example/error"));
        variations.put("SSO URL", recipient.replace("https://target.example/sso", "https://foreign.example/sso"));
        variations.put("NameID leading meaningful whitespace", recipient.replace("<md:NameIDFormat>", "<md:NameIDFormat> "));
        variations.put("additional extension", recipient.replace("<md:NameIDFormat>", "<md:Extensions/><md:NameIDFormat>"));
        String nameId = "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>";
        String sso = "<md:SingleSignOnService Binding=\"" + REDIRECT + "\" Location=\"https://target.example/sso\"/>";
        variations.put("retained child order", recipient.replace(nameId + sso, sso + nameId));
        variations.put("root meaningful text", recipient.replace("</md:EntityDescriptor>", "changed</md:EntityDescriptor>"));
        variations.put("descriptor meaningful text", recipient.replace("</md:IDPSSODescriptor>", "changed</md:IDPSSODescriptor>"));
        variations.put("processing instruction", recipient.replace("<md:NameIDFormat>", "<?unbound value?><md:NameIDFormat>"));
        variations.put("comment", recipient.replace("<md:NameIDFormat>", "<!-- unbound --><md:NameIDFormat>"));
        variations.forEach((label, value) -> rejected(label, source, value));
        rejected("coherent nonblank root text", source.replace("</md:EntityDescriptor>", "same</md:EntityDescriptor>"),
                recipient.replace("</md:EntityDescriptor>", "same</md:EntityDescriptor>"));
    }

    @Test void permittedCertificateEncodingWhitespaceStillChangesTheBoundRawMetadataDigest() throws Exception {
        String spaced = source.replace(addedCertificate, addedCertificate.substring(0, 80) + "\n" + addedCertificate.substring(80));
        var original = identity(source, recipient); var changed = identity(spaced, recipient);
        assertNotEquals(original.path("sourceTargetMetadataSha256"), changed.path("sourceTargetMetadataSha256"));
        assertEquals(original.path("generatedCertificateSha256"), changed.path("generatedCertificateSha256"));
        assertEquals(original.path("generatedSpkiSha256"), changed.path("generatedSpkiSha256"));
    }
}
