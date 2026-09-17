package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.saml.crypto.FilePlanKeyStore;

class TargetMetadataObservationTest {
    private static final Instant NOW = Instant.parse("2026-08-30T00:00:00Z");
    private static final String SAML2 = "urn:oasis:names:tc:SAML:2.0:protocol";
    @TempDir java.nio.file.Path directory;

    @Test
    void aSingleSigningKeyMakesIdentificationUnambiguousButUnknownCandidatesDoNot() throws Exception {
        var cert = certificate();
        var key = "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + cert + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        var id = "IIP-MD05-ae-idp-01";
        assertOutcome(id, Outcome.SATISFIED_WITH_NOTE, metadata(role("IDPSSODescriptor", SAML2, key)));
        assertOutcome(id, Outcome.SATISFIED_WITH_NOTE, metadata(role("IDPSSODescriptor", SAML2, key + key)));
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("IDPSSODescriptor", SAML2, "")), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("SPSSODescriptor", SAML2, key)), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("IDPSSODescriptor", SAML2, key.replace("use='signing'", "use='encryption'"))), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("IDPSSODescriptor", SAML2, key.replace(cert, "invalid"))), NOW).isEmpty());
        var other = Base64.getEncoder().encodeToString(new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS", "different").certificate().getEncoded());
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("IDPSSODescriptor", SAML2, key + key.replace(cert, other))), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(id, metadata(role("IDPSSODescriptor", SAML2,
                key.replace("</ds:KeyInfo>", "<ds:KeyValue/></ds:KeyInfo>"))), NOW).isEmpty());
    }

    @Test
    void unpublishedUiGuidanceUsesOnlyTheExplicitApprovedNoteBranches() {
        for (var suffix : List.of("f7", "f8", "fa")) {
            var id = "IIP-MD05-" + suffix + "-idp-01";
            assertOutcome(id, Outcome.SATISFIED_WITH_NOTE, metadata(role("IDPSSODescriptor", SAML2, "")));
            assertTrue(TargetMetadataObservation.evaluate(id,
                    metadata(role("SPSSODescriptor", SAML2, "")), NOW).isEmpty());
            assertTrue(TargetMetadataObservation.evaluate(id, "<unrelated/>".getBytes(StandardCharsets.UTF_8), NOW).isEmpty());
        }
        for (var suffix : List.of("f9", "fb", "fh", "fj")) {
            assertFalse(TargetMetadataObservation.supports("IIP-MD05-" + suffix + "-idp-01"),
                    "a publisher document cannot prove absence of a consumer UI");
        }
    }

    @Test
    void presentUiContentNeedsActualSemanticOrAssetEvidence() {
        for (var pair : List.of(new String[]{"f7", "Description"}, new String[]{"f8", "Logo"}, new String[]{"fa", "InformationURL"})) {
            for (var text : List.of("", "https://example.test/image.png")) {
                if (pair[0].equals("f8") && text.isEmpty()) continue;
                var xml = metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><mdui:UIInfo xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\"><mdui:"
                                + pair[1] + ">" + text + "</mdui:" + pair[1] + "></mdui:UIInfo></md:Extensions>"));
                assertTrue(TargetMetadataObservation.evaluate("IIP-MD05-" + pair[0] + "-idp-01",
                        xml, NOW).isEmpty());
            }
        }
        assertOutcome("IIP-MD05-f8-idp-01", Outcome.VIOLATED, metadata(role("IDPSSODescriptor", SAML2,
                "<md:Extensions><u:UIInfo xmlns:u=\"urn:oasis:names:tc:SAML:metadata:ui\">"
                        + "<u:Logo>http://example.test/logo.png</u:Logo></u:UIInfo></md:Extensions>")));
    }

    @Test
    void detectsOverlappingSameTypeRolesWithoutTreatingOneRoleAsAnOverlap() {
        assertOutcome("IIP-MD05-a7-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata(role("IDPSSODescriptor", SAML2, "")));
        assertOutcome("IIP-MD05-a7-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, "")
                        + role("IDPSSODescriptor", SAML2, "")));
        assertOutcome("IIP-MD05-a7-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, "")
                        + role("IDPSSODescriptor", "urn:other:protocol", "")));
        assertOutcome("IIP-MD05-a7-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata(genericRole("ext:One", SAML2) + genericRole("ext:Two", SAML2)));
        assertOutcome("IIP-MD05-a7-idp-01", Outcome.VIOLATED,
                metadata(genericRole("ext:One", SAML2) + genericRole("alt:One", SAML2)));
    }

    @Test
    void everySamlRoleMustAdvertiseTheSamlTwoProtocol() {
        assertOutcome("IIP-MD05-a9-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, "")));
        assertOutcome("IIP-MD05-a9-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", "urn:other:protocol", "")));
        assertOutcome("IIP-MD05-a9-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata(role("RoleDescriptor", "urn:non-saml:protocol", "")));
    }

    @Test
    void oneDirectionEndpointsMustNotCarryResponseLocation() {
        assertOutcome("IIP-MD05-ab-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:SingleSignOnService Binding=\"urn:test\" Location=\"https://idp.example/sso\"/>")));
        assertOutcome("IIP-MD05-ab-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:SingleSignOnService Binding=\"urn:test\" Location=\"https://idp.example/sso\" ResponseLocation=\"https://idp.example/response\"/>")));
    }

    @Test
    void keyInfoRequiresAKeyValueOrExactlyOneCertificateRepresentation() throws Exception {
        var certificate = certificate();
        assertOutcome("IIP-MD05-c9-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor(
                        "<ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data>"))));
        assertOutcome("IIP-MD05-c9-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor("<ds:KeyName>only-a-hint</ds:KeyName>"))));
        assertOutcome("IIP-MD05-ca-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor(
                        "<ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate>"
                                + "<ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data>"))));
        assertOutcome("IIP-MD05-ca-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata("<ds:Signature><ds:KeyInfo><ds:X509Data>"
                        + "<ds:X509Certificate>" + certificate + "</ds:X509Certificate>"
                        + "<ds:X509Certificate>" + certificate + "</ds:X509Certificate>"
                        + "</ds:X509Data></ds:KeyInfo></ds:Signature>"
                        + role("IDPSSODescriptor", SAML2, "")));
    }

    @Test
    void publisherStructureRemovesEightQuestionnaireItems() throws Exception {
        var certificate = certificate();
        assertOutcome("IIP-MD05-a6-idp-01", Outcome.SATISFIED, metadata(""));
        assertOutcome("IIP-MD05-a6-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, "").replace(
                        "protocolSupportEnumeration", "validUntil=\"2026-09-01T00:00:00Z\" protocolSupportEnumeration")));

        assertOutcome("IIP-MD05-c8-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor(
                        "<ds:X509Data><ds:X509Certificate>" + certificate
                                + "</ds:X509Certificate></ds:X509Data>"))));
        assertOutcome("IIP-MD05-c8-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor("<ds:KeyName>hint</ds:KeyName>"))));

        assertOutcome("IIP-MD05-cb-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-cc-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor("<ds:KeyName>hint</ds:KeyName>"))));
        assertOutcome("IIP-MD05-d9-idp-01", Outcome.SATISFIED_WITH_NOTE,
                metadata(entityAttributesAssertion("https://idp.example/entity",
                        "<saml:Conditions/><saml:Advice/><saml:AttributeStatement/>")));

        var rsaDescriptor = "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo><ds:X509Data>"
                + "<ds:X509Certificate>" + certificate + "</ds:X509Certificate>"
                + "</ds:X509Data></ds:KeyInfo>"
                + encryptionMethod("http://www.w3.org/2009/xmlenc11#rsa-oaep")
                + "</md:KeyDescriptor>";
        assertOutcome("IIP-MD05-e2-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, rsaDescriptor)));
        assertOutcome("IIP-MD05-e3-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:KeyDescriptor use=\"encryption\"><ds:KeyInfo><ds:KeyName>shared"
                                + "</ds:KeyName></ds:KeyInfo>"
                                + encryptionMethod("http://www.w3.org/2009/xmlenc11#aes128-gcm")
                                + "</md:KeyDescriptor>")));
        assertOutcome("IIP-MD05-ed-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
    }

    @Test
    void publisherCertificateValidityIsObservedWithoutChangingConsumerAcceptance() throws Exception {
        var certificate = certificate();
        assertOutcome("IIP-MD05-ce-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor(
                        "<ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data>"))));
        var outcome = TargetMetadataObservation.evaluate(
                "IIP-MD05-ce-idp-01",
                metadata(role("IDPSSODescriptor", SAML2, keyDescriptor(
                        "<ds:X509Data><ds:X509Certificate>" + certificate + "</ds:X509Certificate></ds:X509Data>"))),
                Instant.parse("2126-08-30T00:00:00Z")).orElseThrow();
        assertEquals(Outcome.VIOLATED, outcome.outcome());
    }

    @Test
    void encryptionDescriptorListsDataAndKeyAlgorithms() {
        var both = encryptionMethod("http://www.w3.org/2009/xmlenc11#aes128-gcm")
                + encryptionMethod("http://www.w3.org/2009/xmlenc11#rsa-oaep");
        assertOutcome("IIP-MD05-e1-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, encryptionKeyDescriptor("encryption", both))));
        assertOutcome("IIP-MD05-e1-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        encryptionKeyDescriptor("encryption", encryptionMethod(
                                "http://www.w3.org/2009/xmlenc11#aes128-gcm")))));
        assertOutcome("IIP-MD05-e1-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2, encryptionKeyDescriptor("", both))));
        assertOutcome("IIP-MD05-e1-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, encryptionKeyDescriptor("", ""))));
    }

    @Test
    void algorithmUrisAreCheckedWithoutDelegatingToSchemaValidation() {
        assertOutcome("IIP-MD05-e4-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2, encryptionKeyDescriptor("encryption",
                        "<md:EncryptionMethod/>"))));
        assertOutcome("IIP-MD05-ec-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><alg:DigestMethod Algorithm=\"urn:digest\"/><alg:SigningMethod/></md:Extensions>")));
    }

    @Test
    void everyEntityPublishesBothSignatureCapabilityKinds() {
        var capabilities = "<md:Extensions><alg:DigestMethod Algorithm=\"urn:digest\"/>"
                + "<alg:SigningMethod Algorithm=\"urn:signature\"/></md:Extensions>";
        assertOutcome("IIP-MD05-e6-idp-01", Outcome.SATISFIED,
                metadata(capabilities + role("IDPSSODescriptor", SAML2, "")));
        assertOutcome("IIP-MD05-e6-idp-01", Outcome.VIOLATED,
                metadata("<md:Extensions><alg:DigestMethod Algorithm=\"urn:digest\"/></md:Extensions>"
                        + role("IDPSSODescriptor", SAML2, "")));
        var twoEntities = ("""
                <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport">
                  %s
                  %s
                </md:EntitiesDescriptor>
                """).formatted(
                entity("https://one.example", capabilities + role("IDPSSODescriptor", SAML2, "")),
                entity("https://two.example", role("IDPSSODescriptor", SAML2, "")));
        assertOutcome("IIP-MD05-e6-idp-01", Outcome.VIOLATED,
                twoEntities.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void uiInfoPlacementContentCardinalityAndLanguagesAreObserved() {
        assertOutcome("IIP-MD05-f1-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-f1-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo><ui:DisplayName xml:lang=\"en\">Example</ui:DisplayName></ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-f1-idp-01", Outcome.VIOLATED,
                metadata("<md:Extensions><ui:UIInfo><ui:DisplayName xml:lang=\"en\">Example</ui:DisplayName></ui:UIInfo></md:Extensions>"));

        assertOutcome("IIP-MD05-f2-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo/></md:Extensions>")));
        assertOutcome("IIP-MD05-f2-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo><ext:Custom/></ui:UIInfo></md:Extensions>")));

        assertOutcome("IIP-MD05-f3-sp-01", Outcome.VIOLATED,
                metadata(role("SPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo/><ui:UIInfo/></md:Extensions>")));
        assertOutcome("IIP-MD05-f3-sp-01", Outcome.SATISFIED,
                metadata(role("SPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo/></md:Extensions>")));

        assertOutcome("IIP-MD05-f4-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo>"
                                + "<ui:DisplayName xml:lang=\"en\">One</ui:DisplayName>"
                                + "<ui:DisplayName xml:lang=\"en\">Two</ui:DisplayName>"
                                + "</ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-f4-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo>"
                                + "<ui:DisplayName xml:lang=\"en\">Name</ui:DisplayName>"
                                + "<ui:Description xml:lang=\"en\">Description</ui:Description>"
                                + "</ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-f4-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo><ui:DisplayName xml:lang=\"en\">One</ui:DisplayName>"
                                + "</ui:UIInfo><ui:UIInfo><ui:DisplayName xml:lang=\"en\">Two</ui:DisplayName>"
                                + "</ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-f4-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo>"
                                + "<ui:DisplayName xml:lang=\"en\">One</ui:DisplayName>"
                                + "<ui:DisplayName xml:lang=\"EN\">Two</ui:DisplayName>"
                                + "</ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-f4-idp-01", Outcome.SATISFIED,
                metadata(
                        role("IDPSSODescriptor", SAML2,
                                "<md:Extensions><ui:UIInfo><ui:DisplayName xml:lang=\"en\">One</ui:DisplayName>"
                                        + "</ui:UIInfo></md:Extensions>")
                                + role("IDPSSODescriptor", SAML2,
                                "<md:Extensions><ui:UIInfo><ui:DisplayName xml:lang=\"en\">Two</ui:DisplayName>"
                                        + "</ui:UIInfo></md:Extensions>")));
    }

    @Test
    void discoHintsPlacementContentAndCardinalityAreObservedForIdpPublishers() {
        assertOutcome("IIP-MD05-fc-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-fc-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints><ui:DomainHint>example.test</ui:DomainHint></ui:DiscoHints></md:Extensions>")));
        assertOutcome("IIP-MD05-fc-idp-01", Outcome.VIOLATED,
                metadata(role("SPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints><ui:DomainHint>example.test</ui:DomainHint></ui:DiscoHints></md:Extensions>")));

        assertOutcome("IIP-MD05-fd-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints/></md:Extensions>")));
        assertOutcome("IIP-MD05-fd-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints><ext:Custom/></ui:DiscoHints></md:Extensions>")));

        assertOutcome("IIP-MD05-fe-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints/><ui:DiscoHints/></md:Extensions>")));
        assertOutcome("IIP-MD05-fe-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:DiscoHints/></md:Extensions>")));
    }

    @Test
    void everyPublishedLogoCarriesBothDimensions() {
        assertOutcome("IIP-MD05-fk-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-fk-idp-01", Outcome.SATISFIED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo><ui:Logo height=\"32\" width=\"64\">https://example.test/logo.svg</ui:Logo></ui:UIInfo></md:Extensions>")));
        assertOutcome("IIP-MD05-fk-idp-01", Outcome.VIOLATED,
                metadata(role("IDPSSODescriptor", SAML2,
                        "<md:Extensions><ui:UIInfo><ui:Logo height=\"32\">https://example.test/logo.svg</ui:Logo></ui:UIInfo></md:Extensions>")));
    }

    @Test
    void metadataExtensionContentMustUseAnExtensionNamespace() {
        assertOutcome("IIP-MD05-a3-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-a3-idp-01", Outcome.SATISFIED,
                metadata("<md:Extensions><ext:Custom/></md:Extensions>"));
        assertOutcome("IIP-MD05-a3-idp-01", Outcome.VIOLATED,
                metadata("<md:Extensions><md:Organization/></md:Extensions>"));
        assertOutcome("IIP-MD05-a3-idp-01", Outcome.VIOLATED,
                metadata("<md:Extensions><saml:Attribute Name=\"wrong-extension-point\"/></md:Extensions>"));
    }

    @Test
    void entityAttributesContainersAndAssertionsAreCheckedStructurally() {
        var validAssertion = entityAttributesAssertion(
                "https://idp.example/entity", "<saml:AttributeStatement/>");
        assertOutcome("IIP-MD05-d2-idp-01", Outcome.SATISFIED, metadata(validAssertion));
        assertOutcome("IIP-MD05-d3-idp-01", Outcome.SATISFIED, metadata(validAssertion));
        assertOutcome("IIP-MD05-d4-idp-01", Outcome.SATISFIED, metadata(validAssertion));
        assertOutcome("IIP-MD05-d5-idp-01", Outcome.SATISFIED, metadata(validAssertion));
        assertOutcome("IIP-MD05-d6-idp-01", Outcome.SATISFIED, metadata(validAssertion));
        assertOutcome("IIP-MD05-d7-idp-01", Outcome.SATISFIED, metadata(validAssertion));

        var underEntities = ("""
                <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <md:Extensions><mdattr:EntityAttributes>
                    <saml:Assertion><saml:AttributeStatement/></saml:Assertion>
                  </mdattr:EntityAttributes></md:Extensions>
                </md:EntitiesDescriptor>
                """).getBytes(StandardCharsets.UTF_8);
        assertOutcome("IIP-MD05-d2-idp-01", Outcome.VIOLATED, underEntities);

        assertOutcome("IIP-MD05-d3-idp-01", Outcome.VIOLATED,
                metadata("<md:Extensions><mdattr:EntityAttributes/><mdattr:EntityAttributes/></md:Extensions>"));
        assertOutcome("IIP-MD05-d4-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://other.example/entity", "<saml:AttributeStatement/>")));
        assertOutcome("IIP-MD05-d5-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://idp.example/entity",
                        "<saml:SubjectConfirmation Method=\"urn:test\"/><saml:AttributeStatement/>")));
        assertOutcome("IIP-MD05-d6-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://idp.example/entity", "")));
        assertOutcome("IIP-MD05-d6-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://idp.example/entity",
                        "<saml:AttributeStatement/><saml:AttributeStatement/>")));
        assertOutcome("IIP-MD05-d7-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://idp.example/entity",
                        "<saml:AttributeStatement/><saml:AuthnStatement/>")));
    }

    @Test
    void entityAttributeAssertionSignatureNeverTreatsPresenceAsCryptographicProof() {
        assertOutcome("IIP-MD05-d8-idp-01", Outcome.SATISFIED_WITH_NOTE, metadata(""));
        assertOutcome("IIP-MD05-d8-idp-01", Outcome.VIOLATED,
                metadata(entityAttributesAssertion("https://idp.example/entity", "<saml:AttributeStatement/>")));
        assertTrue(TargetMetadataObservation.evaluate(
                "IIP-MD05-d8-idp-01",
                metadata(entityAttributesAssertion(
                        "https://idp.example/entity", "<ds:Signature/><saml:AttributeStatement/>")),
                NOW).isEmpty());
    }

    @Test
    void malformedMetadataAndUnsupportedCasesRemainManual() {
        assertTrue(TargetMetadataObservation.evaluate(
                "IIP-MD05-e6-idp-01", "<broken".getBytes(StandardCharsets.UTF_8), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(
                "IIP-MD05-a2-idp-01", metadata(""), NOW).isEmpty());
        assertTrue(TargetMetadataObservation.supports("IIP-MD05-f1-sp-01"));
        assertFalse(TargetMetadataObservation.supports("IIP-MD05-fc-sp-01"));
    }

    @Test
    void evidenceIsBoundToTheExactMetadataBytes() {
        var first = TargetMetadataObservation.evaluate(
                "IIP-MD05-a9-idp-01", metadata(role("IDPSSODescriptor", SAML2, "")), NOW)
                .orElseThrow().evidence().getFirst().reference();
        var second = TargetMetadataObservation.evaluate(
                "IIP-MD05-a9-idp-01",
                metadata(role("IDPSSODescriptor", SAML2, "<!--different bytes-->")), NOW)
                .orElseThrow().evidence().getFirst().reference();

        assertTrue(first.matches("sha256:[0-9a-f]{64}"));
        assertNotEquals(first, second);
    }

    @Test
    void algorithmPublicationCapabilityRequiresPositiveSignatureAndEncryptionDeclarations() {
        var complete = metadata("""
                <md:Extensions>
                  <alg:SigningMethod Algorithm="urn:example:signature" MinKeySize="2048"/>
                  <alg:EncryptionMethod Algorithm="urn:example:encryption"/>
                </md:Extensions>
                """);
        var partial = metadata("""
                <md:Extensions>
                  <alg:SigningMethod Algorithm="urn:example:signature"/>
                </md:Extensions>
                """);

        var outcome = TargetMetadataObservation.evaluate("IIP-MD09-a-idp-01", complete, NOW)
                .orElseThrow();
        assertEquals(Outcome.SATISFIED, outcome.outcome());
        assertEquals(1L, outcome.details().get("signing_methods"));
        assertEquals(1L, outcome.details().get("encryption_methods"));
        assertTrue(TargetMetadataObservation.evaluate("IIP-MD09-a-idp-01", partial, NOW).isEmpty());
        assertTrue(TargetMetadataObservation.evaluate(
                "IIP-MD09-a-idp-01", metadata(""), NOW).isEmpty());
    }

    @Test
    void automaticWrapperPreservesBothApprovedManualPrompts() {
        var evidence = new AttestedOutcomeTestCase(
                "IIP-MD05-a7-idp-01", com.samlscope.core.plan.TargetRole.IDP,
                "evidence-key", "Review evidence", Duration.ofHours(1),
                List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "satisfied")));
        var fallback = new ConfigurationGateTestCase(
                evidence, "config-key", "Prepare configuration", Duration.ofHours(1),
                com.samlscope.core.caseexec.ConfigurationFailureSemantics.TEST_PRECONDITION);
        var wrapper = new AutoConfigurationEvidenceTestCase(fallback, ignored -> null);

        assertEquals("Prepare configuration", wrapper.instructionEn());
        assertEquals("Review evidence", wrapper.promptEn());
        assertEquals(List.of("satisfied"), wrapper.options().stream().map(AttestationOption::value).toList());
    }

    private void assertOutcome(String caseId, Outcome expected, byte[] metadata) {
        assertEquals(expected, TargetMetadataObservation.evaluate(caseId, metadata, NOW).orElseThrow().outcome());
    }

    private byte[] metadata(String contents) {
        return entity("https://idp.example/entity", contents).getBytes(StandardCharsets.UTF_8);
    }

    private String entity(String entityId, String contents) {
        return """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                  xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
                  xmlns:ui="urn:oasis:names:tc:SAML:metadata:ui"
                  xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                  xmlns:ext="urn:example:role" xmlns:alt="urn:example:role"
                  entityID="%s">%s</md:EntityDescriptor>
                """.formatted(entityId, contents);
    }

    private String entityAttributesAssertion(String subjectEntityId, String assertionContents) {
        return "<md:Extensions><mdattr:EntityAttributes><saml:Assertion>"
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">"
                + subjectEntityId + "</saml:NameID></saml:Subject>"
                + assertionContents
                + "</saml:Assertion></mdattr:EntityAttributes></md:Extensions>";
    }

    private String role(String localName, String protocols, String children) {
        return "<md:" + localName + " protocolSupportEnumeration=\"" + protocols + "\">"
                + children + "</md:" + localName + ">";
    }

    private String genericRole(String type, String protocols) {
        return "<md:RoleDescriptor xsi:type=\"" + type
                + "\" protocolSupportEnumeration=\"" + protocols + "\"/>";
    }

    private String keyDescriptor(String keyInfo) {
        return "<md:KeyDescriptor use=\"signing\"><ds:KeyInfo>" + keyInfo + "</ds:KeyInfo></md:KeyDescriptor>";
    }

    private String encryptionKeyDescriptor(String use, String methods) {
        var attribute = use.isBlank() ? "" : " use=\"" + use + "\"";
        return "<md:KeyDescriptor" + attribute + "><ds:KeyInfo><ds:KeyValue/></ds:KeyInfo>"
                + methods + "</md:KeyDescriptor>";
    }

    private String encryptionMethod(String algorithm) {
        return "<md:EncryptionMethod Algorithm=\"" + algorithm + "\"/>";
    }

    private String certificate() throws Exception {
        var certificate = new FilePlanKeyStore(directory, Clock.fixed(NOW, ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS").certificate();
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }
}
