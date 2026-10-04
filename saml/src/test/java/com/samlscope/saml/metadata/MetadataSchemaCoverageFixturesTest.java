package com.samlscope.saml.metadata;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.List;
import javax.xml.XMLConstants;
import com.samlscope.saml.SamlTestFixtures;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.SamlSchemaValidation;
import com.samlscope.saml.normal.SecureXml;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;

class MetadataSchemaCoverageFixturesTest {
    @TempDir java.nio.file.Path directory;
    private static final String MD = MetadataService.MD;
    private static final List<MetadataService.Variant> VARIANTS = List.of(
            MetadataService.Variant.SCHEMA_GLOBAL_ELEMENT_FAMILIES,
            MetadataService.Variant.SCHEMA_AFFILIATION_ONLY,
            MetadataService.Variant.SCHEMA_ADDITIONAL_METADATA_LOCATION,
            MetadataService.Variant.SCHEMA_LOCALIZED_NAME_BOUNDARY,
            MetadataService.Variant.SCHEMA_ATTRIBUTE_CONSUMING_SERVICE,
            MetadataService.Variant.SCHEMA_SSO_ENDPOINT_SET,
            MetadataService.Variant.SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN);

    private FilePlanKeyStore keys() {
        return new FilePlanKeyStore(directory, Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"), ZoneOffset.UTC));
    }

    private MetadataService service() {
        return new MetadataService(URI.create("https://peer.example"), keys(), new XmlSigner(),
                Clock.fixed(Instant.parse("2026-10-01T00:00:00Z"), ZoneOffset.UTC));
    }

    private Element fixture(MetadataService.Variant variant) {
        return SecureXml.parse(service().generate(SamlTestFixtures.idpPlan(), variant, "run_schema")).getDocumentElement();
    }

    private Element first(Element parent, String name) {
        var found = parent.getElementsByTagNameNS(MD, name);
        assertTrue(found.getLength() > 0, name);
        return (Element) found.item(0);
    }

    private void valid(Element root) {
        assertEquals(java.util.Optional.empty(), SamlSchemaValidation.validationFailure(root,
                SamlSchemaValidation.SchemaKind.METADATA));
    }

    @Test void allCoverageInputsAreSchemaValidAndSignedInBothGenerationModes() {
        var plan = SamlTestFixtures.idpPlan();
        for (var variant : VARIANTS) {
            for (var polling : List.of(false, true)) {
                var raw = polling ? service().generatePolling(plan, variant, "run_schema")
                        : service().generate(plan, variant, "run_schema");
                var root = SecureXml.parse(raw).getDocumentElement();
                valid(root);
                assertEquals(1, root.getElementsByTagNameNS(MetadataService.DS, "Signature").getLength());
                var signer = polling ? service().credentialsForPollingVariant(plan, variant).certificate()
                        : keys().getOrCreate(plan.id()).certificate();
                assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, signer), variant.id());
            }
        }
    }

    @Test void roleFamiliesIncludeEveryAuthorityOptionalChildAndDerivedRole() {
        var root = fixture(MetadataService.Variant.SCHEMA_GLOBAL_ELEMENT_FAMILIES);
        for (var role : List.of("IDPSSODescriptor", "SPSSODescriptor", "AuthnAuthorityDescriptor",
                "PDPDescriptor", "AttributeAuthorityDescriptor", "RoleDescriptor")) assertNotNull(first(root, role));
        assertEquals("md:SPSSODescriptorType", first(root, "RoleDescriptor")
                .getAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "type"));
        for (var role : List.of("AuthnAuthorityDescriptor", "PDPDescriptor", "AttributeAuthorityDescriptor")) {
            var value = first(root, role);
            for (var optional : List.of("KeyDescriptor", "Organization", "ContactPerson",
                    "AssertionIDRequestService", "NameIDFormat")) assertNotNull(first(value, optional));
        }
        var authority = first(root, "AttributeAuthorityDescriptor");
        assertNotNull(first(authority, "AttributeProfile"));
        assertEquals(1, authority.getElementsByTagNameNS(MetadataService.SAML, "Attribute").getLength());
        valid(root);
    }

    @Test void globalKeysExtensionsAndMultilingualContactsExerciseTheirActualTypes() {
        var root = fixture(MetadataService.Variant.SCHEMA_GLOBAL_ELEMENT_FAMILIES);
        var sp = first(root, "SPSSODescriptor");
        var uses = new HashSet<String>();
        var descriptors = sp.getElementsByTagNameNS(MD, "KeyDescriptor");
        boolean multipleMethods = false;
        for (int index = 0; index < descriptors.getLength(); index++) {
            var key = (Element) descriptors.item(index);
            uses.add(key.getAttribute("use"));
            multipleMethods |= key.getElementsByTagNameNS(MD, "EncryptionMethod").getLength() == 2;
        }
        assertTrue(uses.containsAll(List.of("", "signing", "encryption")));
        assertTrue(multipleMethods);
        assertEquals("value", root.getAttributeNS("urn:samlscope:test:foreign", "attribute"));
        assertEquals(1, first(root, "Extensions").getElementsByTagNameNS("urn:samlscope:test:foreign", "element").getLength());
        var types = new HashSet<String>();
        var contacts = root.getElementsByTagNameNS(MD, "ContactPerson");
        for (int index = 0; index < contacts.getLength(); index++) {
            var contact = (Element) contacts.item(index);
            types.add(contact.getAttribute("contactType"));
            assertEquals(2, contact.getElementsByTagNameNS(MD, "EmailAddress").getLength());
            assertEquals(2, contact.getElementsByTagNameNS(MD, "TelephoneNumber").getLength());
        }
        assertEquals(new HashSet<>(List.of("technical", "support", "administrative", "billing", "other")), types);
        for (var name : List.of("OrganizationName", "OrganizationDisplayName", "OrganizationURL")) {
            var values = first(root, "Organization").getElementsByTagNameNS(MD, name);
            assertEquals(2, values.getLength());
            assertEquals("en", ((Element) values.item(0)).getAttributeNS(XMLConstants.XML_NS_URI, "lang"));
            assertEquals("ja", ((Element) values.item(1)).getAttributeNS(XMLConstants.XML_NS_URI, "lang"));
        }
    }

    @Test void ssoOptionalElementsAndEndpointExtensionsAreSchemaOrdered() {
        var root = fixture(MetadataService.Variant.SCHEMA_SSO_ENDPOINT_SET);
        for (var name : List.of("SPSSODescriptor", "IDPSSODescriptor")) {
            var role = first(root, name);
            for (var common : List.of("ArtifactResolutionService", "SingleLogoutService", "ManageNameIDService", "NameIDFormat"))
                assertNotNull(first(role, common));
            var endpoint = first(role, "ArtifactResolutionService");
            assertEquals("0", endpoint.getAttribute("index"));
            assertEquals("true", endpoint.getAttribute("isDefault"));
            assertFalse(endpoint.getAttribute("ResponseLocation").isEmpty());
            assertEquals(1, endpoint.getElementsByTagNameNS("urn:samlscope:test:foreign", "endpoint").getLength());
            assertEquals("value", endpoint.getAttributeNS("urn:samlscope:test:foreign", "attribute"));
        }
        var idp = first(root, "IDPSSODescriptor");
        for (var optional : List.of("NameIDMappingService", "AssertionIDRequestService", "AttributeProfile")) assertNotNull(first(idp, optional));
        assertEquals(1, idp.getElementsByTagNameNS(MetadataService.SAML, "Attribute").getLength());
        assertEquals("true", idp.getAttribute("WantAuthnRequestsSigned"));
        var sp = first(root, "SPSSODescriptor");
        assertEquals("true", sp.getAttribute("AuthnRequestsSigned"));
        assertEquals("true", sp.getAttribute("WantAssertionsSigned"));
        var indexes = new HashSet<String>();
        var endpoints = sp.getElementsByTagNameNS(MD, "AssertionConsumerService");
        assertEquals(7, endpoints.getLength());
        for (int i = 0; i < endpoints.getLength(); i++) assertTrue(indexes.add(((Element) endpoints.item(i)).getAttribute("index")));
        valid(root);
    }

    @Test void entityIdBoundaryAndRequiredLanguageCannotBeSubstitutedByUnrelatedStrings() {
        var root = fixture(MetadataService.Variant.SCHEMA_LOCALIZED_NAME_BOUNDARY);
        assertEquals(1024, root.getAttribute("entityID").length());
        valid(root);
        root.setAttribute("entityID", root.getAttribute("entityID") + "a");
        assertTrue(SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA).isPresent());
        root.setAttribute("entityID", root.getAttribute("entityID").substring(0, 1024));
        first(root, "OrganizationName").removeAttributeNS(XMLConstants.XML_NS_URI, "lang");
        assertTrue(SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA).isPresent());
    }

    @Test void affiliationIsExclusiveAndHasMultipleMembersAndKeys() {
        var root = fixture(MetadataService.Variant.SCHEMA_AFFILIATION_ONLY);
        assertEquals(0, root.getElementsByTagNameNS(MD, "SPSSODescriptor").getLength());
        var affiliation = first(root, "AffiliationDescriptor");
        assertEquals(2, affiliation.getElementsByTagNameNS(MD, "AffiliateMember").getLength());
        assertEquals(2, affiliation.getElementsByTagNameNS(MD, "KeyDescriptor").getLength());
        valid(root);
        var ordinary = fixture(MetadataService.Variant.SCHEMA_SSO_ENDPOINT_SET);
        root.appendChild(root.getOwnerDocument().importNode(first(ordinary, "SPSSODescriptor"), true));
        assertTrue(SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA).isPresent());
    }

    @Test void mixedRecursiveEntitiesAndAttributeServicesCoverRemainingConditions() {
        var recursive = fixture(MetadataService.Variant.SCHEMA_ADDITIONAL_METADATA_LOCATION);
        assertEquals("EntitiesDescriptor", recursive.getLocalName());
        assertEquals(2, recursive.getElementsByTagNameNS(MD, "EntityDescriptor").getLength());
        assertEquals(1, recursive.getElementsByTagNameNS(MD, "EntitiesDescriptor").getLength());
        assertEquals(4, recursive.getElementsByTagNameNS(MD, "AdditionalMetadataLocation").getLength());
        valid(recursive);
        var service = first(fixture(MetadataService.Variant.SCHEMA_ATTRIBUTE_CONSUMING_SERVICE), "AttributeConsumingService");
        assertEquals(2, service.getElementsByTagNameNS(MD, "ServiceName").getLength());
        assertEquals(2, service.getElementsByTagNameNS(MD, "ServiceDescription").getLength());
        var requested = service.getElementsByTagNameNS(MD, "RequestedAttribute");
        assertEquals(3, requested.getLength());
        for (int index = 0; index < requested.getLength(); index++) assertEquals("false", ((Element) requested.item(index)).getAttribute("isRequired"));
    }

    @Test void endpointContrastKeepsTheSamePollingKeysAndEveryOperativeEndpoint() {
        var plan = SamlTestFixtures.idpPlan();
        var service = service();
        var test = SecureXml.parse(service.generatePolling(plan, MetadataService.Variant.SCHEMA_SSO_ENDPOINT_SET, "run_schema")).getDocumentElement();
        var control = SecureXml.parse(service.generatePolling(plan, MetadataService.Variant.SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN, "run_schema")).getDocumentElement();
        assertEquals(test.getAttribute("entityID"), control.getAttribute("entityID"));
        var testKeys = test.getElementsByTagNameNS(MetadataService.DS, "X509Certificate");
        var controlKeys = control.getElementsByTagNameNS(MetadataService.DS, "X509Certificate");
        assertEquals(testKeys.getLength(), controlKeys.getLength());
        for (int index = 0; index < testKeys.getLength(); index++) assertEquals(testKeys.item(index).getTextContent(), controlKeys.item(index).getTextContent());
        assertTrue(test.getElementsByTagNameNS("urn:samlscope:test:foreign", "endpoint").getLength() > 0);
        assertEquals(0, control.getElementsByTagNameNS("urn:samlscope:test:foreign", "endpoint").getLength());
        for (var name : List.of("ArtifactResolutionService", "ManageNameIDService", "SingleLogoutService",
                "AssertionConsumerService", "SingleSignOnService", "NameIDMappingService", "AssertionIDRequestService")) {
            var a = test.getElementsByTagNameNS(MD, name); var b = control.getElementsByTagNameNS(MD, name);
            assertEquals(a.getLength(), b.getLength());
            for (int index = 0; index < a.getLength(); index++) {
                for (var attribute : List.of("Binding", "Location", "ResponseLocation", "index", "isDefault"))
                    assertEquals(((Element) a.item(index)).getAttribute(attribute), ((Element) b.item(index)).getAttribute(attribute));
            }
        }
        valid(test); valid(control);
    }

    @Test void schemaInvalidControlHasARealSignatureAndIsRejectedByTheProductionSchemaValidator() {
        var plan = SamlTestFixtures.idpPlan();
        var service = service();
        for (var polling : List.of(false, true)) {
            var variant = MetadataService.Variant.SCHEMA_INVALID_ENDPOINT_LOCATION;
            var raw = polling ? service.generatePolling(plan, variant, "run_schema") : service.generate(plan, variant, "run_schema");
            var root = SecureXml.parse(raw).getDocumentElement();
            var certificate = polling ? service.credentialsForPollingVariant(plan, variant).certificate() : keys().getOrCreate(plan.id()).certificate();
            assertTrue(new XmlSignatureVerifier().hasValidEnvelopedSignature(root, certificate));
            assertTrue(SamlSchemaValidation.validationFailure(root, SamlSchemaValidation.SchemaKind.METADATA).isPresent());
        }
    }
}
