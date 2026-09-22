package com.samlscope.saml.metadata;

import java.util.List;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * IIP-MD05.b schema-coverage inputs. Each fixture assembles a conforming document that exercises a
 * global element family or boundary from the SAML V2.0 Metadata schema; acceptance alone is the
 * observation, so nothing here asserts a verdict.
 */
final class MetadataSchemaCoverageFixtures {
    private static final String MD = MetadataService.MD;
    private static final String SAML = MetadataService.SAML;
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

    private MetadataSchemaCoverageFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        switch (variant) {
            case SCHEMA_GLOBAL_ELEMENT_FAMILIES -> globalElementFamilies(document, entity);
            case SCHEMA_ADDITIONAL_METADATA_LOCATION -> additionalMetadataLocation(document, entity);
            case SCHEMA_LOCALIZED_NAME_BOUNDARY -> localizedNameBoundary(document, entity);
            case SCHEMA_ATTRIBUTE_CONSUMING_SERVICE -> attributeConsumingService(document, entity);
            case SCHEMA_SSO_ENDPOINT_SET -> ssoEndpointSet(document, entity);
            default -> { }
        }
        return entity;
    }

    private static void globalElementFamilies(Document document, Element entity) {
        var sp = first(document, entity, "SPSSODescriptor");
        // KeyDescriptor with use omitted, signing and encryption, with several EncryptionMethod elements.
        keyDescriptor(document, sp, null);
        keyDescriptor(document, sp, "signing");
        var encryption = keyDescriptor(document, sp, "encryption");
        for (var algorithm : List.of(XENC11_SHA, XENC11_GCM)) {
            var method = node(document, "EncryptionMethod");
            method.setAttribute("Algorithm", algorithm);
            encryption.appendChild(method);
        }
        // AdditionalMetadataLocation, element and attribute extensions in non-SAML namespaces.
        var location = node(document, "AdditionalMetadataLocation");
        location.setAttribute("namespace", "urn:samlscope:test:additional");
        location.setTextContent("https://example.invalid/additional-metadata.xml");
        entity.appendChild(location);
        var foreign = node(document, "Extensions");
        foreign.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", "urn:samlscope:test:foreign");
        foreign.setAttributeNS("urn:samlscope:test:foreign", "foreign:attribute", "value");
        entity.insertBefore(foreign, entity.getFirstChild());
        // Organization with multilingual values, ContactPerson covering several contactTypes.
        var organization = node(document, "Organization");
        for (var name : List.of("OrganizationName", "OrganizationDisplayName", "OrganizationURL")) {
            for (var language : List.of("en", "ja")) {
                var value = node(document, name);
                value.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", language);
                value.setTextContent(name.equals("OrganizationURL")
                        ? "https://example.invalid/" : "SAMLscope " + name + " (" + language + ")");
                organization.appendChild(value);
            }
        }
        entity.appendChild(organization);
        for (var type : List.of("technical", "support", "administrative", "billing", "other")) {
            var contact = node(document, "ContactPerson");
            contact.setAttribute("contactType", type);
            entity.appendChild(contact);
        }
        // The six standard role descriptors plus a RoleDescriptor-derived type and an AffiliationDescriptor.
        for (var role : List.of("AuthnAuthorityDescriptor", "AttributeAuthorityDescriptor"
                , "PDPDescriptor")) {
            if (entity.getElementsByTagNameNS(MD, role).getLength() > 0) continue;
            var descriptor = node(document, role);
            descriptor.setAttribute("protocolSupportEnumeration", PROTOCOL);
            // Each authority descriptor requires at least one service of its declared type.
            var serviceName = switch (role) {
                case "AuthnAuthorityDescriptor" -> "AuthnQueryService";
                case "AttributeAuthorityDescriptor" -> "AttributeService";
                case "PDPDescriptor" -> "AuthzService";
                default -> "AuthnQueryService";
            };
            var service = node(document, serviceName);
            service.setAttribute("Binding", MetadataService.SOAP);
            service.setAttribute("Location", "https://example.invalid/" + serviceName);
            descriptor.appendChild(service);
            if ("AttributeAuthorityDescriptor".equals(role)) {
                var assertionIdRequest = node(document, "AssertionIDRequestService");
                assertionIdRequest.setAttribute("Binding", MetadataService.SOAP);
                assertionIdRequest.setAttribute("Location", "https://example.invalid/AssertionIDRequestService");
                descriptor.appendChild(assertionIdRequest);
            }
            entity.appendChild(descriptor);
        }
        var derived = (Element) sp.cloneNode(true);
        document.renameNode(derived, MD, "md:RoleDescriptor");
        derived.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
        derived.setAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi:type", "md:SPSSODescriptorType");
        entity.appendChild(derived);
        var affiliated = node(document, "AffiliationDescriptor");
        affiliated.setAttribute("affiliationOwnerID", entity.getAttribute("entityID") + "/owner");
        for (var member : List.of(entity.getAttribute("entityID"), entity.getAttribute("entityID") + "/member")) {
            var affiliateMember = node(document, "AffiliateMember");
            affiliateMember.setTextContent(member);
            affiliated.appendChild(affiliateMember);
        }
        keyDescriptor(document, affiliated, "signing");
        keyDescriptor(document, affiliated, "encryption");
        entity.appendChild(affiliated);
    }

    private static void additionalMetadataLocation(Document document, Element entity) {
        for (var value : List.of("urn:samlscope:test:additional-one", "urn:samlscope:test:additional-two")) {
            var location = node(document, "AdditionalMetadataLocation");
            location.setAttribute("namespace", value);
            location.setTextContent("https://example.invalid/additional-metadata.xml");
            entity.appendChild(location);
        }
    }

    private static void localizedNameBoundary(Document document, Element entity) {
        // entityIDType is an anyURI up to 1,024 characters. The Suite entityID is fixed by the
        // Run correlation, so exercise the boundary on a separate AdditionalMetadataLocation
        // namespace and on maximum-length localized strings, keeping the tested entity intact.
        var location = node(document, "AdditionalMetadataLocation");
        location.setAttribute("namespace", "urn:samlscope:test:" + "a".repeat(1024 - 21));
        location.setTextContent("https://example.invalid/additional-metadata.xml");
        entity.appendChild(location);
        var organization = node(document, "Organization");
        for (var name : List.of("OrganizationName", "OrganizationDisplayName", "OrganizationURL")) {
            var value = node(document, name);
            value.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
            value.setTextContent(name.equals("OrganizationURL")
                    ? "https://example.invalid/" : "SAMLscope boundary " + "b".repeat(1024 - 30));
            organization.appendChild(value);
        }
        entity.appendChild(organization);
    }

    private static void attributeConsumingService(Document document, Element entity) {
        var sp = first(document, entity, "SPSSODescriptor");
        var service = node(document, "AttributeConsumingService");
        service.setAttribute("index", "0");
        service.setAttribute("isDefault", "true");
        for (var name : List.of("ServiceName", "ServiceDescription")) {
            for (var language : List.of("en", "ja")) {
                var value = node(document, name);
                value.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", language);
                value.setTextContent("SAMLscope " + name + " (" + language + ")");
                service.appendChild(value);
            }
        }
        for (var attribute : List.of("urn:oid:1.3.6.1.4.1.5923.1.1.1.1", "urn:oid:2.5.4.3", "urn:oid:0.9.2342.19200300.100.1.1")) {
            var requested = node(document, "RequestedAttribute");
            requested.setAttribute("Name", attribute);
            requested.setAttribute("isRequired", "false");
            service.appendChild(requested);
        }
        sp.appendChild(service);
    }

    private static void ssoEndpointSet(Document document, Element entity) {
        var sp = first(document, entity, "SPSSODescriptor");
        for (var index = 0; index < 3; index++) {
            var acs = node(document, "AssertionConsumerService");
            acs.setAttribute("Binding", MetadataService.POST);
            acs.setAttribute("Location", "https://example.invalid/acs/" + index);
            acs.setAttribute("index", String.valueOf(index));
            if (index == 0) acs.setAttribute("isDefault", "true");
            sp.appendChild(acs);
        }
        var idp = entity.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (idp.getLength() > 0) {
            var role = (Element) idp.item(0);
            role.setAttribute("WantAuthnRequestsSigned", "true");
            for (var binding : List.of(MetadataService.REDIRECT, MetadataService.POST)) {
                var sso = node(document, "SingleSignOnService");
                sso.setAttribute("Binding", binding);
                sso.setAttribute("Location", "https://example.invalid/sso");
                role.insertBefore(sso, role.getFirstChild());
            }
            var artifact = node(document, "ArtifactResolutionService");
            artifact.setAttribute("Binding", MetadataService.SOAP);
            artifact.setAttribute("Location", "https://example.invalid/artifact");
            artifact.setAttribute("index", "0");
            role.insertBefore(artifact, role.getFirstChild());
        }
        for (var format : List.of("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")) {
            var nameIdFormat = node(document, "NameIDFormat");
            nameIdFormat.setTextContent(format);
            sp.insertBefore(nameIdFormat, sp.getFirstChild());
        }
    }

    private static Element keyDescriptor(Document document, Element parent, String use) {
        var descriptor = node(document, "KeyDescriptor");
        if (use != null) descriptor.setAttribute("use", use);
        var keyInfo = document.createElementNS(MetadataService.DS, "ds:KeyInfo");
        keyInfo.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", MetadataService.DS);
        descriptor.appendChild(keyInfo);
        parent.appendChild(descriptor);
        return descriptor;
    }

    private static Element first(Document document, Element entity, String name) {
        var nodes = entity.getElementsByTagNameNS(MD, name);
        if (nodes.getLength() == 0) throw new IllegalStateException("Missing fixture parent: " + name);
        return (Element) nodes.item(0);
    }

    private static Element node(Document document, String name) {
        return document.createElementNS(MD, "md:" + name);
    }

    private static final String XENC11_SHA = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
    private static final String XENC11_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm";
}
