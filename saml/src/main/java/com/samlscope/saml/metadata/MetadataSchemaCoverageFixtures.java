package com.samlscope.saml.metadata;

import java.util.List;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * IIP-MD05.b schema-coverage inputs. Roles and AffiliationDescriptor are exclusive alternatives
 * in EntityDescriptorType, so they are generated as separate documents.
 */
final class MetadataSchemaCoverageFixtures {
    private static final String MD = MetadataService.MD;
    private static final String SAML = MetadataService.SAML;
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

    private MetadataSchemaCoverageFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        if (variant.id().startsWith("schema-")) {
            // Namespace bindings must exist before the enveloped signature is computed;
            // serializer-added bindings would otherwise change the signed canonical bytes.
            entity.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", "urn:samlscope:test:foreign");
            entity.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", SAML);
        }
        switch (variant) {
            case SCHEMA_GLOBAL_ELEMENT_FAMILIES -> globalElementFamilies(document, entity);
            case SCHEMA_AFFILIATION_ONLY -> affiliationOnly(document, entity);
            case SCHEMA_ADDITIONAL_METADATA_LOCATION -> {
                additionalMetadataLocation(document, entity);
                return recursiveEntities(document, entity);
            }
            case SCHEMA_LOCALIZED_NAME_BOUNDARY -> localizedNameBoundary(document, entity);
            case SCHEMA_ATTRIBUTE_CONSUMING_SERVICE -> attributeConsumingService(document, entity);
            case SCHEMA_SSO_ENDPOINT_SET -> ssoEndpointSet(document, entity);
            case SCHEMA_SSO_ENDPOINT_WITHOUT_FOREIGN -> {
                ssoEndpointSet(document, entity);
                removeEndpointExtensions(entity);
            }
            case SCHEMA_INVALID_ENDPOINT_LOCATION -> {
                ssoEndpointSet(document, entity);
                removeEndpointExtensions(entity);
                // Preserve the ordinary default ACS so preparation does not fail before the
                // consumer sees the invalid member; this control targets schema validation only.
                var endpoints = first(document, entity, "SPSSODescriptor").getElementsByTagNameNS(MD, "AssertionConsumerService");
                ((Element) endpoints.item(endpoints.getLength() - 1)).removeAttribute("Location");
            }
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
        var foreign = node(document, "Extensions");
        entity.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", "urn:samlscope:test:foreign");
        var foreignElement = document.createElementNS("urn:samlscope:test:foreign", "foreign:element");
        foreign.appendChild(foreignElement);
        entity.setAttributeNS("urn:samlscope:test:foreign", "foreign:attribute", "value");
        entity.insertBefore(foreign, entity.getFirstChild());
        // The six standard role descriptors plus a RoleDescriptor-derived type.
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
            var roleKey = node(document, "KeyDescriptor");
            roleKey.setAttribute("use", "signing");
            roleKey.appendChild(sp.getElementsByTagNameNS(MetadataService.DS, "KeyInfo").item(0).cloneNode(true));
            descriptor.appendChild(roleKey);
            descriptor.appendChild(organization(document));
            descriptor.appendChild(contact(document, "technical"));
            descriptor.appendChild(endpoint(document, serviceName, MetadataService.SOAP));
            descriptor.appendChild(endpoint(document, "AssertionIDRequestService", MetadataService.SOAP));
            text(document, descriptor, "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
            if ("AttributeAuthorityDescriptor".equals(role)) {
                text(document, descriptor, "AttributeProfile", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic");
                attribute(document, descriptor);
            }
            entity.appendChild(descriptor);
        }
        var derived = (Element) sp.cloneNode(true);
        document.renameNode(derived, MD, "md:RoleDescriptor");
        derived.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
        derived.setAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi:type", "md:SPSSODescriptorType");
        entity.appendChild(derived);
        // Organization, contacts and additional locations follow all role descriptors in the XSD.
        entity.appendChild(organization(document));
        for (var type : List.of("technical", "support", "administrative", "billing", "other")) {
            entity.appendChild(contact(document, type));
        }
        entity.appendChild(location);
    }

    private static Element organization(Document document) {
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
        return organization;
    }

    private static Element contact(Document document, String type) {
        var contact = node(document, "ContactPerson");
        contact.setAttribute("contactType", type);
        text(document, contact, "Company", "SAMLscope");
        text(document, contact, "GivenName", "Reference");
        text(document, contact, "SurName", "Contact");
        for (var value : List.of("mailto:one@example.invalid", "mailto:two@example.invalid"))
            text(document, contact, "EmailAddress", value);
        for (var value : List.of("+1-555-0100", "+1-555-0101"))
            text(document, contact, "TelephoneNumber", value);
        return contact;
    }

    private static void additionalMetadataLocation(Document document, Element entity) {
        for (var value : List.of("urn:samlscope:test:additional-one", "urn:samlscope:test:additional-two")) {
            var location = node(document, "AdditionalMetadataLocation");
            location.setAttribute("namespace", value);
            location.setTextContent("https://example.invalid/additional-metadata.xml");
            entity.appendChild(location);
        }
    }

    private static void affiliationOnly(Document document, Element entity) {
        var sp = first(document, entity, "SPSSODescriptor");
        var keyInfo = sp.getElementsByTagNameNS(MetadataService.DS, "KeyInfo").item(0);
        if (keyInfo == null) throw new IllegalStateException("Missing affiliation key material");
        while (entity.hasChildNodes()) entity.removeChild(entity.getFirstChild());
        var affiliation = node(document, "AffiliationDescriptor");
        affiliation.setAttribute("affiliationOwnerID", entity.getAttribute("entityID"));
        for (var member : List.of(entity.getAttribute("entityID") + "/member-one",
                entity.getAttribute("entityID") + "/member-two")) {
            var element = node(document, "AffiliateMember");
            element.setTextContent(member);
            affiliation.appendChild(element);
        }
        for (var use : List.of("signing", "encryption")) {
            var descriptor = node(document, "KeyDescriptor");
            descriptor.setAttribute("use", use);
            descriptor.appendChild(keyInfo.cloneNode(true));
            affiliation.appendChild(descriptor);
        }
        entity.appendChild(affiliation);
    }

    private static void localizedNameBoundary(Document document, Element entity) {
        // This is an admission fixture: the bound is exercised on entityIDType itself, not on
        // an unrelated URI or localized string. Consumers must bind to this actual entityID.
        var prefix = "urn:samlscope:schema-boundary:";
        entity.setAttribute("entityID", prefix + "a".repeat(1024 - prefix.length()));
        var location = node(document, "AdditionalMetadataLocation");
        location.setAttribute("namespace", "urn:samlscope:test:additional");
        location.setTextContent("https://example.invalid/additional-metadata.xml");
        entity.appendChild(organization(document));
        entity.appendChild(location);
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
        sp.setAttribute("AuthnRequestsSigned", "true");
        sp.setAttribute("WantAssertionsSigned", "true");
        commonSso(document, sp);
        for (var index = 4; index < 7; index++) {
            var acs = endpoint(document, "AssertionConsumerService", MetadataService.POST);
            acs.setAttribute("Location", "https://example.invalid/acs/" + index);
            acs.setAttribute("index", String.valueOf(index));
            acs.setAttribute("isDefault", "false");
            sp.appendChild(acs);
        }
        var idp = entity.getElementsByTagNameNS(MD, "IDPSSODescriptor");
        if (idp.getLength() > 0) {
            var role = (Element) idp.item(0);
            role.setAttribute("WantAuthnRequestsSigned", "true");
            commonSso(document, role);
            role.appendChild(endpoint(document, "NameIDMappingService", MetadataService.SOAP));
            role.appendChild(endpoint(document, "AssertionIDRequestService", MetadataService.SOAP));
            text(document, role, "AttributeProfile", "urn:oasis:names:tc:SAML:2.0:profiles:attribute:basic");
            attribute(document, role);
        }
    }

    private static void commonSso(Document document, Element role) {
        var artifact = endpoint(document, "ArtifactResolutionService", MetadataService.SOAP);
        artifact.setAttribute("index", "0");
        artifact.setAttribute("isDefault", "true");
        insertBeforeNames(role, artifact, List.of("SingleLogoutService", "ManageNameIDService",
                "NameIDFormat", "AssertionConsumerService", "SingleSignOnService"));
        var manage = endpoint(document, "ManageNameIDService", MetadataService.POST);
        insertBeforeNames(role, manage, List.of("NameIDFormat", "AssertionConsumerService", "SingleSignOnService"));
        for (var format : List.of("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress")) {
            var nameIdFormat = node(document, "NameIDFormat");
            nameIdFormat.setTextContent(format);
            insertBeforeNames(role, nameIdFormat, List.of("AssertionConsumerService", "SingleSignOnService"));
        }
    }

    private static Element endpoint(Document document, String name, String binding) {
        var endpoint = node(document, name);
        endpoint.setAttribute("Binding", binding);
        endpoint.setAttribute("Location", "https://example.invalid/" + name);
        endpoint.setAttribute("ResponseLocation", "https://example.invalid/response/" + name);
        endpoint.setAttributeNS("urn:samlscope:test:foreign", "foreign:attribute", "value");
        endpoint.appendChild(document.createElementNS("urn:samlscope:test:foreign", "foreign:endpoint"));
        return endpoint;
    }

    private static void removeEndpointExtensions(Element root) {
        var all = root.getElementsByTagNameNS(MD, "*");
        for (int index = 0; index < all.getLength(); index++) {
            var element = (Element) all.item(index);
            if (!element.hasAttribute("Binding") || !element.hasAttribute("Location")) continue;
            element.removeAttributeNS("urn:samlscope:test:foreign", "attribute");
            for (var child = element.getFirstChild(); child != null;) {
                var next = child.getNextSibling();
                if (child instanceof Element value && "urn:samlscope:test:foreign".equals(value.getNamespaceURI()))
                    element.removeChild(child);
                child = next;
            }
        }
    }

    private static void insertBeforeNames(Element parent, Element element, List<String> names) {
        for (var child = parent.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element value && MD.equals(value.getNamespaceURI())
                    && names.contains(value.getLocalName())) {
                parent.insertBefore(element, child);
                return;
            }
        }
        parent.appendChild(element);
    }

    private static void text(Document document, Element parent, String name, String value) {
        var element = node(document, name);
        element.setTextContent(value);
        parent.appendChild(element);
    }

    private static void attribute(Document document, Element parent) {
        var attribute = document.createElementNS(SAML, "saml:Attribute");
        attribute.setAttribute("Name", "urn:samlscope:schema:attribute");
        attribute.setAttribute("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:uri");
        attribute.setAttribute("FriendlyName", "schema-attribute");
        var value = document.createElementNS(SAML, "saml:AttributeValue");
        value.setTextContent("reference");
        attribute.appendChild(value);
        parent.appendChild(attribute);
    }

    private static Element recursiveEntities(Document document, Element entity) {
        var root = node(document, "EntitiesDescriptor");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:ds", MetadataService.DS);
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", "urn:samlscope:test:foreign");
        root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", SAML);
        root.setAttribute("ID", "_schema_outer_" + entity.getAttribute("ID"));
        var nested = node(document, "EntitiesDescriptor");
        nested.setAttribute("ID", "_schema_inner_" + entity.getAttribute("ID"));
        var other = (Element) entity.cloneNode(true);
        other.removeAttribute("ID");
        other.setAttribute("entityID", entity.getAttribute("entityID") + "/nested-schema-peer");
        document.replaceChild(root, entity);
        root.appendChild(entity);
        nested.appendChild(other);
        root.appendChild(nested);
        return root;
    }

    private static Element keyDescriptor(Document document, Element parent, String use) {
        var descriptor = node(document, "KeyDescriptor");
        if (use != null) descriptor.setAttribute("use", use);
        var existing = parent.getElementsByTagNameNS(MD, "KeyDescriptor");
        if (existing.getLength() == 0) throw new IllegalStateException("No valid key material for schema fixture");
        var keyInfo = ((Element) existing.item(0)).getElementsByTagNameNS(MetadataService.DS, "KeyInfo").item(0);
        if (keyInfo == null) throw new IllegalStateException("Missing key material for schema fixture");
        descriptor.appendChild(keyInfo.cloneNode(true));
        if (existing.getLength() > 0) {
            var last = existing.item(existing.getLength() - 1);
            parent.insertBefore(descriptor, last.getNextSibling());
        } else {
            parent.insertBefore(descriptor, parent.getFirstChild());
        }
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
