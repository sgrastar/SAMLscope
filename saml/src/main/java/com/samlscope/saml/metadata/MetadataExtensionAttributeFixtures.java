package com.samlscope.saml.metadata;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.XMLConstants;

/** One foreign attribute per metadata fixture; all ordinary flow endpoints remain available. */
final class MetadataExtensionAttributeFixtures {
    static final String FOREIGN = "urn:samlscope:fixture:foreign-attribute";
    private static final String MD = MetadataService.MD;
    private MetadataExtensionAttributeFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        if (!variant.id().startsWith("foreign-attribute-")) return entity;
        var target = switch (variant) {
            case FOREIGN_ATTRIBUTE_ENTITY -> entity;
            case FOREIGN_ATTRIBUTE_ORGANIZATION -> organization(document, entity);
            case FOREIGN_ATTRIBUTE_CONTACT -> contact(document, entity);
            case FOREIGN_ATTRIBUTE_ROLE -> role(document, entity);
            case FOREIGN_ATTRIBUTE_SINGLE_LOGOUT -> first(entity, "SingleLogoutService");
            case FOREIGN_ATTRIBUTE_SINGLE_SIGN_ON -> first(entity, "SingleSignOnService");
            case FOREIGN_ATTRIBUTE_MANAGE_NAMEID -> endpoint(document, first(entity, "SPSSODescriptor"), "ManageNameIDService", true);
            case FOREIGN_ATTRIBUTE_NAMEID_MAPPING -> endpoint(document, first(entity, "IDPSSODescriptor"), "NameIDMappingService", false);
            case FOREIGN_ATTRIBUTE_ASSERTION_ID -> endpoint(document, first(entity, "IDPSSODescriptor"), "AssertionIDRequestService", false);
            case FOREIGN_ATTRIBUTE_AUTHN_QUERY -> authority(document, entity, "AuthnAuthorityDescriptor", "AuthnQueryService");
            case FOREIGN_ATTRIBUTE_AUTHZ -> authority(document, entity, "PDPDescriptor", "AuthzService");
            case FOREIGN_ATTRIBUTE_ATTRIBUTE_SERVICE -> authority(document, entity, "AttributeAuthorityDescriptor", "AttributeService");
            case FOREIGN_ATTRIBUTE_AFFILIATION -> null;
            default -> throw new IllegalArgumentException("Unimplemented foreign attribute fixture: " + variant);
        };
        if (target != null) {
            mark(target);
            return entity;
        }
        var wrapper = node(document, "EntitiesDescriptor");
        wrapper.setAttribute("ID", entity.getAttribute("ID") + "_aggregate");
        wrapper.setAttribute("validUntil", entity.getAttribute("validUntil"));
        wrapper.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:md", MD);
        document.removeChild(entity);
        wrapper.appendChild(entity);
        var affiliated = node(document, "EntityDescriptor");
        affiliated.setAttribute("entityID", entity.getAttribute("entityID") + "/attribute-affiliation");
        var affiliation = node(document, "AffiliationDescriptor");
        affiliation.setAttribute("affiliationOwnerID", affiliated.getAttribute("entityID"));
        var member = node(document, "AffiliateMember");
        member.setTextContent(entity.getAttribute("entityID"));
        affiliation.appendChild(member);
        mark(affiliation);
        affiliated.appendChild(affiliation);
        wrapper.appendChild(affiliated);
        document.appendChild(wrapper);
        return wrapper;
    }

    private static Element organization(Document d, Element entity) {
        var organization = node(d, "Organization");
        for (var name : java.util.List.of("OrganizationName", "OrganizationDisplayName", "OrganizationURL")) {
            var value = node(d, name);
            value.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
            value.setTextContent(name.equals("OrganizationURL") ? "https://example.invalid/" : "SAMLscope fixture");
            organization.appendChild(value);
        }
        entity.appendChild(organization);
        return organization;
    }
    private static Element contact(Document d, Element entity) {
        var contact = node(d, "ContactPerson");
        contact.setAttribute("contactType", "technical");
        entity.appendChild(contact);
        return contact;
    }
    private static Element role(Document d, Element entity) {
        var original = first(entity, "SPSSODescriptor");
        var role = (Element) original.cloneNode(true);
        d.renameNode(role, MD, "md:RoleDescriptor");
        role.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
        role.setAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi:type", "md:SPSSODescriptorType");
        entity.appendChild(role);
        return role;
    }
    private static Element authority(Document d, Element entity, String roleName, String serviceName) {
        var role = node(d, roleName);
        role.setAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
        entity.appendChild(role);
        return endpoint(d, role, serviceName, false);
    }
    private static Element endpoint(Document d, Element role, String name, boolean beforeNameId) {
        var endpoint = node(d, name);
        endpoint.setAttribute("Binding", MetadataService.SOAP);
        // No probe is sent here. The unchanged SP/IdP endpoints establish consumption without software failure.
        endpoint.setAttribute("Location", "https://example.invalid/attribute-fixture/" + name);
        org.w3c.dom.Node before = null;
        if (beforeNameId) {
            for (var child = role.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof Element e && java.util.List.of("NameIDFormat", "AssertionConsumerService").contains(e.getLocalName())) {
                    before = child; break;
                }
            }
        }
        role.insertBefore(endpoint, before);
        return endpoint;
    }
    private static Element node(Document d, String name) { return d.createElementNS(MD, "md:" + name); }
    private static Element first(Element root, String name) {
        var result = root.getElementsByTagNameNS(MD, name);
        if (result.getLength() == 0) throw new IllegalStateException("Missing fixture parent: " + name);
        return (Element) result.item(0);
    }
    private static void mark(Element target) {
        target.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:foreign", FOREIGN);
        target.setAttributeNS(FOREIGN, "foreign:undefined", "ignored-content");
    }
}
