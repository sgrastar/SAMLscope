package com.samlscope.saml.metadata;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import javax.xml.XMLConstants;

/** Exercises extension points with their required enclosing metadata structure intact. */
final class MetadataExtensionPlacementFixtures {
    private MetadataExtensionPlacementFixtures() {}

    static Element apply(Document document, Element entity, MetadataService.Variant variant) {
        var parentVariant = switch (variant) {
            case UNKNOWN_ORGANIZATION_EXTENSION, INVALID_ORGANIZATION_SAML_EXTENSION -> MetadataService.Variant.FOREIGN_ATTRIBUTE_ORGANIZATION;
            case UNKNOWN_CONTACT_EXTENSION -> MetadataService.Variant.FOREIGN_ATTRIBUTE_CONTACT;
            case UNKNOWN_AFFILIATION_EXTENSION -> MetadataService.Variant.FOREIGN_ATTRIBUTE_AFFILIATION;
            default -> null;
        };
        if (parentVariant == null) return entity;
        var root = MetadataExtensionAttributeFixtures.apply(document, entity, parentVariant);
        var parentName = switch (variant) {
            case UNKNOWN_CONTACT_EXTENSION -> "ContactPerson";
            case UNKNOWN_AFFILIATION_EXTENSION -> "AffiliationDescriptor";
            default -> "Organization";
        };
        var parent = (Element) root.getElementsByTagNameNS(MetadataService.MD, parentName).item(0);
        parent.removeAttributeNS(MetadataExtensionAttributeFixtures.FOREIGN, "undefined");
        parent.removeAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "foreign");
        var extensions = document.createElementNS(MetadataService.MD, "md:Extensions");
        Element probe;
        if (variant == MetadataService.Variant.INVALID_ORGANIZATION_SAML_EXTENSION) {
            probe = document.createElementNS(MetadataService.SAML, "saml:Attribute");
            probe.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", MetadataService.SAML);
            probe.setAttribute("Name", "invalid-at-this-extension-point");
        } else {
            var namespace = "urn:samlscope:test:metadata-extension";
            probe = document.createElementNS(namespace, "samlscope:Probe");
            probe.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:samlscope", namespace);
            probe.setTextContent(variant.id());
        }
        extensions.appendChild(probe);
        parent.insertBefore(extensions, parent.getFirstChild());
        return root;
    }
}
