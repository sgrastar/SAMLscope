package com.samlscope.saml.metadata;

import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Controlled policy inputs; publishing these inputs is not evidence of target consumption. */
final class MetadataAttributePolicyFixtures {
    static final String MDATTR = "urn:oasis:names:tc:SAML:metadata:attribute";
    static final String POLICY_NAME = "urn:samlscope:test:release-policy";
    static final String ATTRIBUTE_NAME = "urn:oid:0.9.2342.19200300.100.1.1";
    static final String OTHER_ATTRIBUTE_NAME = "urn:oid:2.5.4.4";
    private static final String URI_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

    private MetadataAttributePolicyFixtures() {}

    static Element apply(Document doc, Element entity, MetadataService.Variant variant) {
        switch (variant) {
            case ATTRIBUTE_POLICY_ENTITY_PRESENT -> {
                var extensions = doc.createElementNS(MetadataService.MD, "md:Extensions");
                var attributes = doc.createElementNS(MDATTR, "mdattr:EntityAttributes");
                attributes.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdattr", MDATTR);
                var attribute = doc.createElementNS(MetadataService.SAML, "saml:Attribute");
                attribute.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:saml", MetadataService.SAML);
                attribute.setAttribute("Name", POLICY_NAME);
                attribute.setAttribute("NameFormat", URI_FORMAT);
                var value = doc.createElementNS(MetadataService.SAML, "saml:AttributeValue");
                value.setTextContent("release");
                attribute.appendChild(value);
                attributes.appendChild(attribute);
                extensions.appendChild(attributes);
                entity.insertBefore(extensions, entity.getFirstChild());
            }
            case ATTRIBUTE_POLICY_REQUESTED_REQUIRED -> consumingService(doc, entity, 0, ATTRIBUTE_NAME, true);
            case ATTRIBUTE_POLICY_REQUESTED_OPTIONAL -> consumingService(doc, entity, 0, ATTRIBUTE_NAME, false);
            case ATTRIBUTE_POLICY_INDEXED -> {
                consumingService(doc, entity, 0, ATTRIBUTE_NAME, true);
                consumingService(doc, entity, 1, OTHER_ATTRIBUTE_NAME, true);
            }
            // Explicit absence inputs keep both EntityAttributes and RequestedAttribute absent.
            case ATTRIBUTE_POLICY_ENTITY_ABSENT, ATTRIBUTE_POLICY_REQUESTED_ABSENT -> { }
            default -> { }
        }
        return entity;
    }

    private static void consumingService(Document doc, Element entity, int index, String name, boolean required) {
        var sp = (Element) entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        if (sp == null) throw new IllegalArgumentException("Attribute policy fixture requires SP role");
        var service = doc.createElementNS(MetadataService.MD, "md:AttributeConsumingService");
        service.setAttribute("index", Integer.toString(index));
        service.setAttribute("isDefault", Boolean.toString(index == 0));
        var label = doc.createElementNS(MetadataService.MD, "md:ServiceName");
        label.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
        label.setTextContent("SAMLscope attribute policy");
        service.appendChild(label);
        var attribute = doc.createElementNS(MetadataService.MD, "md:RequestedAttribute");
        attribute.setAttribute("Name", name);
        attribute.setAttribute("NameFormat", URI_FORMAT);
        attribute.setAttribute("isRequired", Boolean.toString(required));
        service.appendChild(attribute);
        sp.appendChild(service);
    }
}
