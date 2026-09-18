package com.samlscope.saml.metadata;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Consumer inputs only: metadata import does not prove that a browser displayed any candidate. */
final class MetadataUiConsumerFixtures {
    static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    static final String DISPLAY_NAME = "SAMLscope UI display candidate";
    static final String SERVICE_NAME = "SAMLscope service candidate";

    private MetadataUiConsumerFixtures() {}

    static Element apply(Document doc, Element entity, MetadataService.Variant variant) {
        if (!variant.id().startsWith("ui-consumer-")) return entity;
        var sp = (Element) entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        if (sp == null) throw new IllegalArgumentException("UI consumer fixture requires SP role");
        switch (variant) {
            case UI_CONSUMER_DISPLAY_ALL -> {
                var info = info(doc, sp);
                var display = ui(doc, "DisplayName");
                display.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
                display.setTextContent(DISPLAY_NAME);
                info.appendChild(display);
                serviceName(doc, sp);
            }
            case UI_CONSUMER_DISPLAY_SERVICE -> serviceName(doc, sp);
            case UI_CONSUMER_DISPLAY_ENTITY -> { }
            case UI_CONSUMER_LOGO_LOCALIZED, UI_CONSUMER_LOGO_FALLBACK -> {
                var info = info(doc, sp);
                // A no-language candidate coexists with a localized candidate in both fixtures.
                // The browser adapter must prove its preferred language, never infer it from this label.
                logo(doc, info, null, "DEFAULT", "#1d4ed8");
                logo(doc, info, variant == MetadataService.Variant.UI_CONSUMER_LOGO_LOCALIZED ? "en" : "fr",
                        "LOCALIZED", "#b45309");
            }
            default -> throw new IllegalArgumentException("Unknown UI consumer fixture");
        }
        return entity;
    }

    private static Element info(Document doc, Element sp) {
        var extensions = doc.createElementNS(MetadataService.MD, "md:Extensions");
        var info = ui(doc, "UIInfo");
        info.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdui", UI);
        extensions.appendChild(info);
        sp.insertBefore(extensions, sp.getFirstChild());
        return info;
    }

    private static void serviceName(Document doc, Element sp) {
        var service = doc.createElementNS(MetadataService.MD, "md:AttributeConsumingService");
        service.setAttribute("index", "0");
        service.setAttribute("isDefault", "true");
        var name = doc.createElementNS(MetadataService.MD, "md:ServiceName");
        name.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
        name.setTextContent(SERVICE_NAME);
        service.appendChild(name);
        // A schema-valid AttributeConsumingService requires a RequestedAttribute.
        var attribute = doc.createElementNS(MetadataService.MD, "md:RequestedAttribute");
        attribute.setAttribute("Name", MetadataAttributePolicyFixtures.ATTRIBUTE_NAME);
        attribute.setAttribute("isRequired", "false");
        service.appendChild(attribute);
        sp.appendChild(service);
    }

    private static void logo(Document doc, Element info, String language, String label, String color) {
        var logo = ui(doc, "Logo");
        logo.setAttribute("width", "180");
        logo.setAttribute("height", "48");
        if (language != null) logo.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", language);
        // Fixed inert assets: no remote request, scripting, or dependence on an external host.
        var svg = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\">"
                + "<rect width=\"180\" height=\"48\" fill=\"" + color + "\"/>"
                + "<text x=\"12\" y=\"30\" fill=\"white\" font-size=\"18\">" + label + "</text></svg>";
        logo.setTextContent("data:image/svg+xml;base64,"
                + Base64.getEncoder().encodeToString(svg.getBytes(StandardCharsets.UTF_8)));
        info.appendChild(logo);
    }

    private static Element ui(Document doc, String name) { return doc.createElementNS(UI, "mdui:" + name); }
}
