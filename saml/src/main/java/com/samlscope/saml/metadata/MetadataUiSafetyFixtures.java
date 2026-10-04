package com.samlscope.saml.metadata;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Explicit additional inputs for the approved MD05.fg runtime safety variants.
 * Existing UI URL fixtures, including their historical XML bytes, remain unchanged.
 * The fixed alert token contains no credential or product data. In a native image
 * context it must not execute; the browser adapter checks an isolated active-sink control.
 */
final class MetadataUiSafetyFixtures {
    static final String TOKEN = "SAMLscope-UI-safety-v1";
    static final String SCRIPT_SVG = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\">"
            + "<rect width=\"180\" height=\"48\" fill=\"#1d4ed8\"/>"
            + "<script>alert('" + TOKEN + "')</script></svg>";
    static final String JAVASCRIPT = "javascript:alert('" + TOKEN + "')";

    private MetadataUiSafetyFixtures() {}

    static Element apply(Document doc, Element entity, MetadataService.Variant variant) {
        if (!variant.id().startsWith("ui-safety-")) return entity;
        var roles = entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor");
        if (roles.getLength() != 1) throw new IllegalArgumentException("Single SP role required");
        var role = (Element) roles.item(0);
        var extension = doc.createElementNS(MetadataService.MD, "md:Extensions");
        var info = doc.createElementNS(MetadataService.UI, "mdui:UIInfo");
        info.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdui", MetadataService.UI);
        var display = doc.createElementNS(MetadataService.UI, "mdui:DisplayName");
        display.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
        display.setTextContent("SAMLscope URL policy control");
        info.appendChild(display);
        String element = switch (variant) {
            case UI_SAFETY_LOGO_DATA -> "Logo";
            case UI_SAFETY_INFORMATION_JAVASCRIPT -> "InformationURL";
            case UI_SAFETY_PRIVACY_JAVASCRIPT -> "PrivacyStatementURL";
            default -> throw new IllegalArgumentException("Unknown runtime safety fixture");
        };
        var value = doc.createElementNS(MetadataService.UI, "mdui:" + element);
        if ("Logo".equals(element)) {
            value.setAttribute("width", "180"); value.setAttribute("height", "48");
            value.setTextContent("data:image/svg+xml;base64," + Base64.getEncoder()
                    .encodeToString(SCRIPT_SVG.getBytes(StandardCharsets.UTF_8)));
        } else {
            value.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
            value.setTextContent(JAVASCRIPT);
        }
        info.appendChild(value); extension.appendChild(info);
        role.insertBefore(extension, role.getFirstChild());
        return entity;
    }
}
