package com.samlscope.saml.metadata;

import javax.xml.XMLConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/** Each fixture changes one URL-bearing UI element; image reachability is a separate prerequisite. */
final class MetadataUiUrlFixtures {
    private MetadataUiUrlFixtures() {}
    static Element apply(Document doc, Element entity, MetadataService.Variant variant, MetadataUiAssetLocations assets) {
        if (!variant.id().startsWith("ui-url-")) return entity;
        var tokens = variant.id().split("-");
        if (tokens.length != 4) throw new IllegalArgumentException("Invalid UI URL variant");
        var name = switch (tokens[2]) {
            case "logo" -> "Logo";
            case "information" -> "InformationURL";
            case "privacy" -> "PrivacyStatementURL";
            default -> throw new IllegalArgumentException("Unknown UI URL element");
        };
        var value = switch (tokens[3]) {
            case "data" -> MetadataUiFixtureAsset.dataUri();
            // A hierarchical javascript URI also reaches native URL validators that
            // require an authority. It remains the same excluded scheme; the browser
            // payload is only a comment followed by void(0), with no external request.
            case "javascript" -> name.equals("Logo")
                    ? "javascript://samlscope-fixture/%0Avoid(0)" : "javascript:void(0)";
            case "file" -> "file:///samlscope-fixture-nonexistent/ui-url.svg";
            case "http" -> assets.http().toASCIIString();
            case "https" -> assets.https().toASCIIString();
            default -> throw new IllegalArgumentException("Unknown UI URL scheme");
        };
        var sp = (Element) entity.getElementsByTagNameNS(MetadataService.MD, "SPSSODescriptor").item(0);
        if (sp == null) throw new IllegalArgumentException("Missing SP role");
        var extensions = doc.createElementNS(MetadataService.MD, "md:Extensions");
        var info = doc.createElementNS(MetadataUiConsumerFixtures.UI, "mdui:UIInfo");
        info.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:mdui", MetadataUiConsumerFixtures.UI);
        var display = doc.createElementNS(MetadataUiConsumerFixtures.UI, "mdui:DisplayName");
        display.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
        display.setTextContent("SAMLscope URL policy control");
        info.appendChild(display);
        var url = doc.createElementNS(MetadataUiConsumerFixtures.UI, "mdui:" + name);
        if (name.equals("Logo")) {
            url.setAttribute("width", "180"); url.setAttribute("height", "48");
        } else url.setAttributeNS(XMLConstants.XML_NS_URI, "xml:lang", "en");
        url.setTextContent(value);
        info.appendChild(url);
        extensions.appendChild(info);
        sp.insertBefore(extensions, sp.getFirstChild());
        return entity;
    }
}
