package com.samlscope.saml.metadata;

import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Element;

/** Select only entities in the metadata aggregate hierarchy, excluding extension payloads. */
final class MetadataEntitySelection {
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private MetadataEntitySelection() {}
    static Element select(Element root, String entityId) {
        if (entityId == null || entityId.isBlank()) throw new IllegalArgumentException("Target entityID is required");
        if (!MD.equals(root.getNamespaceURI()) || !("EntityDescriptor".equals(root.getLocalName())
                || "EntitiesDescriptor".equals(root.getLocalName())))
            throw new IllegalArgumentException("Expected SAML metadata document");
        var matches = new ArrayList<Element>();
        collect(root, entityId, matches);
        if (matches.isEmpty()) throw new IllegalArgumentException("Selected entityID is absent from metadata");
        if (matches.size() != 1) throw new IllegalArgumentException("Metadata contains duplicate selected entityID");
        return matches.getFirst();
    }
    private static void collect(Element node, String id, List<Element> matches) {
        if (!MD.equals(node.getNamespaceURI())) return;
        if ("EntityDescriptor".equals(node.getLocalName())) {
            if (id.equals(node.getAttribute("entityID"))) matches.add(node);
        } else if ("EntitiesDescriptor".equals(node.getLocalName())) {
            for (var child = node.getFirstChild(); child != null; child = child.getNextSibling())
                if (child instanceof Element element) collect(element, id, matches);
        }
    }
}
