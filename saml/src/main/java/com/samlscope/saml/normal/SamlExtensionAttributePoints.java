package com.samlscope.saml.normal;

import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import org.w3c.dom.Element;

/** Declared types containing their own anyAttribute, without adding inherited wildcards. */
public final class SamlExtensionAttributePoints {
    private static final String XSD = "http://www.w3.org/2001/XMLSchema";
    private SamlExtensionAttributePoints() {}

    public record Point(QName element, QName declaredType) {}

    public static List<Point> inventory() {
        var result = new ArrayList<Point>();
        for (var resource : List.of("schema/saml-schema-protocol-2.0.xsd",
                "schema/saml-schema-assertion-2.0.xsd", "schema/saml-schema-metadata-2.0.xsd")) {
            try (var stream = SamlExtensionAttributePoints.class.getClassLoader().getResourceAsStream(resource)) {
                if (stream == null) throw new IllegalStateException("Missing pinned schema: " + resource);
                var root = SecureXml.parse(stream.readAllBytes()).getDocumentElement();
                var namespace = root.getAttribute("targetNamespace");
                var types = new java.util.HashSet<String>();
                for (var node = root.getFirstChild(); node != null; node = node.getNextSibling()) {
                    if (node instanceof Element type && XSD.equals(type.getNamespaceURI())
                            && "complexType".equals(type.getLocalName())
                            && type.getElementsByTagNameNS(XSD, "anyAttribute").getLength() > 0) {
                        types.add(type.getAttribute("name"));
                    }
                }
                var declarations = root.getElementsByTagNameNS(XSD, "element");
                for (int i = 0; i < declarations.getLength(); i++) {
                    var element = (Element) declarations.item(i);
                    var lexical = element.getAttribute("type");
                    if (lexical.isEmpty() || !element.hasAttribute("name")) continue;
                    int colon = lexical.indexOf(':');
                    var local = colon < 0 ? lexical : lexical.substring(colon + 1);
                    var typeNamespace = element.lookupNamespaceURI(colon < 0 ? null : lexical.substring(0, colon));
                    if (namespace.equals(typeNamespace) && types.contains(local)) {
                        result.add(new Point(new QName(namespace, element.getAttribute("name")), new QName(namespace, local)));
                    }
                }
            } catch (java.io.IOException failure) {
                throw new IllegalStateException("Cannot read pinned schema: " + resource, failure);
            }
        }
        return result.stream().distinct().sorted(java.util.Comparator.comparing(point -> point.element().toString())).toList();
    }
}
