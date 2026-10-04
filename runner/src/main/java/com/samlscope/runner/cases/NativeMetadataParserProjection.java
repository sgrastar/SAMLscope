package com.samlscope.runner.cases;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.*;
import javax.xml.datatype.Duration;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.*;
import org.w3c.dom.Node;

/** Full public native object tree, without dropping unknown attributes or other parser output. */
public final class NativeMetadataParserProjection {
    private NativeMetadataParserProjection() {}
    public record Observation(String rootType, List<String> entityIds, List<Boolean> affiliationDescriptorPresent, String tree) {
        public Observation { entityIds = List.copyOf(entityIds); affiliationDescriptorPresent = List.copyOf(affiliationDescriptorPresent); }
    }
    public static String parse(ClassLoader loader, byte[] original) throws Exception { return observe(loader, original).tree(); }
    public static Observation observe(ClassLoader loader, byte[] original) throws Exception {
        var factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
        var reader = factory.createXMLEventReader(new ByteArrayInputStream(original));
        try {
            var type = loader.loadClass("org.keycloak.saml.processing.core.parsers.saml.SAMLParser");
            var parser = type.getMethod("getInstance").invoke(null);
            var parsed = type.getMethod("parse", XMLEventReader.class).invoke(parser, reader);
            if (!parsed.getClass().getName().equals("org.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType"))
                throw new IllegalArgumentException("Native aggregate type absent");
            var entities = (List<?>) parsed.getClass().getMethod("getEntityDescriptor").invoke(parsed);
            var ids = new ArrayList<String>(); var affiliations = new ArrayList<Boolean>();
            for (var entity : entities) {
                if (!entity.getClass().getName().equals("org.keycloak.dom.saml.v2.metadata.EntityDescriptorType"))
                    throw new IllegalArgumentException("Nested native aggregate is outside this observation");
                ids.add((String) entity.getClass().getMethod("getEntityID").invoke(entity));
                boolean hasAffiliation = false;
                for (var choice : (List<?>) entity.getClass().getMethod("getChoiceType").invoke(entity))
                    hasAffiliation |= choice.getClass().getMethod("getAffiliationDescriptor").invoke(choice) != null;
                affiliations.add(hasAffiliation);
            }
            return new Observation(parsed.getClass().getName(), ids, affiliations, project(parsed));
        } finally { reader.close(); }
    }
    static String project(Object nativeObject) throws Exception { return new Tree().value(nativeObject, 0); }

    private static final class Tree {
        int nodes;
        String value(Object object, int depth) throws Exception {
            if (object == null) return "N";
            if (depth > 64 || ++nodes > 100_000) throw new IllegalArgumentException("Native object tree exceeds bounds");
            if (object instanceof CharSequence || object instanceof Number || object instanceof Boolean
                    || object instanceof Enum<?> || object instanceof URI || object instanceof QName
                    || object instanceof XMLGregorianCalendar || object instanceof Duration)
                return frame(object.getClass().getName()) + frame(object.toString());
            if (object instanceof Node node) {
                var attributes = new TreeMap<String,String>();
                if (node.getAttributes() != null) for (int i = 0; i < node.getAttributes().getLength(); i++) {
                    var attribute = node.getAttributes().item(i);
                    attributes.put(frame(Objects.toString(attribute.getNamespaceURI(), "")) + frame(attribute.getNodeName()),
                            frame(attribute.getNodeValue()));
                }
                var children = new ArrayList<String>();
                for (var child = node.getFirstChild(); child != null; child = child.getNextSibling())
                    children.add(value(child, depth + 1));
                return "D" + frame(Short.toString(node.getNodeType()))
                        + frame(Objects.toString(node.getNamespaceURI(), "")) + frame(node.getNodeName())
                        + frame(Objects.toString(node.getNodeValue(), "")) + map(attributes) + sequence(children);
            }
            if (object instanceof Collection<?> collection) {
                var result = new ArrayList<String>();
                for (var item : collection) result.add(value(item, depth + 1));
                return "L" + sequence(result);
            }
            if (object instanceof Map<?,?> source) {
                var result = new TreeMap<String,String>();
                for (var entry : source.entrySet()) {
                    var key = value(entry.getKey(), depth + 1);
                    if (result.put(key, value(entry.getValue(), depth + 1)) != null)
                        throw new IllegalArgumentException("Ambiguous native map key");
                }
                return "M" + map(result);
            }
            if (!object.getClass().getName().startsWith("org.keycloak.dom."))
                throw new IllegalArgumentException("Unsupported native object type");
            var properties = new TreeMap<String,String>();
            for (var method : object.getClass().getMethods()) {
                if (method.getParameterCount() == 0 && !method.getName().equals("getClass")
                        && (method.getName().startsWith("get") || method.getName().startsWith("is"))) {
                    if (properties.put(method.getName(), value(method.invoke(object), depth + 1)) != null)
                        throw new IllegalArgumentException("Ambiguous native getter");
                }
            }
            if (properties.isEmpty()) throw new IllegalArgumentException("Native object has no observable properties");
            return "O" + frame(object.getClass().getName()) + map(properties);
        }
        private static String frame(String value) { return value.length() + ":" + value; }
        private static String sequence(List<String> values) {
            var result = new StringBuilder().append(values.size()).append(':');
            values.forEach(value -> result.append(frame(value))); return result.toString();
        }
        private static String map(Map<String,String> values) {
            var result = new ArrayList<String>();
            values.forEach((key, value) -> result.add(frame(key) + frame(value)));
            return sequence(result);
        }
    }
}
