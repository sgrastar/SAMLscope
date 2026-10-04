package com.samlscope.saml.normal;

import java.io.InputStream;
import java.io.Reader;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.sax.SAXResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.TypeInfoProvider;
import javax.xml.validation.ValidatorHandler;
import org.w3c.dom.Element;
import org.w3c.dom.TypeInfo;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/** Offline, DTD-free validation against the SAML 2.0 schemas shipped with the pinned OpenSAML runtime. */
public final class SamlSchemaValidation {
    public enum SchemaKind { PROTOCOL, ASSERTION, METADATA }

    private static final Map<String, String> NAMESPACE_RESOURCES = Map.of(
            "urn:oasis:names:tc:SAML:2.0:metadata", "schema/saml-schema-metadata-2.0.xsd",
            "http://www.w3.org/XML/1998/namespace", "schema/xml.xsd",
            "urn:oasis:names:tc:SAML:2.0:protocol", "schema/saml-schema-protocol-2.0.xsd",
            "urn:oasis:names:tc:SAML:2.0:assertion", "schema/saml-schema-assertion-2.0.xsd",
            "http://www.w3.org/2000/09/xmldsig#", "schema/xmldsig-core-schema.xsd",
            "http://www.w3.org/2001/04/xmlenc#", "schema/xenc-schema.xsd",
            "http://www.w3.org/2009/xmlenc11#", "schema/xenc11-schema.xsd");
    private static final Schema PROTOCOL = load("urn:oasis:names:tc:SAML:2.0:protocol");
    private static final Schema ASSERTION = load("urn:oasis:names:tc:SAML:2.0:assertion");
    private static final Schema METADATA = load("urn:oasis:names:tc:SAML:2.0:metadata");
    private static final class StringFixtureSchema {
        private static final Schema INSTANCE = load("urn:oasis:names:tc:SAML:2.0:protocol", true);
    }

    private SamlSchemaValidation() {}

    public static boolean isValid(Element element, SchemaKind kind) {
        return validationFailure(element, kind).isEmpty();
    }

    public static java.util.Optional<String> validationFailure(Element element, SchemaKind kind) {
        return validationFailure(element, schema(kind));
    }

    /** Explicit opt-in for Suite-generated input only; normal target validation is unchanged. */
    public static java.util.Optional<String> stringFixtureValidationFailure(Element element) {
        return validationFailure(element, StringFixtureSchema.INSTANCE);
    }

    private static java.util.Optional<String> validationFailure(Element element, Schema schema) {
        try {
            var validator = schema.newValidator();
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            validator.validate(new DOMSource(element));
            return java.util.Optional.empty();
        } catch (SAXException | java.io.IOException invalid) {
            return java.util.Optional.ofNullable(invalid.getMessage()).or(() -> java.util.Optional.of("Schema validation failed"));
        }
    }

    /**
     * Validates an element and reports values whose schema type is {@code xs:string}
     * or a simple-content type derived from it. This deliberately uses schema type
     * information rather than element-name heuristics.
     */
    public static StringInspection inspectStringValues(Element element, SchemaKind kind) {
        return inspectStringValues(element, schema(kind));
    }

    /** Resolves the fixed Suite fixture type, never arbitrary network or target schemas. */
    public static StringInspection inspectFixtureStringValues(Element element) {
        return inspectStringValues(element, StringFixtureSchema.INSTANCE);
    }

    private static StringInspection inspectStringValues(Element element, Schema schema) {
        try {
            var handler = schema.newValidatorHandler();
            var collector = new StringValueCollector(handler.getTypeInfoProvider());
            handler.setContentHandler(collector);
            var transformerFactory = javax.xml.transform.TransformerFactory.newInstance();
            transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            transformerFactory.newTransformer().transform(new DOMSource(element), new SAXResult(handler));
            return new StringInspection(true, collector.values());
        } catch (javax.xml.transform.TransformerException failure) {
            return new StringInspection(false, List.of());
        }
    }

    public record TypedStringValue(String path, String value, boolean attribute) {
        public TypedStringValue {
            path = java.util.Objects.requireNonNull(path, "path");
            value = java.util.Objects.requireNonNull(value, "value");
        }
    }

    public record StringInspection(boolean schemaValid, List<TypedStringValue> values) {
        public StringInspection {
            values = List.copyOf(values);
        }
    }

    private static Schema schema(SchemaKind kind) {
        return switch (kind) { case PROTOCOL -> PROTOCOL; case ASSERTION -> ASSERTION; case METADATA -> METADATA; };
    }

    private static boolean isString(TypeInfo type) {
        if (type == null) return false;
        if (XMLConstants.W3C_XML_SCHEMA_NS_URI.equals(type.getTypeNamespace())
                && "string".equals(type.getTypeName())) return true;
        return type.isDerivedFrom(
                XMLConstants.W3C_XML_SCHEMA_NS_URI,
                "string",
                TypeInfo.DERIVATION_RESTRICTION | TypeInfo.DERIVATION_EXTENSION);
    }

    private static final class StringValueCollector extends DefaultHandler {
        private final TypeInfoProvider types;
        private final ArrayDeque<ElementValue> elements = new ArrayDeque<>();
        private final List<TypedStringValue> values = new ArrayList<>();

        private StringValueCollector(TypeInfoProvider types) {
            this.types = types;
        }

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) {
            var path = (elements.isEmpty() ? "" : elements.peek().path()) + "/" + display(uri, localName, qName);
            elements.push(new ElementValue(path, isString(types.getElementTypeInfo()), new StringBuilder()));
            for (var index = 0; index < attributes.getLength(); index++) {
                if (isString(types.getAttributeTypeInfo(index))) {
                    values.add(new TypedStringValue(
                            path + "/@" + display(attributes.getURI(index), attributes.getLocalName(index), attributes.getQName(index)),
                            attributes.getValue(index),
                            true));
                }
            }
        }

        @Override
        public void characters(char[] characters, int start, int length) {
            if (!elements.isEmpty()) elements.peek().text().append(characters, start, length);
        }

        @Override
        public void endElement(String uri, String localName, String qName) {
            var element = elements.pop();
            if (element.stringType()) {
                values.add(new TypedStringValue(element.path(), element.text().toString(), false));
            }
        }

        private List<TypedStringValue> values() {
            return List.copyOf(values);
        }

        private static String display(String uri, String localName, String qName) {
            var name = localName == null || localName.isBlank() ? qName : localName;
            return uri == null || uri.isBlank() ? name : "{" + uri + "}" + name;
        }

        private record ElementValue(String path, boolean stringType, StringBuilder text) {}
    }

    private static Schema load(String namespace) {
        return load(namespace, false);
    }

    private static Schema load(String namespace, boolean stringFixtures) {
        try {
            var factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setResourceResolver(new ClasspathResolver());
            var resource = NAMESPACE_RESOURCES.get(namespace);
            var stream = requiredResource(resource);
            var source = new StreamSource(stream, "classpath:/" + resource);
            var xmlEncryption11Resource = NAMESPACE_RESOURCES.get("http://www.w3.org/2009/xmlenc11#");
            var xmlEncryption11 = new StreamSource(
                    requiredResource(xmlEncryption11Resource), "classpath:/" + xmlEncryption11Resource);
            if (stringFixtures) {
                var fixture = new StreamSource(requiredResource("schema/samlscope-string-fixtures.xsd"),
                        "classpath:/schema/samlscope-string-fixtures.xsd");
                return factory.newSchema(new StreamSource[] {source, xmlEncryption11, fixture});
            }
            return factory.newSchema(new StreamSource[] {source, xmlEncryption11});
        } catch (SAXException failure) {
            throw new ExceptionInInitializerError(failure);
        }
    }

    private static InputStream requiredResource(String resource) {
        var stream = SamlSchemaValidation.class.getClassLoader().getResourceAsStream(resource);
        if (stream == null) throw new IllegalStateException("Missing pinned schema resource: " + resource);
        return stream;
    }

    private static final class ClasspathResolver implements LSResourceResolver {
        @Override
        public LSInput resolveResource(
                String type, String namespaceURI, String publicId, String systemId, String baseURI) {
            var resource = NAMESPACE_RESOURCES.get(namespaceURI);
            if (resource == null) return null;
            return new Input(publicId, systemId, "classpath:/" + resource, requiredResource(resource));
        }
    }

    private static final class Input implements LSInput {
        private String publicId;
        private String systemId;
        private String baseUri;
        private InputStream byteStream;
        private String encoding;
        private String stringData;
        private Reader characterStream;
        private boolean certifiedText;

        private Input(String publicId, String systemId, String baseUri, InputStream byteStream) {
            this.publicId = publicId;
            this.systemId = systemId;
            this.baseUri = baseUri;
            this.byteStream = byteStream;
        }

        @Override public Reader getCharacterStream() { return characterStream; }
        @Override public void setCharacterStream(Reader value) { characterStream = value; }
        @Override public InputStream getByteStream() { return byteStream; }
        @Override public void setByteStream(InputStream value) { byteStream = value; }
        @Override public String getStringData() { return stringData; }
        @Override public void setStringData(String value) { stringData = value; }
        @Override public String getSystemId() { return systemId; }
        @Override public void setSystemId(String value) { systemId = value; }
        @Override public String getPublicId() { return publicId; }
        @Override public void setPublicId(String value) { publicId = value; }
        @Override public String getBaseURI() { return baseUri; }
        @Override public void setBaseURI(String value) { baseUri = value; }
        @Override public String getEncoding() { return encoding; }
        @Override public void setEncoding(String value) { encoding = value; }
        @Override public boolean getCertifiedText() { return certifiedText; }
        @Override public void setCertifiedText(boolean value) { certifiedText = value; }
    }
}
