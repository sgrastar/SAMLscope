package com.samlscope.saml.normal;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.xml.XMLConstants;
import org.w3c.dom.Element;

/** Schema-bound input fragments. Creating an input does not prove target acceptance or a verdict. */
public final class SamlTypedStringFixtures {
    public static final String NAMESPACE = "urn:samlscope:fixture:string";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private SamlTypedStringFixtures() {}

    public enum Placement {
        PERSISTENT_NAMEID, TRANSIENT_NAMEID, ADVICE_STRING, ATTRIBUTE_VALUE_STRING, EXTENSION_STRING_ATTRIBUTE
    }

    public record Fixture(Placement placement, SamlErrorProbeRequestFactory.Probe characters) {
        public Fixture {
            Objects.requireNonNull(placement, "placement");
            if (!SamlErrorProbeRequestFactory.stringProbes().contains(characters) || characters.name().contains("_LITERAL_"))
                throw new IllegalArgumentException("Expected a string character fixture");
        }
        public String id() {
            return placement.name().toLowerCase(Locale.ROOT).replace('_', '-') + ":"
                    + characters.name().substring("STRING_".length()).toLowerCase(Locale.ROOT).replace('_', '-');
        }
        public String value() { return SamlErrorProbeRequestFactory.stringValue(characters); }
        public Element create() {
            var document = SecureXml.newDocument();
            String local = switch (placement) {
                case PERSISTENT_NAMEID, TRANSIENT_NAMEID -> "NameID";
                case ADVICE_STRING -> "Advice";
                case ATTRIBUTE_VALUE_STRING -> "AttributeValue";
                case EXTENSION_STRING_ATTRIBUTE -> "Extensions";
            };
            boolean protocol = placement == Placement.EXTENSION_STRING_ATTRIBUTE;
            var root = document.createElementNS(protocol ? PROTOCOL : ASSERTION, (protocol ? "samlp:" : "saml:") + local);
            root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, protocol ? "xmlns:samlp" : "xmlns:saml", protocol ? PROTOCOL : ASSERTION);
            document.appendChild(root);
            switch (placement) {
                case PERSISTENT_NAMEID, TRANSIENT_NAMEID -> {
                    root.setAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:"
                            + (placement == Placement.PERSISTENT_NAMEID ? "persistent" : "transient"));
                    root.setTextContent(value());
                }
                case ADVICE_STRING, EXTENSION_STRING_ATTRIBUTE -> {
                    root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:f", NAMESPACE);
                    var child = document.createElementNS(NAMESPACE,
                            placement == Placement.ADVICE_STRING ? "f:AdviceString" : "f:ExtensionString");
                    if (placement == Placement.ADVICE_STRING) child.setTextContent(value());
                    else child.setAttribute("value", value());
                    root.appendChild(child);
                }
                case ATTRIBUTE_VALUE_STRING -> {
                    root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:f", NAMESPACE);
                    root.setAttributeNS(XMLConstants.XMLNS_ATTRIBUTE_NS_URI, "xmlns:xsi", XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI);
                    root.setAttributeNS(XMLConstants.W3C_XML_SCHEMA_INSTANCE_NS_URI, "xsi:type", "f:MyStringType");
                    root.setTextContent(value());
                }
            }
            return root;
        }
    }

    public static List<Fixture> matrix() {
        return java.util.Arrays.stream(Placement.values()).flatMap(placement ->
                SamlErrorProbeRequestFactory.stringProbes().stream().filter(probe -> !probe.name().contains("_LITERAL_")).map(probe -> new Fixture(placement, probe))).toList();
    }
}
