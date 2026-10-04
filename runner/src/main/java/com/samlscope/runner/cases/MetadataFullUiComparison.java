package com.samlscope.runner.cases;

import com.samlscope.saml.normal.SecureXml;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.w3c.dom.Element;

/** Value comparison for the approved complete MetaUI input, independent of the native adapter.
 * Unknown foreign extensions are harmless-input controls; retaining their undefined meaning is
 * deliberately not a condition of satisfaction. */
public final class MetadataFullUiComparison {
    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    static final String UI = "urn:oasis:names:tc:SAML:metadata:ui";
    private static final Set<String> UI_FIELDS = Set.of("DisplayName", "Description", "Keywords",
            "Logo", "InformationURL", "PrivacyStatementURL");
    private static final Set<String> HINT_FIELDS = Set.of("IPHint", "DomainHint", "GeolocationHint");

    public record Values(String entityId, Map<String, List<String>> knownValues,
            int foreignUiChildren, int foreignHintChildren) {
        public Values { knownValues = Map.copyOf(knownValues); }
    }

    public static Values input(byte[] raw) throws Exception {
        var value = read(raw, true);
        for (var field : UI_FIELDS) require(value.knownValues().containsKey("ui:" + field));
        for (var field : HINT_FIELDS) require(value.knownValues().containsKey("hint:" + field));
        require(value.foreignUiChildren() > 0 && value.foreignHintChildren() > 0);
        var display = value.knownValues().get("ui:DisplayName");
        require(display.size() > 1 && display.stream().map(v -> v.substring(0, v.indexOf('|')))
                .distinct().count() == display.size());
        var ips = value.knownValues().get("hint:IPHint");
        require(ips.stream().anyMatch(v -> v.contains(":")) && ips.stream().anyMatch(v -> v.contains(".")));
        return value;
    }

    public static Values output(byte[] raw) throws Exception { return read(raw, false); }

    public static boolean matches(Values input, Values output) {
        return input.entityId().equals(output.entityId()) && input.knownValues().equals(output.knownValues());
    }

    private static Values read(byte[] raw, boolean input) throws Exception {
        require(raw != null && raw.length > 0 && raw.length <= 1048576);
        var root = SecureXml.parse(raw).getDocumentElement();
        require(MD.equals(root.getNamespaceURI()) && "EntityDescriptor".equals(root.getLocalName()));
        require(!root.getAttribute("entityID").isBlank());
        var role = one(children(root, MD, "SPSSODescriptor"));
        var extensionNodes = children(role, MD, "Extensions");
        if (!input && extensionNodes.isEmpty()) return new Values(root.getAttribute("entityID"), Map.of(), 0, 0);
        var extensions = one(extensionNodes);
        var infos = children(extensions, UI, "UIInfo");
        var hints = children(extensions, UI, "DiscoHints");
        // A selected native model that ignores both extensions is the complete normative mutant.
        if (!input && infos.isEmpty() && hints.isEmpty())
            return new Values(root.getAttribute("entityID"), Map.of(), 0, 0);
        var info = one(infos); var hint = one(hints);
        var values = new LinkedHashMap<String, List<String>>();
        int foreignUi = fields(info, UI_FIELDS, "ui:", values);
        int foreignHint = fields(hint, HINT_FIELDS, "hint:", values);
        values.replaceAll((key, list) -> list.stream().sorted().toList());
        return new Values(root.getAttribute("entityID"), values, foreignUi, foreignHint);
    }

    private static int fields(Element parent, Set<String> known, String prefix,
            Map<String, List<String>> values) {
        int foreign = 0;
        for (var child : children(parent, null, null)) {
            if (!UI.equals(child.getNamespaceURI())) {
                require(child.getNamespaceURI() != null && !child.getNamespaceURI().isBlank());
                foreign++; continue;
            }
            require(known.contains(child.getLocalName()) && children(child, null, null).isEmpty());
            String text = child.getTextContent().strip(); require(!text.isBlank());
            String value = text;
            if (prefix.equals("ui:")) {
                String lang = child.getAttributeNS("http://www.w3.org/XML/1998/namespace", "lang");
                require(!lang.isBlank()); value = lang + "|" + text;
                if (child.getLocalName().equals("Logo")) {
                    require(child.getAttribute("width").matches("[1-9][0-9]*")
                            && child.getAttribute("height").matches("[1-9][0-9]*"));
                    value = lang + "|" + child.getAttribute("width") + "|" + child.getAttribute("height") + "|" + text;
                }
            }
            values.computeIfAbsent(prefix + child.getLocalName(), ignored -> new ArrayList<>()).add(value);
        }
        return foreign;
    }

    static List<Element> children(Element parent, String namespace, String name) {
        var result = new ArrayList<Element>();
        for (var node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element && (namespace == null || namespace.equals(element.getNamespaceURI()))
                    && (name == null || name.equals(element.getLocalName()))) result.add(element);
        return result;
    }
    static Element one(List<Element> nodes) { require(nodes.size() == 1); return nodes.getFirst(); }
    static void require(boolean value) { if (!value) throw new IllegalArgumentException("Full UI proof incomplete"); }
}
