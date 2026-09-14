package com.samlscope.saml.normal;

import java.nio.charset.StandardCharsets;

/** Preserves the lexical TAB/LF fixture while XML signature verification sees normalized spaces. */
public final class ProviderNameWireFormat {
    private ProviderNameWireFormat() {}
    public static byte[] literalWhitespace(byte[] serialized) {
        var xml = text(serialized);
        var span = span(xml);
        var value = xml.substring(span[0], span[1]);
        value = value.replace("&#9;", "\t").replace("&#x9;", "\t")
                .replace("&#10;", "\n").replace("&#xA;", "\n").replace("&#xa;", "\n");
        return replace(xml, span, value);
    }
    public static byte[] preserve(byte[] original, byte[] signed) {
        var originalRoot = SecureXml.parse(original).getDocumentElement();
        if (!originalRoot.hasAttribute("ProviderName")) return signed;
        var before = text(original);
        var location = span(before);
        var lexical = before.substring(location[0], location[1]);
        if (!lexical.contains("\t") && !lexical.contains("\n")) return signed;
        var signedRoot = SecureXml.parse(signed).getDocumentElement();
        if (!originalRoot.getAttribute("ProviderName").equals(signedRoot.getAttribute("ProviderName")))
            throw new SamlException("Signing changed the parsed ProviderName value");
        var after = text(signed);
        return replace(after, span(after), lexical);
    }
    private static String text(byte[] bytes) {
        var root = SecureXml.parse(bytes).getDocumentElement();
        if (!"urn:oasis:names:tc:SAML:2.0:protocol".equals(root.getNamespaceURI())
                || !"AuthnRequest".equals(root.getLocalName())) throw new SamlException("Expected AuthnRequest");
        return new String(bytes, StandardCharsets.UTF_8);
    }
    private static byte[] replace(String xml, int[] span, String value) {
        var result = (xml.substring(0,span[0]) + value + xml.substring(span[1])).getBytes(StandardCharsets.UTF_8);
        SecureXml.parse(result);
        return result;
    }
    // Quote-aware scanner: skip prolog/comments, then inspect only the root start tag.
    // Return the entire quoted value so original quote/entity spelling remains intact.
    private static int[] span(String xml) {
        int p = 0;
        while (true) {
            while (p < xml.length() && (Character.isWhitespace(xml.charAt(p)) || xml.charAt(p)=='\uFEFF')) p++;
            if (xml.startsWith("<?",p)) { p=end(xml,"?>",p)+2; continue; }
            if (xml.startsWith("<!--",p)) { p=end(xml,"-->",p)+3; continue; }
            break;
        }
        if (p>=xml.length() || xml.charAt(p++)!='<') throw new SamlException("Missing root start tag");
        while (p<xml.length() && !Character.isWhitespace(xml.charAt(p)) && xml.charAt(p)!='>' && xml.charAt(p)!='/') p++;
        while (p<xml.length()) {
            while (p<xml.length() && Character.isWhitespace(xml.charAt(p))) p++;
            if (p==xml.length() || xml.charAt(p)=='>' || xml.charAt(p)=='/') break;
            int name=p;
            while (p<xml.length() && !Character.isWhitespace(xml.charAt(p)) && xml.charAt(p)!='=') p++;
            String attribute=xml.substring(name,p);
            while (p<xml.length() && Character.isWhitespace(xml.charAt(p))) p++;
            if (p==xml.length() || xml.charAt(p++)!='=') throw new SamlException("Malformed attribute");
            while (p<xml.length() && Character.isWhitespace(xml.charAt(p))) p++;
            if (p==xml.length() || (xml.charAt(p)!='\'' && xml.charAt(p)!='"')) throw new SamlException("Missing attribute quote");
            int start=p;char quote=xml.charAt(p++);
            while (p<xml.length() && xml.charAt(p)!=quote) p++;
            if (p==xml.length()) throw new SamlException("Unterminated attribute");
            p++;
            if (attribute.equals("ProviderName")) return new int[]{start,p};
        }
        throw new SamlException("Missing ProviderName attribute");
    }
    private static int end(String xml,String token,int start) {
        int end=xml.indexOf(token,start);if(end<0) throw new SamlException("Unterminated XML prolog");return end;
    }
}
