package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ProviderNameWireFormatTest {
    @Test void scopesRewritingToTheRootAttributeAcrossQuotesPrefixesAndPrologDecoys() {
        for (var quote : new String[]{"'","\""}) for (var prefix : new String[]{"","p:"})
            for (var prolog : new String[]{"","<?xml version='1.0'?><!-- <AuthnRequest ProviderName='decoy'/> --><?probe fake?>"})
                for (var whitespace : new String[]{"&#9;","&#10;","&#x9;","&#xA;"}) {
                    var ns=prefix.isEmpty()?"xmlns":"xmlns:p";
                    var xml=prolog+"<"+prefix+"AuthnRequest "+ns+"='urn:oasis:names:tc:SAML:2.0:protocol' Other='not&#9;ours>' ProviderName="
                            +quote+"a"+whitespace+"b"+quote+"/>";
                    var original=xml.getBytes(StandardCharsets.UTF_8);
                    var literal=ProviderNameWireFormat.literalWhitespace(original);
                    var parsed=SecureXml.parse(literal).getDocumentElement();
                    assertEquals("a b",parsed.getAttribute("ProviderName"));
                    assertEquals("not\tours>",parsed.getAttribute("Other"));
                    var serialized=SecureXml.serialize(parsed.getOwnerDocument());
                    var restored=ProviderNameWireFormat.preserve(literal,serialized);
                    var raw=new String(restored,StandardCharsets.UTF_8);
                    assertTrue(raw.contains("a\tb") || raw.contains("a\nb"));
                    assertEquals("a b",SecureXml.parse(restored).getDocumentElement().getAttribute("ProviderName"));
                }
    }
    @Test void refusesSemanticChangesAndLeavesReferenceInputsAlone() {
        var factory=new SamlErrorProbeRequestFactory();
        var original=factory.build(SamlErrorProbeRequestFactory.Probe.STRING_TAB_LITERAL_255,"_id",
                java.net.URI.create("https://idp.example"),"issuer",java.net.URI.create("https://suite.example"),java.time.Instant.EPOCH);
        var changed=SecureXml.parse(original);changed.getDocumentElement().setAttribute("ProviderName","changed");
        assertThrows(SamlException.class,()->ProviderNameWireFormat.preserve(original,SecureXml.serialize(changed)));
        var reference=factory.build(SamlErrorProbeRequestFactory.Probe.STRING_TAB_REFERENCE_255,"_id",
                java.net.URI.create("https://idp.example"),"issuer",java.net.URI.create("https://suite.example"),java.time.Instant.EPOCH);
        var serialized=SecureXml.serialize(SecureXml.parse(reference));
        assertArrayEquals(serialized,ProviderNameWireFormat.preserve(reference,serialized));
    }
}
