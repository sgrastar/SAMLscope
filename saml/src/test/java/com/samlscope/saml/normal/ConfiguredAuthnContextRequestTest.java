package com.samlscope.saml.normal;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

class ConfiguredAuthnContextRequestTest {
    @Test void preservesCandidateOrderForEveryComparisonAndReferenceKind() {
        var factory=new SamlRequestedAuthnContextRequestFactory();
        for(var comparison:Comparison.values()) for(var kind:ReferenceKind.values()) {
            for(var order:List.of(List.of("urn:target:low","urn:target:high"),List.of("urn:target:high","urn:target:low"))) {
                var request=SecureXml.parse(factory.buildConfiguredContext(new ContextRequest(comparison,kind,order),
                    "_fixed",URI.create("https://idp.example/sso"),"https://sp.example",URI.create("https://sp.example/acs"),Instant.EPOCH));
                var contexts=request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:protocol","RequestedAuthnContext");
                assertEquals(1,contexts.getLength());
                assertEquals(comparison.name().toLowerCase(Locale.ROOT),((org.w3c.dom.Element)contexts.item(0)).getAttribute("Comparison"));
                var references=request.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion",
                    kind==ReferenceKind.CLASS?"AuthnContextClassRef":"AuthnContextDeclRef");
                assertEquals(2,references.getLength());
                assertEquals(order.get(0),references.item(0).getTextContent());assertEquals(order.get(1),references.item(1).getTextContent());
            }
        }
    }
    @Test void rejectsAmbiguousFixtureInputsBeforeTransmission() {
        for(var invalid:List.of(List.<String>of(),List.of(""),List.of("urn:a","urn:a"))) {
            assertThrows(IllegalArgumentException.class,()->new ContextRequest(Comparison.MINIMUM,ReferenceKind.CLASS,invalid));
        }
    }
}
