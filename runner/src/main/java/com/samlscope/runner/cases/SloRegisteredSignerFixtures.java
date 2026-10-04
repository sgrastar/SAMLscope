package com.samlscope.runner.cases;

import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlLogoutRequestFactory;
import com.samlscope.saml.normal.SecureXml;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/** Exact outbox fixtures: only the signature key/value varies, never Issuer or session. */
final class SloRegisteredSignerFixtures {
    static byte[] build(String fixture, String requestId, Instant issueInstant,
            SloRegisteredSignerProbeInputs input, PlanCredentials own, PlanCredentials other) {
        if (!SloRegisteredSignerComparison.FIXTURES.contains(fixture)) throw new IllegalArgumentException("Unknown SLO signer fixture");
        var factory = new SamlLogoutRequestFactory();
        var name = SecureXml.parse(input.nameIdXml()).getDocumentElement();
        var bytes = factory.sign(factory.build(requestId,input.destination(),input.entity(),name,
                input.sessionIndexes(),issueInstant,null,false),
                "local-other-signer".equals(fixture)?other:own);
        if (!"local-invalid-signature".equals(fixture)) return bytes;
        var document = SecureXml.parse(bytes);
        var signatures = document.getDocumentElement().getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue");
        if (signatures.getLength()!=1) throw new IllegalArgumentException("Unambiguous signature required");
        var value=Base64.getMimeDecoder().decode(signatures.item(0).getTextContent());
        if(value.length==0)throw new IllegalArgumentException("Empty signature");
        value=Arrays.copyOf(value,value.length);value[0]^=1;
        signatures.item(0).setTextContent(Base64.getEncoder().encodeToString(value));
        return SecureXml.serialize(document);
    }
    private SloRegisteredSignerFixtures() { }
}
