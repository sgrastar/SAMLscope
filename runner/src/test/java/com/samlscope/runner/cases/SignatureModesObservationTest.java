package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Element;
import com.samlscope.core.evaluation.*;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class SignatureModesObservationTest {
    @TempDir java.nio.file.Path directory;
    private static final String S = "urn:oasis:names:tc:SAML:2.0:assertion";
    private PlanCredentials key() { return new FilePlanKeyStore(directory, Clock.systemUTC()).getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS"); }
    private Element response(String mode, boolean brokenAssertion) {
        var doc = SecureXml.parse("""
            <p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">
              <s:Issuer>target</s:Issuer><p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></p:Status>
              <s:Assertion ID="_a"><s:Issuer>target</s:Issuer><s:Subject><s:NameID>test</s:NameID>
                <s:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                  <s:SubjectConfirmationData InResponseTo="_request" Recipient="https://suite.example/acs"/>
                </s:SubjectConfirmation></s:Subject>
                <s:Conditions><s:AudienceRestriction><s:Audience>peer</s:Audience></s:AudienceRestriction></s:Conditions>
              </s:Assertion>
            </p:Response>
            """.getBytes(StandardCharsets.UTF_8));
        var root = doc.getDocumentElement();
        var assertion = (Element) root.getElementsByTagNameNS(S,"Assertion").item(0);
        if (!mode.equals("response-only") && !mode.equals("unsigned")) {
            new XmlSigner().sign(assertion, key(), (Element) assertion.getElementsByTagNameNS(S,"Issuer").item(0));
            if (brokenAssertion) assertion.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","SignatureValue").item(0).setTextContent("AAAA");
        }
        if (!mode.equals("assertion-only") && !mode.equals("unsigned"))
            new XmlSigner().sign(root, key(), (Element) root.getElementsByTagNameNS(S,"Issuer").item(0));
        return root;
    }
    private SignatureModesObservation.Sample inspect(Element response) {
        return SignatureModesObservation.inspect(response, "target", "peer", "_request", "https://suite.example/acs",
                List.of(key().certificate()), ignored -> Optional.empty(), "run", List.of(new EvidenceRef("transcript","original")));
    }
    @Test void allIndependentlyVerifiedConfigurationsAreRequired() {
        var samples = SignatureModesObservation.REQUIRED.stream().map(mode -> inspect(response(mode,false))).toList();
        assertEquals(SignatureModesObservation.REQUIRED, samples.stream().map(SignatureModesObservation.Sample::mode).toList());
        assertEquals(Outcome.SATISFIED, SignatureModesObservation.evaluate(samples,List.of()).outcome());
        for (var omitted : SignatureModesObservation.REQUIRED)
            assertEquals(Outcome.NOT_VERIFIED, SignatureModesObservation.evaluate(samples.stream().filter(s -> !s.mode().equals(omitted)).toList(),List.of()).outcome());
    }
    @Test void alwaysBothMutantDoesNotProveIndependentSigning() {
        var sample = inspect(response("both",false));
        assertEquals(Outcome.NOT_VERIFIED, SignatureModesObservation.evaluate(List.of(sample,sample,sample),List.of()).outcome());
    }
    @Test void authenticOuterSignatureDoesNotHideInvalidInnerSignature() {
        assertThrows(IllegalArgumentException.class, () -> inspect(response("both",true)));
        assertThrows(IllegalArgumentException.class, () -> inspect(response("assertion-only",true)));
        assertThrows(IllegalArgumentException.class, () -> inspect(response("unsigned",false)));
    }
    @Test void signedAssertionMustBindRequestAndAudience() {
        var root = response("assertion-only",false);
        assertThrows(IllegalArgumentException.class, () -> SignatureModesObservation.inspect(root,"target","wrong-peer","_request",
                "https://suite.example/acs",List.of(key().certificate()),ignored -> Optional.empty(),"run",List.of()));
        assertThrows(IllegalArgumentException.class, () -> SignatureModesObservation.inspect(root,"target","peer","_other-request",
                "https://suite.example/acs",List.of(key().certificate()),ignored -> Optional.empty(),"run",List.of()));
    }
    @Test void differentPeersCannotSupplyDifferentMissingModes() {
        var samples = new ArrayList<>(SignatureModesObservation.REQUIRED.stream().map(mode -> inspect(response(mode,false))).toList());
        var first=samples.getFirst(); samples.set(0,new SignatureModesObservation.Sample(first.mode(),first.issuer(),"other-peer",first.evidence()));
        assertEquals(Outcome.NOT_VERIFIED, SignatureModesObservation.evaluate(samples,List.of()).outcome());
    }
}
