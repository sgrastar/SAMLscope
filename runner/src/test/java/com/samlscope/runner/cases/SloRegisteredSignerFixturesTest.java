package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.saml.normal.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SloRegisteredSignerFixturesTest {
    @TempDir Path directory;
    private static final Instant NOW=Instant.parse("2026-10-03T13:00:00Z");
    @Test void onlyCryptographicSignerChangesWhileKnownIssuerAndSessionStayFixed(){
        var store=new FilePlanKeyStore(directory,Clock.fixed(NOW,ZoneOffset.UTC));var own=store.getOrCreate("plan_00000000000000000000000000");var other=store.getOrCreate("plan_11111111111111111111111111");
        var input=new SloRegisteredSignerProbeInputs("run_00000000000000000000000000","run_11111111111111111111111111","https://suite.example/p/plan_00000000000000000000000000",
                URI.create("https://idp.example/slo"),URI.create("https://suite.example/slo"),"<saml:NameID xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>session-user</saml:NameID>".getBytes(StandardCharsets.UTF_8),List.of("authenticated-session"),"a".repeat(64));
        var verifier=new XmlSignatureVerifier();for(var fixture:SloRegisteredSignerComparison.FIXTURES){
            var raw=SloRegisteredSignerFixtures.build(fixture,"_same",NOW,input,own,other);assertArrayEquals(raw,SloRegisteredSignerFixtures.build(fixture,"_same",NOW,input,own,other));
            var root=SecureXml.parse(raw).getDocumentElement();assertTrue(SamlSchemaValidation.isValid(root,SamlSchemaValidation.SchemaKind.PROTOCOL));
            assertEquals(input.entity(),SloRegisteredSignerEvidence.issuer(root));assertEquals("authenticated-session",root.getElementsByTagNameNS(SloRegisteredSignerEvidence.P,"SessionIndex").item(0).getTextContent());
            assertEquals("session-user",root.getElementsByTagNameNS(SloRegisteredSignerEvidence.S,"NameID").item(0).getTextContent());
            assertEquals(fixture.equals("local-normal"),verifier.hasValidEnvelopedSignature(root,own.certificate()));assertEquals(fixture.equals("local-other-signer"),verifier.hasValidEnvelopedSignature(root,other.certificate()));
        }
        assertEquals("local-normal",SloRegisteredSignerComparison.FIXTURES.getLast());
    }
    @Test void malformedNativeSessionInputsFailBeforePreparingOutboundAction(){
        assertThrows(IllegalArgumentException.class,()->new SloRegisteredSignerProbeInputs("run_00000000000000000000000000","run_00000000000000000000000000","entity",URI.create("https://idp.example/slo"),URI.create("https://suite.example/slo"),new byte[]{1},List.of("session"),"a".repeat(64)));
    }
}
