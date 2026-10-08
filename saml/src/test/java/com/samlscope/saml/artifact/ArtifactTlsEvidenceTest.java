package com.samlscope.saml.artifact;

import static org.junit.jupiter.api.Assertions.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.saml.crypto.*;

class ArtifactTlsEvidenceTest {
    @TempDir Path folder;
    PlanCredentials suite,foreign;Map<String,Object> facts;
    static final URI ENDPOINT=URI.create("https://idp.example/resolve");
    final byte[] request="original-request".getBytes(StandardCharsets.UTF_8),response="original-response".getBytes(StandardCharsets.UTF_8);
    @BeforeEach void setup(){var store=new FilePlanKeyStore(folder,Clock.systemUTC());suite=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS");foreign=store.getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS","foreign");facts=new LinkedHashMap<>(Map.of("source",ArtifactTlsEvidence.SOURCE,"run_id","run-owned","action_id","action-owned","endpoint_sha256",hash(ENDPOINT.toASCIIString().getBytes(StandardCharsets.UTF_8)),"request_reference","tx-request","response_reference","tx-response","request_sha256",hash(request),"response_sha256",hash(response),"protocol","TLSv1.3","cipher_suite","TLS_AES_128_GCM_SHA256"));facts.put("peer_certificate_sha256",List.of("a".repeat(64)));}
    Optional<ArtifactTlsEvidence> verify(Map<String,Object> receipt){return ArtifactTlsEvidence.verify(receipt,"run-owned","action-owned",ENDPOINT,"tx-request","tx-response",request,response,suite.certificate());}
    @Test void signedCaptureIsBoundAndDeeplyImmutable(){var value=ArtifactTlsEvidence.sign(facts,suite);var proof=verify(value).orElseThrow();assertTrue(proof.coversResponse(response));assertFalse(proof.coversResponse(request));assertThrows(UnsupportedOperationException.class,()->proof.receipt().put("facts",Map.of()));var exposed=(Map<?,?>)proof.receipt().get("facts");assertThrows(UnsupportedOperationException.class,()->((List<?>)exposed.get("peer_certificate_sha256")).clear());}
    @Test void nakedTlsFlagAndUnsignedOrForeignSignedStatementsAreNotEvidence(){assertTrue(verify(Map.of("authenticated",true)).isEmpty());assertTrue(verify(ArtifactTlsEvidence.sign(facts,foreign)).isEmpty());var signed=new LinkedHashMap<>(ArtifactTlsEvidence.sign(facts,suite));signed.remove("signature_value");assertTrue(verify(signed).isEmpty());}
    @Test void changedRunActionEndpointReferencesOrBodyBreaksTheSignatureOrBinding(){var original=ArtifactTlsEvidence.sign(facts,suite);for(String field:List.of("run_id","action_id","endpoint_sha256","request_reference","response_reference","request_sha256","response_sha256","source")){var changed=new LinkedHashMap<>(facts);changed.put(field,"wrong");var tampered=new LinkedHashMap<>(original);tampered.put("facts",changed);assertTrue(verify(tampered).isEmpty(),field);if(!field.equals("source"))assertTrue(verify(ArtifactTlsEvidence.sign(changed,suite)).isEmpty(),field+" re-signed binding");}}
    @Test void nullAnonymousAndUnidentifiedTlsSessionsCannotBeSigned(){for(String cipher:List.of("SSL_NULL_WITH_NULL_NULL","TLS_DH_anon_WITH_AES_128_CBC_SHA")){facts.put("cipher_suite",cipher);assertThrows(IllegalArgumentException.class,()->ArtifactTlsEvidence.sign(facts,suite));}facts.put("cipher_suite","TLS_AES_128_GCM_SHA256");facts.put("peer_certificate_sha256",List.of());assertThrows(IllegalArgumentException.class,()->ArtifactTlsEvidence.sign(facts,suite));}
    static String hash(byte[] bytes){return SamlArtifact.hash("SHA-256",bytes);}
}
