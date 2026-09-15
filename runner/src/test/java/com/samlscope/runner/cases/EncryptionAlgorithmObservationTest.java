package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.crypto.*;
import com.samlscope.saml.normal.SecureXml;

class EncryptionAlgorithmObservationTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-09-15T00:00:00Z");
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final KeyPair SUITE_KEY = suiteKey();

    private static KeyPair suiteKey() {
        try { return keyPair(); } catch (Exception failure) { throw new IllegalStateException(failure); }
    }

    @Test
    void extractsInlineEncryptionParametersFromAGeneratedAssertion() throws Exception {
        var suite = keyPair();
        for (var algorithms : SamlEncryptionFixtureFactory.matrix()) {
            var wrapper = encrypt(suite, algorithms);
            var observation = EncryptionAlgorithmObservation.inspect(
                    new EvidenceRef("transcript", "request"), new EvidenceRef("transcript", "response"),
                    wrapper, true);
            assertEquals(algorithms.content().uri(), observation.contentAlgorithm(), algorithms.id());
            assertEquals(algorithms.transport().uri(), observation.transportAlgorithm(), algorithms.id());
            assertEquals(algorithms.digest() == SamlEncryptionFixtureFactory.Digest.DEFAULT
                    ? null : algorithms.digest().uri(), observation.digestAlgorithm(), algorithms.id());
            assertEquals(algorithms.mgf() == SamlEncryptionFixtureFactory.Mgf.DEFAULT
                    ? null : algorithms.mgf().uri(), observation.mgfAlgorithm(), algorithms.id());
        }
    }

    @Test
    void satisfiedOnlyForTheRequiredAlgorithmAcrossTheCoveredVariants() throws Exception {
        var suite = keyPair();
        // RSA_OAEP is rsa-oaep-mgf1p and RSA_OAEP_11 is the XML Encryption 1.1 rsa-oaep URI.
        var aes256Oaep = observation(suite, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES256_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,
                SamlEncryptionFixtureFactory.Digest.DEFAULT, SamlEncryptionFixtureFactory.Mgf.DEFAULT), true);
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG04-b-idp-01", List.of(aes256Oaep)).isPresent());
        assertEquals(Outcome.SATISFIED,
                EncryptionAlgorithmObservation.evaluate("IIP-ALG04-b-idp-01", List.of(aes256Oaep)).orElseThrow().outcome());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG04-a-idp-01", List.of(aes256Oaep)).isEmpty());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-b-idp-01", List.of(aes256Oaep)).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-d-idp-01", List.of(aes256Oaep)).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-a-idp-01", List.of(aes256Oaep)).isEmpty());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-c-idp-01", List.of(aes256Oaep)).isEmpty());

        var aes128Mgf1p = observation(suite, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES128_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                SamlEncryptionFixtureFactory.Digest.SHA256, SamlEncryptionFixtureFactory.Mgf.DEFAULT), true);
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG04-a-idp-01", List.of(aes128Mgf1p)).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-a-idp-01", List.of(aes128Mgf1p)).isPresent());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-b-idp-01", List.of(aes128Mgf1p)).isEmpty());
        // The default-MGF variant applies to the XML Encryption 1.1 rsa-oaep URI only.
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-d-idp-01", List.of(aes128Mgf1p)).isEmpty());
        var explicitOtherMgf = observation(suite, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES128_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11,
                SamlEncryptionFixtureFactory.Digest.SHA256, SamlEncryptionFixtureFactory.Mgf.SHA256), true);
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-d-idp-01", List.of(explicitOtherMgf)).isEmpty());
    }

    @Test
    void allFourDigestAndTransportCombinationsAreRequired() throws Exception {
        var suite = keyPair();
        var combos = List.of(
                combo(suite, SamlEncryptionFixtureFactory.Transport.RSA_OAEP, SamlEncryptionFixtureFactory.Digest.DEFAULT),
                combo(suite, SamlEncryptionFixtureFactory.Transport.RSA_OAEP, SamlEncryptionFixtureFactory.Digest.SHA256),
                combo(suite, SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11, SamlEncryptionFixtureFactory.Digest.DEFAULT),
                combo(suite, SamlEncryptionFixtureFactory.Transport.RSA_OAEP_11, SamlEncryptionFixtureFactory.Digest.SHA256));
        var partial = combos.subList(0, 3);
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-c-idp-01", partial).isEmpty());
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG06-c-idp-01", combos).isPresent());
    }

    @Test
    void undecryptedOrWrongKeysNeverProduceAnOutcome() throws Exception {
        // The Suite decrypts with its own run key; a mismatched key leaves the case inconclusive.
        var suite = keyPair();
        var generated = encrypt(suite, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES256_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                SamlEncryptionFixtureFactory.Digest.DEFAULT, SamlEncryptionFixtureFactory.Mgf.DEFAULT));
        var failed = EncryptionAlgorithmObservation.inspect(
                new EvidenceRef("transcript", "request"), new EvidenceRef("transcript", "response"), generated, false);
        assertTrue(EncryptionAlgorithmObservation.evaluate("IIP-ALG04-b-idp-01", List.of(failed)).isEmpty());
        var documents = new HashMap<String, byte[]>();
        documents.put("req", request("_request").getBytes(StandardCharsets.UTF_8));
        documents.put("resp", SecureXml.serialize(ciphertext(generated, "_request")));
        assertInstanceOf(CaseStep.AwaitBrowser.class,
                fixture(documents, "_request", true, false, "normal"));
    }

    @Test
    void correlatedEncryptedBrowserResponseCompletesTheCase() throws Exception {
        var suite = keyPair();
        var generated = SecureXml.serialize(ciphertext(encrypt(SUITE_KEY, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES256_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                SamlEncryptionFixtureFactory.Digest.DEFAULT, SamlEncryptionFixtureFactory.Mgf.DEFAULT)), "_request"));
        var documents = new HashMap<String, byte[]>();
        documents.put("req", request("_request").getBytes(StandardCharsets.UTF_8));
        documents.put("resp", generated);
        var finish = assertInstanceOf(CaseStep.Finish.class,
                fixture(documents, "_request", true, false, "normal"));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals("browser.encryption.aes256-gcm.decrypted", finish.outcome().reasonCode());
        assertEquals(2, finish.outcome().evidence().size());
        assertEquals(List.of("http://www.w3.org/2009/xmlenc11#aes256-gcm"),
                finish.outcome().details().get("encryption_algorithm"));
    }

    @Test
    void ecpProbeResponsesCorrelateByOutboxAction() throws Exception {
        var suite = keyPair();
        var generated = SecureXml.serialize(ciphertext(encrypt(SUITE_KEY, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES256_GCM, SamlEncryptionFixtureFactory.Transport.RSA_OAEP,
                SamlEncryptionFixtureFactory.Digest.DEFAULT, SamlEncryptionFixtureFactory.Mgf.DEFAULT)), "_action_probe"));
        var documents = new HashMap<String, byte[]>();
        documents.put("req", request("_action_probe").getBytes(StandardCharsets.UTF_8));
        documents.put("resp", generated);
        var finish = assertInstanceOf(CaseStep.Finish.class,
                fixture(documents, "_action_probe", true, true, "action_probe"));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
    }

    private CaseStep fixture(
            Map<String, byte[]> documents, String inResponseTo,
            boolean success, boolean active, String correlation) {
        var content = (TranscriptContentReader) entry -> documents.get(entry.decodedSamlRef());
        var entries = new ArrayList<TranscriptEntry>();
        entries.add(entry("req", Direction.OUTBOUND, correlation,
                "AuthnRequest", "req", Map.of("type", active ? "EcpSoapRequest" : "AuthnRequest")));
        entries.add(entry("resp", Direction.INBOUND, active ? "_" + correlation : "correlation",
                "Response", "resp", summary(inResponseTo, success, active)));
        var recorder = new TranscriptRecorder() {
            public List<TranscriptEntry> list(String run) { return List.copyOf(entries); }
            public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
            public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String, Object> summary) { throw new UnsupportedOperationException(); }
        };
        var context = new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED, recorder, true);
        var evidence = new AttestedOutcomeTestCase("IIP-ALG04-b-idp-01", TargetRole.IDP, "evidence", "prompt",
                Duration.ofDays(1), List.of(AttestationOption.notVerified(
                        "unable_to_verify", "browser.evidence-unavailable", "browser_evidence_unavailable")));
        var fallback = new BrowserEvidenceTestCase(evidence, URI.create("https://suite.example"),
                "instructions", Duration.ofMinutes(30));
        var testCase = new EncryptionAlgorithmBrowserEvidenceTestCase(
                fallback, content, ignored -> Optional.of(SUITE_KEY.getPrivate()), new SamlXmlDecrypter());
        return testCase.start(context);
    }

    private static Map<String, Object> summary(String inResponseTo, boolean success, boolean active) {
        var summary = new LinkedHashMap<String, Object>();
        summary.put("type", "Response");
        summary.put("inResponseTo", inResponseTo);
        summary.put("statusCode", success ? "urn:oasis:names:tc:SAML:2.0:status:Success"
                : "urn:oasis:names:tc:SAML:2.0:status:Responder");
        if (active) summary.put("activeProbeAccepted", true);
        else summary.put("normalFlowAccepted", true);
        return summary;
    }

    private static TranscriptEntry entry(String id, Direction direction, String correlation,
            String type, String decodedRef, Map<String, Object> summary) {
        return new TranscriptEntry(id, RUN, direction, NOW, correlation, "POST", "https://suite.example/acs",
                200, Map.of(), null, 0, decodedRef, 1, "text/xml", null, summary);
    }

    private static org.w3c.dom.Document ciphertext(Element encryptedAssertion, String inResponseTo) {
        var document = SecureXml.newDocument();
        var root = document.createElementNS(PROTOCOL, "samlp:Response");
        root.setAttribute("InResponseTo", inResponseTo);
        var status = document.createElementNS(PROTOCOL, "samlp:Status");
        var code = document.createElementNS(PROTOCOL, "samlp:StatusCode");
        code.setAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success");
        status.appendChild(code);
        root.appendChild(status);
        root.appendChild(document.importNode(encryptedAssertion, true));
        document.appendChild(root);
        return document;
    }

    private static Element encrypt(KeyPair suite, SamlEncryptionFixtureFactory.Algorithms algorithms) {
        var assertion = SecureXml.parse(("<saml:Assertion xmlns:saml=\"" + ASSERTION + "\" ID=\"_assertion\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer></saml:Assertion>").getBytes(StandardCharsets.UTF_8))
                .getDocumentElement();
        return new SamlEncryptionFixtureFactory().encrypt(
                SamlEncryptionFixtureFactory.Wrapper.EncryptedAssertion, assertion,
                suite.getPublic(), algorithms);
    }

    private static EncryptionAlgorithmObservation.Observation observation(
            KeyPair suite, SamlEncryptionFixtureFactory.Algorithms algorithms, boolean decrypted) {
        return EncryptionAlgorithmObservation.inspect(
                new EvidenceRef("transcript", "request"), new EvidenceRef("transcript", "response"),
                encrypt(suite, algorithms), decrypted);
    }

    private static EncryptionAlgorithmObservation.Observation combo(
            KeyPair suite, SamlEncryptionFixtureFactory.Transport transport, SamlEncryptionFixtureFactory.Digest digest) {
        return observation(suite, new SamlEncryptionFixtureFactory.Algorithms(
                SamlEncryptionFixtureFactory.Content.AES128_GCM, transport, digest,
                SamlEncryptionFixtureFactory.Mgf.DEFAULT), true);
    }

    private static String request(String id) {
        return "<samlp:AuthnRequest xmlns:samlp=\"" + PROTOCOL + "\" ID=\"" + id + "\" Version=\"2.0\"/>";
    }

    private static KeyPair keyPair() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
