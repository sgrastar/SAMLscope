package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.saml.normal.SecureXml;

class AutoConfigurationTranscriptEvidenceTestCaseTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-09-14T00:00:00Z");
    @Test void lateCorrelatedEncryptedAssertionCompletesWithoutAnotherConfigurationAnswer() throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var keys = generator.generateKeyPair();
        var xml = encryptedResponse(keys.getPublic());
        var history = new History();
        var test = testCase(xml, keys.getPrivate());
        var context = context(history, true);
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context));
        assertFalse(test.evidenceStatus(context).ready());
        history.entries.add(entry(xml, false));
        assertFalse(test.evidenceStatus(context).ready(), "unvalidated or uncorrelated inbound data cannot satisfy a case");
        history.entries.clear(); history.entries.add(entry(xml, true));
        assertTrue(test.evidenceStatus(context).ready());
        var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context, waiting.next(), new CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.SATISFIED, finish.outcome().outcome());
        assertEquals("configuration.passive.assertion-encryption-capability", finish.outcome().reasonCode());
        assertEquals(List.of(new EvidenceRef("transcript", "transcript:tx")), finish.outcome().evidence());
        assertFalse(finish.outcome().details().toString().contains("test-user"), "decrypted identifiers must not be persisted");
        assertFalse(test.evidenceStatus(context(history, false)).ready(), "truncated history is not conclusive");
        assertFalse(testCase(xml, generator.generateKeyPair().getPrivate()).evidenceStatus(context).ready());
        assertFalse(testCase(xml, null).evidenceStatus(context).ready());
    }
    @Test void confirmingSetupWithoutProtocolEvidenceDoesNotAskForAVerdict() {
        var test = testCase(new byte[0], null);
        var context = context(new History(), true);
        var waiting = assertInstanceOf(CaseStep.AwaitConfig.class, test.start(context));
        var finish = assertInstanceOf(CaseStep.Finish.class, test.resume(context, waiting.next(), new CaseEvent.ConfigConfirmed()));
        assertEquals(Outcome.NOT_VERIFIED, finish.outcome().outcome());
        assertEquals("configuration.transcript-incomplete", finish.outcome().reasonCode());
    }
    @Test void configurationEvidenceFaultsNeverEscapeOrBorrowAnotherRunsSuccessfulResponse() throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        var keys = generator.generateKeyPair(); var good = encryptedResponse(keys.getPublic());
        for (var caseId : List.of("IIP-IDP09-a-idp-01", "IIP-SSO01-ez-idp-01", "IIP-SSO01-fd-idp-01", "IIP-SSO01-fe-idp-01"))
        for (var fault : List.of("history", "truncated", "run", "duplicate", "missing-ref", "zero-size", "null-content",
                "empty-content", "size", "read", "key", "xml", "type", "namespace")) {
            var history = new History(); history.unavailable = fault.equals("history");
            byte[] body = switch (fault) {
                case "null-content" -> null;
                case "empty-content" -> new byte[0];
                case "xml" -> "not XML".getBytes(StandardCharsets.UTF_8);
                case "type" -> "<p:LogoutResponse xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol'/>".getBytes(StandardCharsets.UTF_8);
                case "namespace" -> "<Response xmlns='urn:foreign'/>".getBytes(StandardCharsets.UTF_8);
                default -> good;
            };
            var accepted = entry(good, true);
            history.entries.add(new TranscriptEntry(accepted.id(), fault.equals("run")?"other-run":RUN,
                    accepted.direction(), NOW, accepted.correlationId(), accepted.method(), accepted.url(), 200,
                    Map.of(), null, 0, fault.equals("missing-ref")?null:"decoded",
                    fault.equals("zero-size")?0:fault.equals("size")?good.length+1:body==null||body.length==0?good.length:body.length,
                    null, null, accepted.samlSummary()));
            if (fault.equals("duplicate")) history.entries.add(history.entries.getFirst());
            var evidence = new AttestedOutcomeTestCase(caseId, TargetRole.IDP, "encryption", "Review evidence",
                    Duration.ofDays(1), List.of(AttestationOption.notVerified("unknown", "unknown", "unknown")));
            var fallback = new ConfigurationGateTestCase(evidence, "encryption", "Enable encryption", Duration.ofDays(1),
                    ConfigurationFailureSemantics.TEST_PRECONDITION);
            var test = new AutoConfigurationTranscriptEvidenceTestCase(fallback,
                    ignored -> { if (fault.equals("read")) throw new IllegalStateException("private path and credential"); return body; },
                    ignored -> { if (fault.equals("key")) throw new IllegalStateException("secret key error"); return Optional.of(keys.getPrivate()); });
            var context = context(history, !fault.equals("truncated"));
            var result = assertInstanceOf(CaseStep.Finish.class, test.start(context)).outcome();
            assertEquals(Outcome.NOT_VERIFIED, result.outcome(), caseId+"/"+fault);
            assertFalse(result.details().toString().contains("private"));
            assertFalse(result.details().toString().contains("secret"));
            assertTrue(result.evidence().isEmpty());
            assertFalse(test.evidenceStatus(context).ready());
            assertEquals(result.details().get("evidence_issues"), test.evidenceStatus(context).details().get("evidence_issues"));
        }
    }

    private static AutoConfigurationTranscriptEvidenceTestCase testCase(byte[] xml, java.security.PrivateKey key) {
        var evidence = new AttestedOutcomeTestCase("IIP-IDP09-a-idp-01", TargetRole.IDP, "encryption", "Review evidence",
                Duration.ofDays(1), List.of(AttestationOption.notVerified("unknown", "unknown", "unknown")));
        var fallback = new ConfigurationGateTestCase(evidence, "encryption", "Enable encryption", Duration.ofDays(1),
                ConfigurationFailureSemantics.TEST_PRECONDITION);
        return new AutoConfigurationTranscriptEvidenceTestCase(fallback, ignored -> xml, ignored -> Optional.ofNullable(key));
    }
    private static CaseContext context(History history, boolean complete) {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.fixed(NOW, ZoneOffset.UTC),
                new TestPlan.Parameters(180,300,""), new TestPlan.Interaction(true,false), Reachability.CONFIRMED, history, complete);
    }
    private static TranscriptEntry entry(byte[] xml, boolean correlated) {
        return new TranscriptEntry("tx", RUN, Direction.INBOUND, NOW, "request", "POST", "https://suite.example/acs", 200,
                Map.of(), null, 0, "decoded", xml.length, "application/x-www-form-urlencoded", null,
                Map.of("type", "Response", "normalFlowAccepted", correlated));
    }
    private static byte[] encryptedResponse(java.security.PublicKey key) throws Exception {
        var generator = javax.crypto.KeyGenerator.getInstance("AES"); generator.init(128);
        var dataKey = generator.generateKey();
        var iv = new byte[12]; new java.security.SecureRandom().nextBytes(iv);
        var aes = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(javax.crypto.Cipher.ENCRYPT_MODE, dataKey, new javax.crypto.spec.GCMParameterSpec(128, iv));
        var encrypted = aes.doFinal(("<saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' ID='_assertion'>"
                + "<saml:Subject><saml:NameID>test-user</saml:NameID></saml:Subject></saml:Assertion>").getBytes(StandardCharsets.UTF_8));
        var data = java.nio.ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array();
        var rsa = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.OAEPParameterSpec(
                "SHA-1", "MGF1", java.security.spec.MGF1ParameterSpec.SHA1, javax.crypto.spec.PSource.PSpecified.DEFAULT));
        var wrapped = rsa.doFinal(dataKey.getEncoded());
        return ("<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>"
                + "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></samlp:Status>"
                + "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Type='http://www.w3.org/2001/04/xmlenc#Element'>"
                + "<xenc:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#aes128-gcm'/>"
                + "<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'><xenc:EncryptedKey>"
                + "<xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'/>"
                + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(wrapped)
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
                + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(data)
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>")
                .getBytes(StandardCharsets.UTF_8);
    }
    private static final class History implements TranscriptRecorder {
        final List<TranscriptEntry> entries = new ArrayList<>();
        boolean unavailable;
        public List<TranscriptEntry> list(String run) { if (unavailable) throw new IllegalStateException("private history"); return List.copyOf(entries); }
        public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
        public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary) { throw new UnsupportedOperationException(); }
    }
}
