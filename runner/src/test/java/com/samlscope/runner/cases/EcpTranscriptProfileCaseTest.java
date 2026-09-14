package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

class EcpTranscriptProfileCaseTest {
    @Test
    void basicExchangeRequiresAnObservedRequestAndSoapCompletion() {
        assertEquals(Outcome.NOT_VERIFIED, fixture(request()).evaluate(
                EcpTranscriptProfileCase.Rule.BASIC_EXCHANGE));
        assertEquals(Outcome.SATISFIED, fixture(request(), response(true, true, true)).evaluate(
                EcpTranscriptProfileCase.Rule.BASIC_EXCHANGE));
    }

    @Test
    void responseHeaderAndBearerRecipientAreBoundToTheRequestedPaosConsumer() {
        var valid = fixture(request(), response(true, true, true));
        assertEquals(Outcome.SATISFIED, valid.evaluate(EcpTranscriptProfileCase.Rule.RESPONSE_HEADER));
        assertEquals(Outcome.SATISFIED, valid.evaluate(EcpTranscriptProfileCase.Rule.BEARER_CONFIRMATION));
        var invalid = fixture(request(), response(false, true, true));
        assertEquals(Outcome.VIOLATED, invalid.evaluate(EcpTranscriptProfileCase.Rule.RESPONSE_HEADER));
        assertEquals(Outcome.VIOLATED, invalid.evaluate(EcpTranscriptProfileCase.Rule.BEARER_CONFIRMATION));
    }

    @Test
    void channelBindingsExerciseAllFiveRequiredScenarios() {
        assertEquals(Outcome.SATISFIED, fixture(channelBindingScenario(true)).evaluate(
                EcpTranscriptProfileCase.Rule.CHANNEL_BINDINGS));
        assertEquals(Outcome.VIOLATED, fixture(channelBindingScenario(false)).evaluate(
                EcpTranscriptProfileCase.Rule.CHANNEL_BINDINGS));
    }

    private Soap[] channelBindingScenario(boolean includeAdviceCopy) {
        return new Soap[] {
                channelRequest("matched-signed-request", "match", "match", true),
                channelResponse("matched-signed-response", "matched-signed", true, true, includeAdviceCopy),
                channelRequest("matched-unsigned-request", "match", "match", false),
                channelResponse("matched-unsigned-response", "matched-unsigned", false, false, false),
                channelRequest("mismatch-request", "request", "header", true),
                channelResponse("mismatch-response", "mismatch", false, false, false),
                channelRequest("request-only-request", "request", null, true),
                channelResponse("request-only-response", "request-only", false, false, false),
                channelRequest("header-only-request", null, "header", false),
                channelResponse("header-only-response", "header-only", false, false, false)
        };
    }

    private Soap channelRequest(String id, String extensionValue, String headerValue, boolean signed) {
        var correlation = id.replace("-request", "");
        var header = headerValue == null ? "" : "<cb:ChannelBindings Type=\"tls-server-end-point\">"
                + headerValue + "</cb:ChannelBindings>";
        var extension = extensionValue == null ? "" : "<samlp:Extensions><cb:ChannelBindings "
                + "Type=\"tls-server-end-point\">" + extensionValue + "</cb:ChannelBindings></samlp:Extensions>";
        var signature = signed ? "<ds:Signature/>" : "";
        return new Soap(id, correlation, Direction.OUTBOUND, """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:cb="urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
                  xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <S:Header>%s</S:Header>
                  <S:Body><samlp:AuthnRequest>%s%s</samlp:AuthnRequest></S:Body>
                </S:Envelope>
                """.formatted(header, signature, extension), Map.of());
    }

    private Soap channelResponse(String id, String correlation, boolean success,
                                 boolean headerCopy, boolean adviceCopy) {
        var header = headerCopy ? "<cb:ChannelBindings Type=\"tls-server-end-point\">match</cb:ChannelBindings>" : "";
        var advice = adviceCopy ? "<saml:Assertion><saml:Advice><cb:ChannelBindings "
                + "Type=\"tls-server-end-point\">match</cb:ChannelBindings></saml:Advice></saml:Assertion>" : "";
        var status = success ? "urn:oasis:names:tc:SAML:2.0:status:Success"
                : "urn:oasis:names:tc:SAML:2.0:status:Responder";
        return new Soap(id, correlation, Direction.INBOUND, """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  xmlns:cb="urn:oasis:names:tc:SAML:protocol:ext:channel-binding">
                  <S:Header>%s</S:Header>
                  <S:Body><samlp:Response><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>%s</samlp:Response></S:Body>
                </S:Envelope>
                """.formatted(header, status, advice), Map.of());
    }

    @Test
    void samlEcRequiresBothCopiesSufficientKeyMaterialAndEncryptedAssertion() {
        assertEquals(Outcome.SATISFIED, fixture(samlEcRequest(), response(true, true, true)).evaluate(
                EcpTranscriptProfileCase.Rule.GENERATED_KEY));
        assertEquals(Outcome.VIOLATED, fixture(samlEcRequest(), response(true, true, false)).evaluate(
                EcpTranscriptProfileCase.Rule.GENERATED_KEY));
    }

    @Test
    void missingSamlEcResponseIsNotAProductViolation() {
        assertEquals(Outcome.NOT_VERIFIED, fixture(samlEcRequest()).evaluate(
                EcpTranscriptProfileCase.Rule.GENERATED_KEY));
    }

    private Fixture fixture(Soap... values) { return new Fixture(List.of(values)); }

    private Soap request() {
        return new Soap("request", "corr", Direction.OUTBOUND, """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:paos="urn:liberty:paos:2003-08"
                    xmlns:cb="urn:oasis:names:tc:SAML:protocol:ext:channel-binding">
                  <S:Header>
                    <paos:Request responseConsumerURL="https://suite.example/paos"/>
                    <cb:ChannelBindings>binding</cb:ChannelBindings>
                  </S:Header>
                  <S:Body><request/></S:Body>
                </S:Envelope>
                """, Map.of("Authorization", List.of("<redacted: Basic, 20 bytes>")));
    }

    private Soap samlEcRequest() {
        return new Soap("saml-ec-request", "corr", Direction.OUTBOUND, """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:samlec="urn:ietf:params:xml:ns:samlec">
                  <S:Header><samlec:SessionKey S:actor="http://schemas.xmlsoap.org/soap/actor/next"
                    S:mustUnderstand="1"><samlec:EncType>17</samlec:EncType></samlec:SessionKey></S:Header>
                  <S:Body><request/></S:Body>
                </S:Envelope>
                """, Map.of("Authorization", List.of("<redacted: Basic, 20 bytes>")));
    }

    private Soap response(boolean correctRecipient, boolean headerBinding, boolean encrypted) {
        var recipient = correctRecipient ? "https://suite.example/paos" : "https://other.example/paos";
        var headerCb = headerBinding
                ? "<cb:ChannelBindings S:actor=\"http://schemas.xmlsoap.org/soap/actor/next\" S:mustUnderstand=\"1\">binding</cb:ChannelBindings>"
                : "";
        var assertion = encrypted
                ? "<saml:EncryptedAssertion/><saml:Assertion ID=\"_a\"><saml:Advice><cb:ChannelBindings>binding</cb:ChannelBindings><samlec:GeneratedKey>AAECAwQFBgcICQoLDA0ODw==</samlec:GeneratedKey></saml:Advice><saml:Subject><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"" + recipient + "\"/></saml:SubjectConfirmation></saml:Subject></saml:Assertion>"
                : "<saml:Assertion><saml:Advice><samlec:GeneratedKey>AA==</samlec:GeneratedKey></saml:Advice></saml:Assertion>";
        return new Soap("response", "corr", Direction.INBOUND, """
                <S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:ecp="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp"
                    xmlns:cb="urn:oasis:names:tc:SAML:protocol:ext:channel-binding"
                    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    xmlns:samlec="urn:ietf:params:xml:ns:samlec">
                  <S:Header>
                    <ecp:Response AssertionConsumerServiceURL="%s" S:actor="http://schemas.xmlsoap.org/soap/actor/next" S:mustUnderstand="1"/>
                    %s
                    <samlec:GeneratedKey>AAECAwQFBgcICQoLDA0ODw==</samlec:GeneratedKey>
                  </S:Header>
                  <S:Body><samlp:Response>%s</samlp:Response></S:Body>
                </S:Envelope>
                """.formatted(recipient, headerCb, assertion), Map.of());
    }

    private record Soap(String id, String correlation, Direction direction, String xml,
                        Map<String, List<String>> headers) {}

    private static final class Fixture {
        private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
        private final List<TranscriptEntry> entries;
        private final Map<String, byte[]> content;

        private Fixture(List<Soap> values) {
            var rows = new java.util.ArrayList<TranscriptEntry>();
            var blobs = new HashMap<String, byte[]>();
            var sequence = 0;
            for (var value : values) {
                var reference = "decoded-" + value.id();
                var bytes = value.xml().getBytes(StandardCharsets.UTF_8);
                rows.add(new TranscriptEntry(
                        value.id(), RUN, value.direction(), Instant.parse("2026-08-29T00:00:00Z").plusSeconds(sequence++),
                        value.correlation(), "POST", "https://idp.example/ecp", 200, value.headers(), null, 0,
                        reference, bytes.length, "application/soap+xml", null, Map.of()));
                blobs.put(reference, bytes);
            }
            entries = List.copyOf(rows); content = Map.copyOf(blobs);
        }

        private Outcome evaluate(EcpTranscriptProfileCase.Rule rule) {
            TranscriptRecorder recorder = new TranscriptRecorder() {
                @Override public TranscriptEntry record(TranscriptInput input) { throw new UnsupportedOperationException(); }
                @Override public TranscriptEntry updateSamlAnalysis(
                        String entryId, String correlationId, Map<String, Object> samlSummary) {
                    throw new UnsupportedOperationException();
                }
                @Override public List<TranscriptEntry> list(String runId) { return entries; }
            };
            TranscriptContentReader reader = entry -> content.get(entry.decodedSamlRef());
            if (rule == EcpTranscriptProfileCase.Rule.GENERATED_KEY) {
                java.security.PrivateKey key = new java.security.PrivateKey() {
                    @Override public String getAlgorithm() { return "fixture"; }
                    @Override public String getFormat() { return "fixture"; }
                    @Override public byte[] getEncoded() { return new byte[0]; }
                };
                com.samlscope.saml.crypto.SamlElementDecrypter decrypter = (wrapper, ignored) ->
                        com.samlscope.saml.normal.SecureXml.parse("""
                            <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                              xmlns:samlec="urn:ietf:params:xml:ns:samlec">
                              <saml:Advice><samlec:GeneratedKey>AAECAwQFBgcICQoLDA0ODw==</samlec:GeneratedKey></saml:Advice>
                            </saml:Assertion>
                            """.getBytes(StandardCharsets.UTF_8)).getDocumentElement();
                return new EcpTranscriptProfileCase(rule, List.of(), key, decrypter)
                        .evaluate(RUN, recorder, reader).outcome();
            }
            return new EcpTranscriptProfileCase(rule, List.of()).evaluate(RUN, recorder, reader).outcome();
        }
    }
}
