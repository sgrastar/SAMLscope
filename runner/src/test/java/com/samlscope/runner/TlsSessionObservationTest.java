package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.http.*;
import java.util.*;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.Test;

class TlsSessionObservationTest {
    private SSLSession session(String protocol, String cipher) {
        return (SSLSession) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{SSLSession.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getProtocol" -> protocol;
                    case "getCipherSuite" -> cipher;
                    default -> throw new AssertionError("Must not inspect session identifiers/principals: " + method.getName());
                });
    }
    private HttpResponse<Void> response(String url, SSLSession session) {
        return new HttpResponse<>() {
            public URI uri() { return URI.create(url); }
            public Optional<SSLSession> sslSession() { return Optional.ofNullable(session); }
            public int statusCode() { return 200; }
            public Void body() { return null; }
            public HttpRequest request() { throw new AssertionError("Request credentials must not be read"); }
            public Optional<HttpResponse<Void>> previousResponse() { return Optional.empty(); }
            public HttpHeaders headers() { throw new AssertionError("Headers must not be inspected"); }
            public HttpClient.Version version() { return HttpClient.Version.HTTP_2; }
        };
    }
    @Test void onlyNegotiatedProtocolAndCipherAreExposedWithoutPolicyConclusions() {
        var observation = TlsSessionObservation.observe(response("https://user:secret@example.test/path?token=private",
                session("TLSv1.3", "TLS_AES_256_GCM_SHA384")));
        assertEquals("tls-session-observed", observation.get("status"));
        assertEquals("TLSv1.3", observation.get("protocol"));
        assertEquals("TLS_AES_256_GCM_SHA384", observation.get("cipher_suite"));
        assertEquals(false, observation.get("affects_verdict"));
        assertEquals(false, observation.get("fresh_handshake_verified"));
        assertFalse(observation.toString().contains("secret"));
        assertFalse(observation.toString().contains("private"));
        assertEquals(64, observation.get("endpoint_sha256").toString().length());
    }
    @Test void plaintextAndUnavailableSessionsAreDistinctAndNeverSecurityVerdicts() {
        assertEquals("plaintext-http-observed", TlsSessionObservation.observe(response("http://example.test", null)).get("status"));
        for (var sample : List.of(response("https://example.test", null),
                response("http://example.test", session("TLSv1.3", "TLS_AES_256_GCM_SHA384")),
                response("https://example.test", session("NONE", "SSL_NULL_WITH_NULL_NULL")),
                response("https://example.test", session("TLSv1.3\nsecret", "TLS_AES_256_GCM_SHA384")))) {
            var observation = TlsSessionObservation.observe(sample);
            assertEquals("tls-session-unavailable", observation.get("status"));
            assertEquals(false, observation.get("affects_verdict"));
            assertFalse(observation.containsKey("protocol"));
            assertFalse(observation.containsKey("cipher_suite"));
        }
    }
}
