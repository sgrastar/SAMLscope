package com.samlscope.runner;

import java.net.URI;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Factual connection evidence only: a negotiated session cannot prove global TLS policy. */
public final class TlsSessionObservation {
    private TlsSessionObservation() {}

    public static Map<String, Object> observe(HttpResponse<?> response) {
        var values = new LinkedHashMap<String, Object>();
        values.put("affects_verdict", false);
        values.put("scope", "single-http-response");
        values.put("source", "jdk-http-client-ssl-session");
        values.put("fresh_handshake_verified", false); // HttpClient may reuse a connection/session.
        try {
            URI endpoint = response.uri();
            values.put("endpoint_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(endpoint.toASCIIString().getBytes(StandardCharsets.UTF_8))));
            var session = response.sslSession();
            if ("http".equalsIgnoreCase(endpoint.getScheme()) && session.isEmpty()) {
                values.put("status", "plaintext-http-observed");
            } else if (!"https".equalsIgnoreCase(endpoint.getScheme()) || session.isEmpty()) {
                values.put("status", "tls-session-unavailable");
            } else {
                var protocol = session.get().getProtocol();
                var cipher = session.get().getCipherSuite();
                if (!token(protocol, 64) || !token(cipher, 160)
                        || "NONE".equals(protocol) || "SSL_NULL_WITH_NULL_NULL".equals(cipher)) {
                    values.put("status", "tls-session-unavailable");
                } else {
                    values.put("status", "tls-session-observed");
                    values.put("protocol", protocol);
                    values.put("cipher_suite", cipher);
                }
            }
        } catch (Exception unavailable) {
            // Exceptions, certificates, peer principals, session IDs and URLs may contain
            // identifiers or credentials. None belongs in this bounded observation.
            values.put("status", "tls-session-unavailable");
        }
        return Map.copyOf(values);
    }

    private static boolean token(String value, int maximum) {
        return value != null && value.length() <= maximum && value.matches("[A-Za-z0-9_.-]+");
    }
}
