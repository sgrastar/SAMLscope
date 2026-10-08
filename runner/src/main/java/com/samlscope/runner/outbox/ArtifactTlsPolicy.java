package com.samlscope.runner.outbox;

import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import javax.net.ssl.*;
import com.samlscope.saml.artifact.ArtifactTlsEvidence;
import com.samlscope.saml.crypto.PlanCredentials;

/** Closed production authority; an injected HttpClient never acquires this policy. */
final class ArtifactTlsPolicy {
    private final HttpClient client;
    private ArtifactTlsPolicy(HttpClient client) { this.client = client; }
    static ArtifactTlsPolicy create() {
        try {
            var trusts = TrustManagerFactory.getInstance("PKIX"); trusts.init((KeyStore)null);
            var context = SSLContext.getInstance("TLS"); context.init(null,trusts.getTrustManagers(),null);
            var parameters = new SSLParameters(); parameters.setEndpointIdentificationAlgorithm("HTTPS");
            return new ArtifactTlsPolicy(HttpClient.newBuilder().sslContext(context).sslParameters(parameters)
                    .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(20)).build());
        } catch (Exception unavailable) { throw new IllegalStateException("Artifact PKIX transport unavailable",unavailable); }
    }
    HttpClient client() { return client; }
    Optional<Map<String,Object>> capture(HttpResponse<?> response, URI endpoint, String runId, String actionId,
            String requestRef, String responseRef, byte[] requestBytes, byte[] responseBytes, PlanCredentials suite) {
        try {
            if (!"https".equalsIgnoreCase(endpoint.getScheme()) || !endpoint.equals(response.uri())
                    || response.previousResponse().isPresent() || response.sslSession().isEmpty()
                    || !"HTTPS".equals(client.sslParameters().getEndpointIdentificationAlgorithm())) return Optional.empty();
            var session = response.sslSession().orElseThrow();
            if (!endpoint.getHost().equalsIgnoreCase(session.getPeerHost())) return Optional.empty();
            var certificates = new ArrayList<String>();
            for (var certificate : session.getPeerCertificates()) {
                if (!(certificate instanceof X509Certificate)) return Optional.empty();
                certificates.add(hash(certificate.getEncoded()));
            }
            if (certificates.isEmpty()) return Optional.empty();
            var facts = new LinkedHashMap<String,Object>();
            facts.put("source",ArtifactTlsEvidence.SOURCE); facts.put("run_id",runId); facts.put("action_id",actionId);
            facts.put("endpoint_sha256",hash(endpoint.toASCIIString().getBytes(StandardCharsets.UTF_8)));
            facts.put("request_reference",requestRef); facts.put("response_reference",responseRef);
            facts.put("request_sha256",hash(requestBytes)); facts.put("response_sha256",hash(responseBytes));
            facts.put("protocol",session.getProtocol()); facts.put("cipher_suite",session.getCipherSuite());
            facts.put("peer_certificate_sha256",List.copyOf(certificates));
            return Optional.of(ArtifactTlsEvidence.sign(facts,suite));
        } catch (Exception unproven) { return Optional.empty(); }
    }
    private static String hash(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
}
