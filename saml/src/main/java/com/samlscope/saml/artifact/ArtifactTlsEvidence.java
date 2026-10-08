package com.samlscope.saml.artifact;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.*;
import com.samlscope.saml.crypto.PlanCredentials;

/**
 * Detached Suite-signed capture of the closed outbox sender's actual PKIX/HTTPS session.
 * The sender is the authority: this is not an operator attestation or a naked TLS boolean.
 * Verification additionally binds both recorded body hashes, references, action and Run.
 */
public final class ArtifactTlsEvidence {
    public static final String SOURCE = "samlscope-artifact-closed-pkix-https-v1";
    private static final List<String> FIELDS = List.of("source", "run_id", "action_id", "endpoint_sha256",
            "request_reference", "response_reference", "request_sha256", "response_sha256", "protocol", "cipher_suite");
    private final Map<String,Object> receipt;
    private ArtifactTlsEvidence(Map<String,Object> receipt) { this.receipt = Map.copyOf(receipt); }
    public Map<String,Object> receipt() { return receipt; }
    public boolean coversResponse(byte[] originalSoap) {
        return SamlArtifact.hash("SHA-256",originalSoap)
                .equals(((Map<?,?>)receipt.get("facts")).get("response_sha256"));
    }

    /** Called exclusively with session facts captured by the closed production outbox factory. */
    public static Map<String,Object> sign(Map<String,Object> facts, PlanCredentials suite) {
        try {
            var normalized = normalize(facts);
            var algorithm = algorithm(suite.privateKey().getAlgorithm());
            var signature = Signature.getInstance(algorithm); signature.initSign(suite.privateKey()); signature.update(material(normalized));
            return Map.of("facts",normalized,"signature_algorithm",algorithm,
                    "signature_value",Base64.getEncoder().encodeToString(signature.sign()),
                    "suite_certificate_sha256",SamlArtifact.hash("SHA-256",suite.certificate().getEncoded()));
        } catch (Exception invalid) { throw new IllegalArgumentException("TLS capture signing unavailable", invalid); }
    }

    public static Optional<ArtifactTlsEvidence> verify(Map<String,Object> captured, String runId, String actionId,
            URI endpoint, String requestRef, String responseRef, byte[] requestBytes, byte[] responseBytes,
            X509Certificate suiteCertificate) {
        try {
            SamlArtifact.require(captured != null && captured.keySet().equals(Set.of("facts","signature_algorithm",
                    "signature_value","suite_certificate_sha256")), "Unknown TLS receipt fields");
            var value = captured.get("facts"); SamlArtifact.require(value instanceof Map<?,?>, "TLS facts unavailable");
            var raw = new LinkedHashMap<String,Object>();
            ((Map<?,?>)value).forEach((key,item) -> { SamlArtifact.require(key instanceof String,"TLS fact name invalid"); raw.put((String)key,item); });
            var facts = normalize(raw);
            SamlArtifact.require(runId.equals(facts.get("run_id")) && actionId.equals(facts.get("action_id"))
                    && "https".equalsIgnoreCase(endpoint.getScheme())
                    && SamlArtifact.hash("SHA-256",endpoint.toASCIIString().getBytes(StandardCharsets.UTF_8)).equals(facts.get("endpoint_sha256"))
                    && requestRef.equals(facts.get("request_reference")) && responseRef.equals(facts.get("response_reference"))
                    && SamlArtifact.hash("SHA-256",requestBytes).equals(facts.get("request_sha256"))
                    && SamlArtifact.hash("SHA-256",responseBytes).equals(facts.get("response_sha256"))
                    && SamlArtifact.hash("SHA-256",suiteCertificate.getEncoded()).equals(captured.get("suite_certificate_sha256")),
                    "Unbound TLS session receipt");
            String expected = algorithm(suiteCertificate.getPublicKey().getAlgorithm());
            SamlArtifact.require(expected.equals(captured.get("signature_algorithm")) && captured.get("signature_value") instanceof String,
                    "Unsupported TLS receipt signature");
            var signature = Signature.getInstance(expected); signature.initVerify(suiteCertificate); signature.update(material(facts));
            SamlArtifact.require(signature.verify(Base64.getDecoder().decode((String)captured.get("signature_value"))), "Invalid TLS receipt signature");
            return Optional.of(new ArtifactTlsEvidence(Map.of("facts",facts,
                    "signature_algorithm",captured.get("signature_algorithm"),
                    "signature_value",captured.get("signature_value"),
                    "suite_certificate_sha256",captured.get("suite_certificate_sha256"))));
        } catch (Exception unproven) { return Optional.empty(); }
    }
    private static Map<String,Object> normalize(Map<String,Object> input) {
        var fields = new HashSet<>(FIELDS); fields.add("peer_certificate_sha256");
        SamlArtifact.require(input.keySet().equals(fields), "Unknown TLS session facts");
        for (var field:FIELDS) SamlArtifact.require(input.get(field) instanceof String text && !text.isBlank(), "Missing TLS session fact");
        SamlArtifact.require(SOURCE.equals(input.get("source")) && ((String)input.get("protocol")).matches("TLSv[0-9.]+")
                && ((String)input.get("cipher_suite")).matches("[A-Za-z0-9_]+")
                && !((String)input.get("cipher_suite")).toUpperCase(Locale.ROOT).contains("NULL")
                && !((String)input.get("cipher_suite")).toUpperCase(Locale.ROOT).contains("ANON"), "Unproven TLS protection");
        var hashes = input.get("peer_certificate_sha256");
        SamlArtifact.require(hashes instanceof List<?> values && !values.isEmpty()
                && values.stream().allMatch(v -> v instanceof String hash && hash.matches("[0-9a-f]{64}")), "Unproven TLS peer identity");
        var copy = new LinkedHashMap<>(input); copy.put("peer_certificate_sha256",List.copyOf((List<?>)hashes)); return Map.copyOf(copy);
    }
    private static byte[] material(Map<String,Object> facts) {
        var output = new StringBuilder("samlscope-artifact-tls-evidence-v1\n");
        for (var field : FIELDS) append(output,field,(String)facts.get(field));
        var peers = (List<?>)facts.get("peer_certificate_sha256"); append(output,"peer_count",Integer.toString(peers.size()));
        for (int index=0; index<peers.size();index++) append(output,"peer_"+index,(String)peers.get(index));
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }
    private static void append(StringBuilder output,String key,String value) { output.append(key.length()).append(':').append(key).append(':').append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value).append('\n'); }
    private static String algorithm(String key) { return switch(key){case "RSA" -> "SHA256withRSA";case "EC" -> "SHA256withECDSA";default -> throw new IllegalArgumentException("Unsupported Suite TLS receipt key");}; }
}
