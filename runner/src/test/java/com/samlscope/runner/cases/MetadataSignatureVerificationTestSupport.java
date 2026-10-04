package com.samlscope.runner.cases;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptEntry;

/**
 * Builds a Run-scoped metadata-signature-verification receipt together with the transcript originals
 * it references. Every original is a real byte sequence bound to the Run and the target, so a case
 * only accepts the receipt when it can read the originals, match their SHA-256 and check their
 * semantics. Tests mutate the receipt or replace an original to exercise the fail-closed paths.
 */
public final class MetadataSignatureVerificationTestSupport {
    public static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    public static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    public static final String TARGET_ENTITY_ID = "http://localhost:18280/idp/shibboleth";
    public static final String CAMPAIGN_ID = "metadata-fixture-refresh";
    public static final byte[] ANCHOR_DER = "suite-out-of-band-anchor-der".getBytes(StandardCharsets.UTF_8);
    public static final byte[] EMBEDDED_DER = "metadata-embedded-keyinfo-der".getBytes(StandardCharsets.UTF_8);
    public static final String FIXTURE = "signed-other-key-primary-keyinfo";
    public static final String POSITIVE = FIXTURE;
    public static final String INVALID = "metadata-signature-invalid-control";
    public static final String EMBEDDED = "metadata-signature-embedded-anchor-control";

    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String P = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final String REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";

    public static final byte[] TARGET = ("<md:EntityDescriptor xmlns:md=\"" + MD + "\" entityID=\""
            + TARGET_ENTITY_ID + "\"><md:IDPSSODescriptor/></md:EntityDescriptor>")
            .getBytes(StandardCharsets.UTF_8);
    public static final byte[] SUCCESS_RESPONSE = ("<samlp:Response xmlns:samlp=\"" + P
            + "\"><samlp:Status><samlp:StatusCode Value=\"" + SUCCESS + "\"/></samlp:Status></samlp:Response>")
            .getBytes(StandardCharsets.UTF_8);
    public static final byte[] REQUESTER_RESPONSE = ("<samlp:Response xmlns:samlp=\"" + P
            + "\"><samlp:Status><samlp:StatusCode Value=\"" + REQUESTER + "\"/></samlp:Status></samlp:Response>")
            .getBytes(StandardCharsets.UTF_8);

    private MetadataSignatureVerificationTestSupport() {}

    public static byte[] fixtureBytes(String variant) { return fixtureXml(variant).getBytes(StandardCharsets.UTF_8); }

    private static String fixtureXml(String variant) {
        return "<md:EntityDescriptor xmlns:md=\"" + MD + "\" xmlns:ds=\"" + DS + "\" entityID=\"https://suite.example/"
                + variant + "\"><ds:Signature><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + Base64.getEncoder().encodeToString(EMBEDDED_DER)
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></md:EntityDescriptor>";
    }

    public static String configurationArtifact(byte[] anchorDer) { return configurationArtifact(RUN, anchorDer); }

    public static String configurationArtifact(String runId, byte[] anchorDer) {
        return "{\"artifact\":\"metadata-signature-trust-configuration\",\"runId\":\"" + runId
                + "\",\"targetEntityId\":\"" + TARGET_ENTITY_ID
                + "\",\"signatureVerification\":\"enabled\",\"trustAnchorCertificates\":[\""
                + Base64.getEncoder().encodeToString(anchorDer) + "\"]}";
    }

    public static String restorationArtifact() { return restorationArtifact(RUN); }

    public static String restorationArtifact(String runId) {
        return "{\"artifact\":\"metadata-signature-configuration-restored\",\"runId\":\"" + runId
                + "\",\"targetEntityId\":\"" + TARGET_ENTITY_ID
                + "\",\"restored\":true,\"trustAnchorCertificates\":[]}";
    }

    public static Path writeReceipt(Path directory, UnaryOperator<String> mutate) throws IOException {
        return writeReceipt(directory, RUN, mutate);
    }

    public static Path writeReceipt(Path directory, String runId, UnaryOperator<String> mutate)
            throws IOException {
        var target = directory.resolve(runId + ".signature-verification.json");
        Files.writeString(target, mutate.apply(receipt(runId)));
        return target;
    }

    public static String receipt() { return receipt(RUN); }

    public static String receipt(String runId) {
        var restoration = restorationArtifact(runId);
        return "{\"schema\":\"samlscope-metadata-signature-verification-receipt-v3\""
                + ",\"runId\":\"" + runId + "\""
                + ",\"campaignId\":\"" + CAMPAIGN_ID + "\""
                + ",\"targetEntityId\":\"" + TARGET_ENTITY_ID + "\""
                + ",\"targetMetadataSha256\":\"" + sha(TARGET) + "\""
                + ",\"evidenceAdapter\":\"shibboleth-signature-validation\""
                + ",\"configurationReadBack\":{\"reference\":\"" + tx(101) + "\",\"sha256\":\""
                + sha(configurationArtifact(runId, ANCHOR_DER).getBytes(StandardCharsets.UTF_8))
                + "\",\"trustAnchorCertificateSha256\":\"" + sha(ANCHOR_DER) + "\"}"
                + ",\"restorationReadBack\":{\"originalReference\":\"" + tx(100)
                + "\",\"originalSha256\":\"" + sha(restoration.getBytes(StandardCharsets.UTF_8))
                + "\",\"finalReference\":\"" + tx(150) + "\",\"finalSha256\":\""
                + sha(restoration.getBytes(StandardCharsets.UTF_8)) + "\"}"
                + ",\"positive\":{\"variant\":\"" + POSITIVE + "\",\"requestReference\":\"" + tx(110)
                + "\",\"responseReference\":\"" + tx(111) + "\",\"requestId\":\"" + requestId(1)
                + "\",\"inResponseTo\":\"" + requestId(1) + "\",\"responseSha256\":\"" + sha(SUCCESS_RESPONSE)
                + "\",\"embeddedKeyInfoCertificateSha256\":\"" + sha(EMBEDDED_DER) + "\"}"
                + ",\"negativeControls\":["
                + "{\"kind\":\"invalid-signature\",\"variant\":\"" + INVALID + "\",\"requestId\":\"" + requestId(5)
                + "\",\"requestReference\":\"" + tx(120) + "\",\"rejectionReference\":\"" + tx(121) + "\"}"
                + ",{\"kind\":\"embedded-anchor\",\"variant\":\"" + EMBEDDED + "\",\"requestId\":\"" + requestId(6)
                + "\",\"requestReference\":\"" + tx(140) + "\",\"rejectionReference\":\"" + tx(141)
                + "\",\"configurationReadBack\":{\"reference\":\"" + tx(130) + "\",\"sha256\":\""
                + sha(configurationArtifact(runId, EMBEDDED_DER).getBytes(StandardCharsets.UTF_8)) + "\"}}"
                + "]}";
    }

    /** Transcript entries the receipt's originals and bindings must resolve to. */
    public static List<TranscriptEntry> correlationEntries() { return correlationEntries(RUN); }

    public static List<TranscriptEntry> correlationEntries(String runId) {
        var entries = new ArrayList<TranscriptEntry>();
        entries.add(artifact(runId, 100, "config-original", restorationArtifact(runId)));
        entries.add(artifact(runId, 101, "config-out-of-band", configurationArtifact(runId, ANCHOR_DER)));
        entries.add(prepared(runId, 102, POSITIVE));
        entries.add(prepared(runId, 103, INVALID));
        entries.add(prepared(runId, 104, EMBEDDED));
        entries.add(request(runId, 110, requestId(1), POSITIVE, null));
        entries.add(response(runId, 111, requestId(1), "response-positive", SUCCESS_RESPONSE, SUCCESS));
        entries.add(request(runId, 120, requestId(5), INVALID, "invalid"));
        entries.add(response(runId, 121, requestId(5), "rejection-invalid", REQUESTER_RESPONSE, REQUESTER));
        entries.add(artifact(runId, 130, "config-embedded", configurationArtifact(runId, EMBEDDED_DER)));
        entries.add(request(runId, 140, requestId(6), EMBEDDED, null));
        entries.add(response(runId, 141, requestId(6), "rejection-embedded", REQUESTER_RESPONSE, REQUESTER));
        entries.add(artifact(runId, 150, "config-final", restorationArtifact(runId)));
        return entries;
    }

    public static TranscriptContentReader content() { return content(RUN); }

    public static TranscriptContentReader content(String runId) { return content(runId, Map.of()); }

    /** content with one or more originals replaced, for the "original bytes disagree" controls. */
    public static TranscriptContentReader content(String runId, Map<String, byte[]> overrides) {
        var decoded = new HashMap<String, byte[]>();
        decoded.put("config-out-of-band", configurationArtifact(runId, ANCHOR_DER).getBytes(StandardCharsets.UTF_8));
        decoded.put("config-embedded", configurationArtifact(runId, EMBEDDED_DER).getBytes(StandardCharsets.UTF_8));
        decoded.put("config-original", restorationArtifact(runId).getBytes(StandardCharsets.UTF_8));
        decoded.put("config-final", restorationArtifact(runId).getBytes(StandardCharsets.UTF_8));
        decoded.put("response-positive", SUCCESS_RESPONSE);
        decoded.put("rejection-invalid", REQUESTER_RESPONSE);
        decoded.put("rejection-embedded", REQUESTER_RESPONSE);
        return entry -> {
            var ref = entry.decodedSamlRef();
            if (ref == null) return new byte[0];
            if (overrides.containsKey(ref)) return overrides.get(ref);
            if (ref.startsWith("fixture-")) return fixtureBytes(ref.substring("fixture-".length()));
            return decoded.getOrDefault(ref, new byte[0]);
        };
    }

    private static TranscriptEntry artifact(String runId, int sequence, String decodedRef, String json) {
        return entry(runId, sequence, Direction.OUTBOUND, "https://suite.example/artifacts/" + decodedRef,
                decodedRef, json.getBytes(StandardCharsets.UTF_8).length,
                Map.of("type", "MetadataSignatureArtifact"));
    }

    private static TranscriptEntry prepared(String runId, int sequence, String variant) {
        return entry(runId, sequence, Direction.OUTBOUND, "/metadata/live", "fixture-" + variant,
                fixtureBytes(variant).length, Map.of("type", "MetadataPrepared", "variant", variant));
    }

    private static TranscriptEntry request(String runId, int sequence, String requestId, String variant,
            String control) {
        var summary = new HashMap<String, Object>();
        summary.put("type", "AuthnRequest");
        summary.put("id", requestId);
        summary.put("variant", variant);
        if (control != null) summary.put("metadataSignatureControl", control);
        return entry(runId, sequence, Direction.OUTBOUND, "https://idp.example/sso", "req-" + sequence, 0, summary);
    }

    private static TranscriptEntry response(String runId, int sequence, String requestId, String decodedRef,
            byte[] body, String status) {
        return entry(runId, sequence, Direction.INBOUND, "https://suite.example/sp/acs/0", decodedRef,
                body.length, Map.of("type", "Response", "inResponseTo", requestId, "statusCode", status));
    }

    private static TranscriptEntry entry(String runId, int sequence, Direction direction, String url,
            String decodedRef, int decodedBytes, Map<String, Object> summary) {
        return new TranscriptEntry(
                tx(sequence), runId, direction, NOW.plusSeconds(sequence), "corr", "GET", url,
                200, Map.of(), null, 0, decodedRef, decodedBytes, null, null, summary);
    }

    public static List<TranscriptEntry> withCorrelation(List<TranscriptEntry> entries) {
        return withCorrelation(entries, RUN);
    }

    public static List<TranscriptEntry> withCorrelation(List<TranscriptEntry> entries, String runId) {
        var all = new ArrayList<>(entries);
        all.addAll(correlationEntries(runId));
        return all;
    }

    public static String requestId(int value) { return "_req_" + value; }

    public static String tx(int value) { return "tx_" + String.format("%026d", value); }

    public static String sha(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (Exception failure) {
            throw new IllegalStateException(failure);
        }
    }
}
