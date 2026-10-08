package com.samlscope.runner.outbox;

import java.net.http.*;
import java.time.*;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.TlsSessionObservation;
import com.samlscope.saml.artifact.ArtifactResolutionProtocol;
import com.samlscope.runner.cases.SamlPlanCredentialsProvider;

/** Only the persisted ArtifactResolve outbox performs its SOAP exchange; never follows redirects. */
public final class ArtifactResolutionOutboundSender implements OutboundSender {
    public static final String CASE = "IIP-IDP12-f-idp-01";
    public static final String PHASE = "await-artifact-resolution";
    private static final int MAX_BYTES = 1024 * 1024;
    private final HttpClient client;
    private final TranscriptRecorder recorder;
    private final Clock clock;
    private final ArtifactTlsPolicy tlsPolicy;
    private final SamlPlanCredentialsProvider suiteKeys;
    public ArtifactResolutionOutboundSender(HttpClient client, TranscriptRecorder recorder, Clock clock) {
        this(client,recorder,clock,null,run -> Optional.empty());
    }
    private ArtifactResolutionOutboundSender(HttpClient client, TranscriptRecorder recorder, Clock clock,
            ArtifactTlsPolicy policy,SamlPlanCredentialsProvider suiteKeys) {
        this.client = Objects.requireNonNull(client); this.recorder = Objects.requireNonNull(recorder); this.clock = Objects.requireNonNull(clock);
        this.tlsPolicy = policy; this.suiteKeys = Objects.requireNonNull(suiteKeys);
        if (client.followRedirects() != HttpClient.Redirect.NEVER) throw new IllegalArgumentException("Artifact sender must not follow redirects");
    }
    public static ArtifactResolutionOutboundSender create(TranscriptRecorder recorder, Clock clock,
            SamlPlanCredentialsProvider suiteKeys) {
        var policy = ArtifactTlsPolicy.create();
        return new ArtifactResolutionOutboundSender(policy.client(),recorder,clock,policy,suiteKeys);
    }
    @Override public SendResult send(String runId, OutboundAction action, byte[] ephemeralCredential) throws Exception {
        if (action.kind() != OutboundKind.ARTIFACT_RESOLVE || action.requiresEphemeralCredential()
                || (ephemeralCredential != null && ephemeralCredential.length != 0)
                || !ActionIds.derive(runId, CASE, PHASE, 0).equals(action.actionId())) {
            throw new IllegalArgumentException("ArtifactResolve is restricted to the approved conditional case");
        }
        var raw = action.payload();
        if (raw.length == 0 || raw.length > MAX_BYTES) throw new IllegalArgumentException("Invalid ArtifactResolve size");
        var requestXml = new ArtifactResolutionProtocol().soapMessage(raw, "ArtifactResolve");
        if (!("_" + action.actionId()).equals(requestXml.getAttribute("ID"))
                || !action.target().toString().equals(requestXml.getAttribute("Destination"))) throw new IllegalArgumentException("Unbound ArtifactResolve action");
        var contentType = "text/xml; charset=utf-8";
        var headers = Map.of("Content-Type", List.of(contentType), "SOAPAction", List.of("\"http://www.oasis-open.org/committees/security\""),
                "Cache-Control", List.of("no-cache, no-store"));
        var request = recorder.record(new TranscriptInput(runId, Direction.OUTBOUND, clock.instant(), action.actionId(),
                "POST", action.target().toString(), null, headers, raw, contentType, null, raw,
                Map.of("type", "ArtifactResolve", "kind", action.kind().name(), "scenario_case_id", CASE,
                        "action_id", action.actionId(), "request_sha256", sha256(raw))));
        var http = HttpRequest.newBuilder(action.target()).timeout(Duration.ofSeconds(20))
                .header("Content-Type", contentType).header("SOAPAction", "\"http://www.oasis-open.org/committees/security\"")
                .header("Cache-Control", "no-cache, no-store").POST(HttpRequest.BodyPublishers.ofByteArray(raw)).build();
        var response = client.send(http, HttpResponse.BodyHandlers.ofInputStream());
        byte[] bytes;
        try (var stream = response.body()) { bytes = stream.readNBytes(MAX_BYTES + 1); }
        if (bytes.length > MAX_BYTES) throw new java.io.IOException("ArtifactResponse exceeds 1 MiB");
        var responseHeaders = new LinkedHashMap<String,List<String>>();
        response.headers().map().forEach((name, values) -> {
            if (!Set.of("authorization", "proxy-authorization", "cookie", "set-cookie")
                    .contains(name.toLowerCase(Locale.ROOT))) responseHeaders.put(name, List.copyOf(values));
        });
        var tls = TlsSessionObservation.observe(response);
        var receipt = recorder.record(new TranscriptInput(runId, Direction.INBOUND, clock.instant(), action.actionId(),
                "POST", action.target().toString(), response.statusCode(), responseHeaders, bytes,
                response.headers().firstValue("content-type").orElse(null), null, bytes,
                Map.of("type", "ArtifactResponse", "scenario_case_id", CASE, "action_id", action.actionId(),
                        "request_transcript", request.id(), "tls_observation", tls,
                        "response_sha256", sha256(bytes))));
        var result = new LinkedHashMap<String,Object>();
        result.put("http_status",response.statusCode()); result.put("response_bytes",bytes.length);
        result.put("request_transcript",request.id()); result.put("response_sha256",sha256(bytes)); result.put("tls_observation",tls);
        if (tlsPolicy != null && suiteKeys.credentialsFor(runId).isPresent()) {
            var capture = tlsPolicy.capture(response,action.target(),runId,action.actionId(),request.id(),receipt.id(),raw,bytes,
                    suiteKeys.credentialsFor(runId).orElseThrow());
            if (capture.isPresent()) {
                var summary = new LinkedHashMap<String,Object>(receipt.samlSummary());
                summary.put("transport_authentication",capture.orElseThrow());
                recorder.updateSamlAnalysis(receipt.id(),receipt.correlationId(),Map.copyOf(summary));
                result.put("transport_authentication",capture.orElseThrow());
            }
        }
        return new SendResult(false, Map.copyOf(result), receipt.id());
    }
    private static String sha256(byte[] bytes) throws java.security.NoSuchAlgorithmException {
        return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
