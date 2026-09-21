package com.samlscope.runner.outbox;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.net.URLEncoder;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

/** The only production boundary that performs HTTP for persisted outbox intents. */
public final class HttpOutboundSender implements OutboundSender {
    private static final int MAX_RESPONSE_BYTES = 1024 * 1024;
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(20);
    private final HttpClient client;
    private final TranscriptRecorder transcript;
    private final Clock clock;

    public HttpOutboundSender(HttpClient client, TranscriptRecorder transcript, Clock clock) {
        this.client = Objects.requireNonNull(client, "client");
        this.transcript = Objects.requireNonNull(transcript, "transcript");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static HttpOutboundSender create(TranscriptRecorder transcript, Clock clock) {
        return new HttpOutboundSender(HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(20))
                .build(), transcript, clock);
    }

    @Override
    public SendResult send(String runId, OutboundAction action, byte[] ephemeralCredential) throws Exception {
        if (action.kind() == OutboundKind.LOGOUT_PROBE) {
            return sendLogoutProbe(runId, action);
        }
        if (action.kind() != OutboundKind.ECP_SOAP) {
            throw new IllegalArgumentException("HTTP sender does not implement " + action.kind());
        }
        if (ephemeralCredential == null || ephemeralCredential.length == 0) {
            throw new IllegalArgumentException("ECP SOAP requires an ephemeral credential");
        }
        var contentType = "text/xml; charset=utf-8";
        var authorization = "Basic " + Base64.getEncoder().encodeToString(ephemeralCredential);
        var requestHeaders = Map.of(
                "Content-Type", List.of(contentType),
                "Accept", List.of("text/xml, application/soap+xml"));
        var outbound = transcript.record(new TranscriptInput(
                runId, Direction.OUTBOUND, clock.instant(), action.actionId(), "POST",
                action.target().toString(), null, requestHeaders, action.payload(), contentType,
                null, action.payload(), Map.of("type", "EcpSoapRequest", "kind", action.kind().name())));

        var request = HttpRequest.newBuilder(action.target())
                .timeout(Duration.ofSeconds(60))
                .header("Content-Type", contentType)
                .header("Accept", "text/xml, application/soap+xml")
                .header("Authorization", authorization)
                .POST(HttpRequest.BodyPublishers.ofByteArray(action.payload()))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        byte[] responseBody;
        try (var body = response.body()) {
            responseBody = body.readNBytes(MAX_RESPONSE_BYTES + 1);
        }
        if (responseBody.length > MAX_RESPONSE_BYTES) {
            throw new java.io.IOException("ECP response exceeds 1 MiB");
        }
        var responseHeaders = new LinkedHashMap<String, List<String>>();
        response.headers().map().forEach((name, values) -> {
            if (!credentialHeader(name)) responseHeaders.put(name, List.copyOf(values));
        });
        var responseContentType = response.headers().firstValue("content-type").orElse(null);
        var tlsObservation = com.samlscope.runner.TlsSessionObservation.observe(response);
        var inbound = transcript.record(new TranscriptInput(
                runId, Direction.INBOUND, clock.instant(), action.actionId(), "POST",
                action.target().toString(), response.statusCode(), responseHeaders, responseBody,
                responseContentType, null, responseBody,
                Map.of("type", "EcpSoapResponse", "request_transcript", outbound.id(),
                        "tls_observation", tlsObservation)));
        return new SendResult(false,
                Map.of("http_status", response.statusCode(), "response_bytes", responseBody.length,
                        "tls_observation", tlsObservation), inbound.id());
    }

    /**
     * Suite-side delivery of an approved SLO fixture over HTTP-POST. The response body is the
     * observation: an HTML page, an error document, or an embedded SAML response. Unknown
     * delivery (connection failure or timeout) stays an exception and becomes UNKNOWN_DELIVERY.
     */
    private SendResult sendLogoutProbe(String runId, OutboundAction action) throws Exception {
        var requestXml = action.payload();
        if (requestXml.length == 0) throw new IllegalArgumentException("Logout probe payload is empty");
        var contentType = "application/x-www-form-urlencoded";
        var body = ("SAMLRequest=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(requestXml), StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8);
        var outbound = transcript.record(new TranscriptInput(
                runId, Direction.OUTBOUND, clock.instant(), action.actionId(), "POST",
                action.target().toString(), null, Map.of("Content-Type", List.of(contentType)),
                body, contentType, null, requestXml,
                Map.of("type", "LogoutRequest", "kind", action.kind().name(),
                        "probe_transport", "direct-http-post")));
        var request = HttpRequest.newBuilder(action.target())
                .timeout(PROBE_TIMEOUT)
                .header("Content-Type", contentType)
                .header("Accept", "text/html, application/xhtml+xml, text/xml;q=0.9")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        byte[] responseBody;
        try (var stream = response.body()) {
            responseBody = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
        }
        if (responseBody.length > MAX_RESPONSE_BYTES) {
            throw new java.io.IOException("Logout probe response exceeds 1 MiB");
        }
        var responseHeaders = new LinkedHashMap<String, List<String>>();
        response.headers().map().forEach((name, values) -> {
            if (!credentialHeader(name)) responseHeaders.put(name, List.copyOf(values));
        });
        var responseContentType = response.headers().firstValue("content-type").orElse(null);
        var location = responseHeaders.getOrDefault("location", List.of()).stream().findFirst().orElse(null);
        var summary = new LinkedHashMap<String, Object>(probeSummary(responseBody, responseContentType, location));
        summary.put("tls_observation", com.samlscope.runner.TlsSessionObservation.observe(response));
        var inbound = transcript.record(new TranscriptInput(
                runId, Direction.INBOUND, clock.instant(), action.actionId(), "POST",
                action.target().toString(), response.statusCode(), responseHeaders, responseBody,
                responseContentType, null, responseBody, summary));
        var details = new LinkedHashMap<String, Object>();
        details.put("http_status", response.statusCode());
        details.put("response_bytes", responseBody.length);
        details.put("request_transcript", outbound.id());
        details.put("tls_observation", summary.get("tls_observation"));
        details.put("saml_message", summary.getOrDefault("saml_message", ""));
        return new SendResult(false, Map.copyOf(details), inbound.id());
    }

    private static boolean credentialHeader(String name) {
        return switch (name.toLowerCase(java.util.Locale.ROOT)) {
            case "authorization", "proxy-authorization", "cookie", "set-cookie", "set-cookie2" -> true;
            default -> false;
        };
    }

    private static Map<String, Object> probeSummary(byte[] body, String contentType, String location) {
        var text = new String(body, StandardCharsets.UTF_8);
        var saml = com.samlscope.saml.normal.SamlEmbeddedMessage.find(text)
                .map(bytes -> (byte[]) bytes).orElse(null);
        if (saml == null && location != null && !location.isBlank()) {
            saml = com.samlscope.saml.normal.SamlEmbeddedMessage.find(location)
                    .map(bytes -> (byte[]) bytes).orElse(null);
        }
        if (saml == null) {
            return Map.of("type", "SloProbeHttpResponse",
                    "probe_response", "http-only",
                    "redirect_location", location == null ? "" : location,
                    "content_type", contentType == null ? "" : contentType);
        }
        try {
            var document = com.samlscope.saml.normal.SecureXml.parse(saml);
            var root = document.getDocumentElement();
            var values = new LinkedHashMap<String, Object>();
            values.put("type", "SloProbeHttpResponse");
            values.put("probe_response", "saml-message");
            values.put("saml_message", root.getLocalName());
            values.put("saml_namespace", String.valueOf(root.getNamespaceURI()));
            values.put("saml_id", root.getAttribute("ID"));
            values.put("in_response_to", root.getAttribute("InResponseTo"));
            values.put("destination", root.getAttribute("Destination"));
            values.put("content_type", contentType == null ? "" : contentType);
            values.put("redirect_location", location == null ? "" : location);
            var statuses = root.getElementsByTagNameNS(
                    "urn:oasis:names:tc:SAML:2.0:protocol", "StatusCode");
            if (statuses.getLength() > 0) {
                values.put("status", ((org.w3c.dom.Element) statuses.item(0)).getAttribute("Value"));
            }
            return Map.copyOf(values);
        } catch (RuntimeException unparsable) {
            return Map.of("type", "SloProbeHttpResponse", "probe_response", "saml-message-unparsed",
                    "content_type", contentType == null ? "" : contentType);
        }
    }

}
