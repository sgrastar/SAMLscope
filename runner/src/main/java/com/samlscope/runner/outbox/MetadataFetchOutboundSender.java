package com.samlscope.runner.outbox;

import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.transcript.*;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;

/** Credential-free metadata retrieval. Dispatch policy and retry decisions belong to Runner. */
public final class MetadataFetchOutboundSender implements OutboundSender {
    public static final String REQUEST = "MetadataFetchRequest", RESPONSE = "MetadataFetchResponse";
    private static final Set<String> CREDENTIAL_QUERY_KEYS = Set.of(
            "password", "passwd", "pwd", "secret", "token", "otp", "pin",
            "accesstoken", "refreshtoken", "idtoken", "authtoken", "bearertoken", "sessiontoken",
            "clientsecret", "apikey", "apisecret", "authorization", "credential", "credentials");
    private final HttpClient client;
    private final TranscriptRecorder recorder;
    private final Clock clock;
    private final Duration timeout;
    private final int limit;

    public MetadataFetchOutboundSender(TranscriptRecorder recorder, Clock clock) {
        this(recorder, clock, Duration.ofSeconds(20), 5 * 1024 * 1024);
    }

    MetadataFetchOutboundSender(TranscriptRecorder recorder, Clock clock, Duration timeout, int limit) {
        this.recorder = Objects.requireNonNull(recorder);
        this.clock = Objects.requireNonNull(clock);
        this.timeout = Objects.requireNonNull(timeout);
        if (timeout.isNegative() || timeout.isZero() || limit <= 0) throw new IllegalArgumentException("Invalid metadata retrieval bounds");
        this.limit = limit;
        // Never inherit an injected sender's authenticator, CookieHandler, or redirect policy.
        this.client = HttpClient.newBuilder().connectTimeout(timeout)
                .followRedirects(HttpClient.Redirect.NEVER).build();
    }

    public static boolean supported(URI uri) {
        if (uri == null || !uri.isAbsolute() || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getFragment() != null || !Set.of("http", "https").contains(uri.getScheme().toLowerCase(Locale.ROOT))) return false;
        if (uri.getRawQuery() != null) for (String part : uri.getRawQuery().split("&")) {
            try {
                int equals = part.indexOf('=');
                String rawKey = equals < 0 ? part : part.substring(0, equals);
                String key = URLDecoder.decode(rawKey, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT)
                        .replace("_", "").replace("-", "");
                if (CREDENTIAL_QUERY_KEYS.contains(key)) return false;
            } catch (IllegalArgumentException malformed) { return false; }
        }
        return true;
    }

    @Override public SendResult send(String runId, OutboundAction action, byte[] credential) throws Exception {
        if (action.kind() != OutboundKind.METADATA_FETCH || action.requiresEphemeralCredential()
                || action.payload().length != 0 || credential != null && credential.length != 0
                || !supported(action.target())) throw new IllegalArgumentException("Credential-free metadata GET required");
        var headers = Map.of("Accept", List.of("application/samlmetadata+xml, application/xml, text/xml"));
        var outbound = recorder.record(new TranscriptInput(runId, Direction.OUTBOUND, clock.instant(),
                action.actionId(), "GET", action.target().toString(), null, headers, new byte[0], null,
                null, new byte[0], Map.of("type", REQUEST, "kind", action.kind().name())));
        var request = HttpRequest.newBuilder(action.target()).timeout(timeout)
                .header("Accept", headers.get("Accept").getFirst()).GET().build();
        var response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        byte[] body;
        try (var stream = response.body()) { body = stream.readNBytes(limit + 1); }
        if (body.length > limit) throw new IOException("Metadata response exceeds observation limit");
        var cleanHeaders = new LinkedHashMap<String, List<String>>();
        response.headers().map().forEach((name, values) -> {
            if (!Set.of("authorization", "proxy-authorization", "cookie", "set-cookie")
                    .contains(name.toLowerCase(Locale.ROOT))) cleanHeaders.put(name, List.copyOf(values));
        });
        String type = response.headers().firstValue("Content-Type").orElse(null);
        String originalHash = hash(body);
        byte[] retained = body;
        // A login/error HTML page is not XML namespace evidence; never retain its potentially secret forms.
        if (body.length == 0 || type != null && type.toLowerCase(Locale.ROOT).contains("html")) retained = new byte[0];
        else try {
            if ("html".equalsIgnoreCase(root(body).getLocalName())) retained = new byte[0];
        } catch (RuntimeException nonXml) { retained = new byte[0]; }
        var inbound = recorder.record(new TranscriptInput(runId, Direction.INBOUND, clock.instant(),
                action.actionId(), "GET", action.target().toString(), response.statusCode(), cleanHeaders, retained,
                type, null, new byte[0], Map.of("type", RESPONSE, "kind", action.kind().name(),
                        "request_transcript", outbound.id(), "response_url", response.uri().toString(),
                        "original_body_sha256", originalHash)));
        return new SendResult(false, Map.of("http_status", response.statusCode(), "response_bytes", body.length), inbound.id());
    }

    public static String hash(byte[] body) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    /** Do not let parser diagnostics print fragments from a non-metadata login/error page. */
    public static org.w3c.dom.Element root(byte[] body) {
        try {
            var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false); factory.setExpandEntityReferences(false);
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(javax.xml.XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            var builder = factory.newDocumentBuilder();
            builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler() {
                @Override public void error(org.xml.sax.SAXParseException error) throws org.xml.sax.SAXException { throw error; }
                @Override public void fatalError(org.xml.sax.SAXParseException error) throws org.xml.sax.SAXException { throw error; }
            });
            return builder.parse(new java.io.ByteArrayInputStream(body)).getDocumentElement();
        } catch (Exception invalid) { throw new IllegalArgumentException("Metadata reference is not secure XML"); }
    }
}
