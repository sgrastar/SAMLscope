package com.samlscope.runner.cases;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import com.samlscope.saml.normal.SamlEmbeddedMessage;
import com.samlscope.saml.normal.SecureXml;
import org.w3c.dom.Element;

/** What the authenticated browser or the SLO endpoint observed for one probe delivery. */
public record SloProbeObservation(
        int httpStatus,
        String url,
        boolean samlPresent,
        String samlType,
        String samlStatus,
        boolean failureIndicated,
        String bodyHash) {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final List<String> FAILURE_TOKENS = List.of(
            "fail", "error", "invalid", "denied", "unable", "unsuccessful", "not able", "rejected");

    /** Shared classification for browser observations recorded outside a probe action. */
    public static boolean failureIndicated(int status, String body) {
        return status >= 400 || containsFailureToken(body == null ? "" : body);
    }

    static SloProbeObservation ofBrowserResponse(int status, String url, String body) {
        var text = body == null ? "" : body;
        var saml = SamlEmbeddedMessage.find(text).flatMap(SloProbeObservation::parse);
        return new SloProbeObservation(status, url == null ? "" : url,
                saml.isPresent(), saml.map(Saml::type).orElse(""), saml.map(Saml::status).orElse(""),
                status >= 400 || containsFailureToken(text), Integer.toHexString(text.hashCode()));
    }

    static SloProbeObservation ofSamlResponse(byte[] xml, int status, String url) {
        var saml = parse(xml);
        var text = xml == null ? "" : new String(xml, java.nio.charset.StandardCharsets.UTF_8);
        return new SloProbeObservation(status, url == null ? "" : url,
                saml.isPresent(), saml.map(Saml::type).orElse(""), saml.map(Saml::status).orElse(""),
                saml.map(value -> value.status() != null && !value.status().endsWith(":Success")).orElse(false),
                Integer.toHexString(text.hashCode()));
    }

    boolean samlSuccess() {
        return samlPresent && samlStatus != null && samlStatus.endsWith(":Success");
    }

    private static boolean containsFailureToken(String text) {
        var lower = text.toLowerCase(java.util.Locale.ROOT);
        return FAILURE_TOKENS.stream().anyMatch(lower::contains);
    }

    private static Optional<Saml> parse(byte[] xml) {
        if (xml == null || xml.length == 0) return Optional.empty();
        try {
            var root = SecureXml.parse(xml).getDocumentElement();
            if (!PROTOCOL.equals(root.getNamespaceURI())) return Optional.empty();
            var name = root.getLocalName();
            if (!"LogoutResponse".equals(name) && !"LogoutRequest".equals(name)) return Optional.empty();
            return Optional.of(new Saml(name, status(root)));
        } catch (RuntimeException unparsable) {
            return Optional.empty();
        }
    }

    private static String status(Element root) {
        var statuses = root.getElementsByTagNameNS(PROTOCOL, "StatusCode");
        return statuses.getLength() == 0 ? "" : ((Element) statuses.item(0)).getAttribute("Value");
    }

    private record Saml(String type, String status) {}

    Map<String, Object> diagnostics() {
        return Map.of("probe_http_status", httpStatus,
                "probe_saml", samlPresent ? samlType : "none",
                "probe_status", samlStatus == null ? "" : samlStatus,
                "probe_failure_indicated", failureIndicated);
    }
}
