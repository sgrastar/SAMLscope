package com.samlscope.saml.normal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Locates an embedded SAML message in a form body, an auto-submit page, or a redirect URL.
 * Detection is deliberately structural: callers decide what the message means.
 */
public final class SamlEmbeddedMessage {
    private static final String BASE64_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=%";

    private SamlEmbeddedMessage() {}

    public static Optional<byte[]> find(String text) {
        if (text == null || text.isEmpty()) return Optional.empty();
        for (var parameter : List.of("SAMLResponse", "SAMLRequest")) {
            var marker = parameter + "=";
            var index = text.indexOf(marker);
            while (index >= 0) {
                var start = index + marker.length();
                var end = start;
                while (end < text.length() && BASE64_CHARS.indexOf(text.charAt(end)) >= 0) end++;
                var decoded = decode(text.substring(start, end));
                if (decoded.isPresent()) return decoded;
                index = text.indexOf(marker, index + marker.length());
            }
            var input = Pattern.compile("(?is)<input[^>]*name\\s*=\\s*[\"']?" + parameter + "[\"']?[^>]*>")
                    .matcher(text);
            while (input.find()) {
                var value = Pattern.compile("(?is)value\\s*=\\s*[\"']([^\"']+)[\"']").matcher(input.group());
                if (!value.find()) continue;
                var decoded = decode(value.group(1));
                if (decoded.isPresent()) return decoded;
            }
        }
        var trimmed = text.strip();
        if (trimmed.startsWith("<")
                && (trimmed.contains("LogoutResponse") || trimmed.contains("LogoutRequest")
                        || trimmed.contains("AuthnRequest"))) {
            return Optional.of(trimmed.getBytes(StandardCharsets.UTF_8));
        }
        return Optional.empty();
    }

    private static Optional<byte[]> decode(String encoded) {
        // HTML attributes carry raw Base64 ("+" stays "+"); form bodies URL-encode it.
        for (var candidate : List.of(encoded, java.net.URLDecoder.decode(encoded, StandardCharsets.UTF_8))) {
            try {
                var decoded = Base64.getMimeDecoder().decode(candidate);
                if (decoded.length > 0 && decoded[0] == '<') return Optional.of(decoded);
            } catch (IllegalArgumentException ignored) {
                // Try the other interpretation.
            }
        }
        return Optional.empty();
    }
}
