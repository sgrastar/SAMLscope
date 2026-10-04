package com.samlscope.runner.cases;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

/** Exact, unambiguous observation correlation; never used to reconstruct signed query bytes. */
final class MetadataProbeCorrelation {
    private MetadataProbeCorrelation() {}

    static boolean signatureControl(com.samlscope.core.transcript.TranscriptEntry entry) {
        return entry.samlSummary().get("metadataSignatureControl") instanceof String value
                && !"valid".equals(value);
    }

    static boolean matches(String url, String runId, String variant) {
        if (url == null) return false;
        try {
            var query = URI.create(url).getRawQuery();
            if (query == null) return false;
            var values = new HashMap<String, String>();
            for (var part : query.split("&", -1)) {
                var pair = part.split("=", 2);
                var key = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                if (!key.equals("mdv") && !key.equals("run")) continue;
                if (pair.length != 2 || values.containsKey(key)) return false;
                values.put(key, URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
            }
            return runId.equals(values.get("run")) && variant.equals(values.get("mdv"));
        } catch (IllegalArgumentException invalidUriOrEncoding) {
            return false;
        }
    }
}
