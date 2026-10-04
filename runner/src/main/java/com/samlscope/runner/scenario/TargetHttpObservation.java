package com.samlscope.runner.scenario;

import java.net.URI;
import java.util.Locale;

/** Strict origin check for Recorder-backed browser terminal observations. */
public final class TargetHttpObservation {
    private TargetHttpObservation() {}

    /**
     * Returns whether the browser ended on an HTTP error owned by the target origin. Paths,
     * queries, fragments, and response bodies are deliberately irrelevant.
     */
    public static boolean isSameOriginError(URI target, int httpStatus, String observedUrl) {
        if (target == null || httpStatus < 400 || httpStatus > 599
                || observedUrl == null || observedUrl.isBlank()) {
            return false;
        }
        final URI observed;
        try {
            observed = URI.create(observedUrl);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        if (!httpOrigin(target) || !httpOrigin(observed)) return false;
        return target.getScheme().equalsIgnoreCase(observed.getScheme())
                && target.getHost().equalsIgnoreCase(observed.getHost())
                && effectivePort(target) == effectivePort(observed);
    }

    private static boolean httpOrigin(URI value) {
        if (!value.isAbsolute() || value.isOpaque() || value.getHost() == null) return false;
        var scheme = value.getScheme().toLowerCase(Locale.ROOT);
        return "http".equals(scheme) || "https".equals(scheme);
    }

    private static int effectivePort(URI value) {
        if (value.getPort() >= 0) return value.getPort();
        return "https".equalsIgnoreCase(value.getScheme()) ? 443 : 80;
    }
}
