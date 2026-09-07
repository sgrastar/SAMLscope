package com.samlscope.api;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;

public record AppConfig(
        Mode mode,
        URI publicBaseUrl,
        URI peerBaseUrl,
        Path dataDirectory,
        int httpPort,
        boolean outboundAllowPrivate,
        boolean outboundAllowInsecureTls,
        boolean publishEnabled,
        String suiteImageDigest,
        String trustedProxyAddress,
        com.samlscope.api.auth.OidcConfig oidc) {
    private static final Logger LOG = Logger.getLogger(AppConfig.class.getName());

    public AppConfig {
        Objects.requireNonNull(oidc, "oidc");
        validateBaseUrl(publicBaseUrl, "publicBaseUrl");
        validateBaseUrl(peerBaseUrl, "peerBaseUrl");
        if (oidc.enabled()) {
            com.samlscope.api.auth.OidcConfig.requireHttps(publicBaseUrl);
            if (publicBaseUrl.getHost().equalsIgnoreCase(peerBaseUrl.getHost())) {
                throw new IllegalArgumentException("OIDC requires separate app and peer hostnames; cookies are not isolated by port");
            }
        }
        if (httpPort < 1 || httpPort > 65535) throw new IllegalArgumentException("Invalid HTTP port");
        if (mode == Mode.HOSTED && sameOrigin(publicBaseUrl, peerBaseUrl)) {
            throw new IllegalArgumentException("Hosted mode requires separate app and peer origins");
        }
        if (mode == Mode.HOSTED && (!"https".equalsIgnoreCase(publicBaseUrl.getScheme())
                || !"https".equalsIgnoreCase(peerBaseUrl.getScheme()))) {
            throw new IllegalArgumentException("Hosted mode requires HTTPS app and peer origins");
        }
        if (mode == Mode.HOSTED && outboundAllowPrivate) {
            throw new IllegalArgumentException("Hosted mode cannot allow private outbound destinations");
        }
        if (mode == Mode.HOSTED && outboundAllowInsecureTls) {
            throw new IllegalArgumentException("Hosted mode cannot disable outbound TLS verification");
        }
        suiteImageDigest = suiteImageDigest == null ? "" : suiteImageDigest;
        if (!suiteImageDigest.isEmpty() && !suiteImageDigest.matches("sha256:[0-9a-f]{64}")) {
            throw new IllegalArgumentException("suiteImageDigest must be a lowercase SHA-256 digest");
        }
        if (mode == Mode.HOSTED && suiteImageDigest.isEmpty()) {
            throw new IllegalArgumentException("Hosted mode requires SAMLSCOPE_IMAGE_DIGEST");
        }
        trustedProxyAddress = trustedProxyAddress == null ? "" : trustedProxyAddress.trim();
        if (!trustedProxyAddress.isEmpty()) {
            trustedProxyAddress = TrustedProxyClientAddress.canonicalAddress(trustedProxyAddress);
        }
        if (mode == Mode.HOSTED && trustedProxyAddress.isEmpty()) {
            throw new IllegalArgumentException(
                    "Hosted mode requires SAMLSCOPE_TRUSTED_PROXY_ADDRESS");
        }
    }

    public boolean managementProtected() { return mode == Mode.HOSTED || oidc.enabled(); }

    public AppConfig(Mode mode, URI publicBaseUrl, URI peerBaseUrl, Path dataDirectory, int httpPort,
                     boolean outboundAllowPrivate, boolean outboundAllowInsecureTls, boolean publishEnabled,
                     String suiteImageDigest, String trustedProxyAddress) {
        this(mode, publicBaseUrl, peerBaseUrl, dataDirectory, httpPort, outboundAllowPrivate,
                outboundAllowInsecureTls, publishEnabled, suiteImageDigest, trustedProxyAddress,
                com.samlscope.api.auth.OidcConfig.disabled());
    }

    public AppConfig(
            Mode mode, URI publicBaseUrl, URI peerBaseUrl, Path dataDirectory, int httpPort,
            boolean outboundAllowPrivate, boolean outboundAllowInsecureTls, boolean publishEnabled) {
        this(mode, publicBaseUrl, peerBaseUrl, dataDirectory, httpPort, outboundAllowPrivate,
                outboundAllowInsecureTls, publishEnabled, "", "");
    }

    public static AppConfig fromEnvironment() { return from(System.getenv()); }

    static AppConfig from(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        var mode = Mode.valueOf(resolve(environment, "MODE", "selfhosted").toUpperCase(Locale.ROOT));
        var publicBase = URI.create(resolve(environment, "PUBLIC_BASE_URL", "http://localhost:8080"));
        var peerBase = URI.create(resolve(environment, "PEER_BASE_URL", publicBase.toString()));
        var data = Path.of(resolve(environment, "DATA_DIR", "/data"));
        var port = Integer.parseInt(resolve(environment, "HTTP_PORT", "8080"));
        var allowPrivate = Boolean.parseBoolean(resolve(
                environment, "OUTBOUND_ALLOW_PRIVATE", mode == Mode.SELFHOSTED ? "true" : "false"));
        var insecureTls = Boolean.parseBoolean(resolve(
                environment, "OUTBOUND_ALLOW_INSECURE_TLS", "false"));
        var publish = Boolean.parseBoolean(resolve(
                environment, "PUBLISH_ENABLED", mode == Mode.HOSTED ? "true" : "false"));
        var imageDigest = resolve(environment, "IMAGE_DIGEST", "");
        var trustedProxy = resolve(environment, "TRUSTED_PROXY_ADDRESS", "");
        return new AppConfig(
                mode, publicBase, peerBase, data, port, allowPrivate, insecureTls, publish,
                imageDigest, trustedProxy, com.samlscope.api.auth.OidcConfig.from(environment));
    }

    private static String resolve(Map<String, String> environment, String suffix, String defaultValue) {
        var currentName = "SAMLSCOPE_" + suffix;
        var legacyName = "SAMLIER_" + suffix;
        var currentPresent = environment.containsKey(currentName);
        var legacyPresent = environment.containsKey(legacyName);
        var current = environment.get(currentName);
        var legacy = environment.get(legacyName);
        if (currentPresent && legacyPresent && !Objects.equals(current, legacy)) {
            throw new IllegalArgumentException(
                    "Conflicting environment variables " + currentName + " and " + legacyName);
        }
        if (legacyPresent) {
            LOG.warning(legacyName + " is deprecated; migrate to " + currentName);
        }
        if (currentPresent) return Objects.requireNonNull(current, currentName);
        if (legacyPresent) return Objects.requireNonNull(legacy, legacyName);
        return defaultValue;
    }

    private static boolean sameOrigin(URI left, URI right) {
        return left.getScheme().equalsIgnoreCase(right.getScheme())
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private static void validateBaseUrl(URI uri, String name) {
        if (uri == null || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null
                || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) {
            throw new IllegalArgumentException(name + " must be an absolute HTTP(S) URL without credentials, query, or fragment");
        }
        if (uri.getPath() != null && !uri.getPath().isEmpty() && !"/".equals(uri.getPath())) {
            throw new IllegalArgumentException(name + " must be an origin without a path");
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    public enum Mode { SELFHOSTED, HOSTED }
}
