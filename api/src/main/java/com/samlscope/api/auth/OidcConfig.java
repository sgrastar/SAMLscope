package com.samlscope.api.auth;

import java.net.URI;
import java.util.Map;
import java.util.Set;

/** Operator-supplied, single-issuer OIDC configuration. Never log the client secret. */
public record OidcConfig(URI issuer, String clientId, String clientSecret,
                         String clientAuthMethod, String signingAlgorithm, AccessPolicy accessPolicy) {
    public enum AccessPolicy { OPTIONAL, NEW_PLANS, REQUIRED }

    public OidcConfig {
        if (issuer != null) {
            requireHttps(issuer);
            if (issuer.getQuery() != null) throw new IllegalArgumentException("OIDC issuer cannot contain a query");
            if (clientId == null || clientId.isBlank() || clientSecret == null || clientSecret.isBlank()) {
                throw new IllegalArgumentException("OIDC requires a client ID and client secret");
            }
            if (!Set.of("client_secret_basic", "client_secret_post").contains(clientAuthMethod)) {
                throw new IllegalArgumentException("Unsupported OIDC client authentication method");
            }
            if (!Set.of("RS256", "PS256", "ES256").contains(signingAlgorithm)) {
                throw new IllegalArgumentException("OIDC signing algorithm must be RS256, PS256, or ES256");
            }
        }
        if (accessPolicy == null) throw new IllegalArgumentException("OIDC access policy is required");
    }

    public boolean enabled() { return issuer != null; }
    public static OidcConfig disabled() {
        return new OidcConfig(null, "", "", "client_secret_basic", "RS256", AccessPolicy.OPTIONAL);
    }
    public static OidcConfig from(Map<String, String> env) {
        if (env.keySet().stream().noneMatch(key -> key.startsWith("SAMLSCOPE_OIDC_"))) return disabled();
        var issuer = env.get("SAMLSCOPE_OIDC_ISSUER");
        if (issuer == null || issuer.isBlank()) throw new IllegalArgumentException("SAMLSCOPE_OIDC_ISSUER is required");
        return new OidcConfig(URI.create(issuer), env.get("SAMLSCOPE_OIDC_CLIENT_ID"),
                env.get("SAMLSCOPE_OIDC_CLIENT_SECRET"),
                env.getOrDefault("SAMLSCOPE_OIDC_CLIENT_AUTH_METHOD", "client_secret_basic"),
                env.getOrDefault("SAMLSCOPE_OIDC_SIGNING_ALGORITHM", "RS256"),
                AccessPolicy.valueOf(env.getOrDefault("SAMLSCOPE_OIDC_ACCESS_POLICY", "optional")
                        .toUpperCase(java.util.Locale.ROOT)));
    }
    public static void requireHttps(URI uri) {
        if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("OIDC endpoints must use HTTPS without credentials or fragments");
        }
    }
    @Override public String toString() {
        return "OidcConfig[issuer=" + issuer + ", clientId=" + clientId + ", clientSecret=<redacted>, policy=" + accessPolicy + "]";
    }
}
