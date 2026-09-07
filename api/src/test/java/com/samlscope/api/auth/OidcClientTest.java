package com.samlscope.api.auth;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class OidcClientTest {
    private static final URI CALLBACK = URI.create("https://app.example/auth/callback");
    private final String verifier = "v".repeat(43);
    @Test void exchangesCodeWithPkceAndUsesStableIssuerSubjectIdentity() throws Exception {
        var provider = new OidcProviderFixture();
        var client = client(provider);
        var identity = login(client, provider);
        assertEquals(provider.issuer, identity.issuer());
        assertEquals("alice", identity.subject());
        assertEquals("Test user", identity.displayName());
        assertNotEquals(identity.ownerId(), new OidcIdentity("https://other.example", "alice", "Test user").ownerId());
        assertEquals(identity.ownerId(), new OidcIdentity(provider.issuer, "alice", "Renamed").ownerId());
    }
    @Test void refreshesJwksForRotatedSigningKey() throws Exception {
        var provider = new OidcProviderFixture();
        var client = client(provider);
        login(client, provider);
        var calls = provider.jwksCalls;
        login(client, provider);
        assertEquals(calls, provider.jwksCalls);
        provider.rotateKey();
        login(client, provider);
        assertTrue(provider.jwksCalls > calls);
    }
    @ParameterizedTest @ValueSource(strings = {"nonce", "missing_nonce", "issuer", "audience", "expired", "future_iat", "missing_exp", "missing_sub", "empty_sub", "azp", "multi_aud", "future_nbf"})
    void rejectsInvalidClaims(String kind) throws Exception {
        var provider = new OidcProviderFixture();
        provider.customize = switch (kind) {
            case "nonce" -> c -> c.claim("nonce", "wrong");
            case "missing_nonce" -> c -> c.claim("nonce", null);
            case "issuer" -> c -> c.issuer("https://wrong.example");
            case "audience" -> c -> c.audience("another-client");
            case "expired" -> c -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)));
            case "future_iat" -> c -> c.issueTime(Date.from(Instant.now().plusSeconds(120)));
            case "missing_exp" -> c -> c.expirationTime(null);
            case "missing_sub" -> c -> c.subject(null);
            case "empty_sub" -> c -> c.subject("");
            case "azp" -> c -> c.claim("azp", "another-client");
            case "multi_aud" -> c -> c.audience(List.of("samlscope", "another-client"));
            case "future_nbf" -> c -> c.notBeforeTime(Date.from(Instant.now().plusSeconds(120)));
            default -> throw new AssertionError();
        };
        var client = client(provider);
        assertThrows(SecurityException.class, () -> login(client, provider));
    }
    @Test void rejectsUnsignedTokensAndUntrustedKeysAndTokenErrors() throws Exception {
        var provider = new OidcProviderFixture();
        var client = client(provider);
        provider.unsigned = true;
        assertThrows(SecurityException.class, () -> login(client, provider));
        provider.unsigned = false;
        provider.signingKey = new OidcProviderFixture().key;
        assertThrows(SecurityException.class, () -> login(client, provider));
        provider.tokenError = true;
        var failure = assertThrows(SecurityException.class, () -> login(client, provider));
        assertFalse(failure.getMessage().contains("secret-detail"));
    }
    @Test void honorsDiscoveryResponseIssuerRequirement() throws Exception {
        var provider = new OidcProviderFixture();
        assertFalse(client(provider).requiresResponseIssuer());
        provider.responseIssuerSupported = true;
        assertTrue(client(provider).requiresResponseIssuer());
    }
    @Test void supportsClientSecretPost() throws Exception {
        var provider = new OidcProviderFixture();
        var config = provider.config(OidcConfig.AccessPolicy.OPTIONAL);
        var client = new OidcClient(new OidcConfig(config.issuer(), config.clientId(), config.clientSecret(),
                "client_secret_post", "RS256", config.accessPolicy()), CALLBACK, provider);
        assertEquals("alice", login(client, provider).subject());
    }
    @Test void failsClosedOnIssuerMismatchAndInsecureDiscoveredEndpoints() throws Exception {
        var provider = new OidcProviderFixture();
        provider.discoveryIssuer = "https://other.example";
        assertThrows(IllegalStateException.class, () -> client(provider));
        provider.discoveryIssuer = provider.issuer;
        provider.tokenEndpoint = "http://idp.example/token";
        assertThrows(IllegalStateException.class, () -> client(provider));
    }
    private OidcClient client(OidcProviderFixture provider) {
        return new OidcClient(provider.config(OidcConfig.AccessPolicy.OPTIONAL), CALLBACK, provider);
    }
    private OidcIdentity login(OidcClient client, OidcProviderFixture provider) {
        var code = provider.authorize(client.authorizationUri("s".repeat(43), "n".repeat(43), verifier), "alice");
        return client.exchange(code, "n".repeat(43), verifier);
    }
}
