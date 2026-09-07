package com.samlscope.api;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class OidcAppConfigTest {
    @Test void oidcIsOptInAndIncompleteConfigurationFailsClosed() {
        assertFalse(AppConfig.from(Map.of()).oidc().enabled());
        assertThrows(IllegalArgumentException.class, () -> AppConfig.from(Map.of("SAMLSCOPE_OIDC_CLIENT_ID", "app")));
        var config = AppConfig.from(environment());
        assertTrue(config.managementProtected());
        assertEquals("RS256", config.oidc().signingAlgorithm());
        assertFalse(config.toString().contains("do-not-log-me"));
        var missing = environment();
        missing.remove("SAMLSCOPE_OIDC_CLIENT_SECRET");
        assertThrows(IllegalArgumentException.class, () -> AppConfig.from(missing));
    }
    @Test void oidcRequiresHttpsAndCookieIsolationEvenForSelfHosted() {
        var env = environment();
        env.put("SAMLSCOPE_PUBLIC_BASE_URL", "http://app.example");
        assertThrows(IllegalArgumentException.class, () -> AppConfig.from(env));
        env.put("SAMLSCOPE_PUBLIC_BASE_URL", "https://app.example:8443");
        env.put("SAMLSCOPE_PEER_BASE_URL", "https://app.example:9443");
        assertThrows(IllegalArgumentException.class, () -> AppConfig.from(env));
    }
    @Test void rejectsInsecureOrAmbiguousIssuerAndUnsafeAlgorithms() {
        for (var issuer : new String[]{"http://idp.example", "https://user:pass@idp.example", "https://idp.example/#fragment", "https://idp.example/?query=x"}) {
            var env = environment();
            env.put("SAMLSCOPE_OIDC_ISSUER", issuer);
            assertThrows(IllegalArgumentException.class, () -> AppConfig.from(env));
        }
        for (var algorithm : new String[]{"none", "HS256", "wrong"}) {
            var env = environment();
            env.put("SAMLSCOPE_OIDC_SIGNING_ALGORITHM", algorithm);
            assertThrows(IllegalArgumentException.class, () -> AppConfig.from(env));
        }
    }
    private HashMap<String, String> environment() {
        return new HashMap<>(Map.of("SAMLSCOPE_PUBLIC_BASE_URL", "https://app.example",
                "SAMLSCOPE_PEER_BASE_URL", "https://peer.example", "SAMLSCOPE_OIDC_ISSUER", "https://idp.example/tenant",
                "SAMLSCOPE_OIDC_CLIENT_ID", "app", "SAMLSCOPE_OIDC_CLIENT_SECRET", "do-not-log-me"));
    }
}
