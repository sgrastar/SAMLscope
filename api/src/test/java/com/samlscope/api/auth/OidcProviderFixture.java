package com.samlscope.api.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;
import static org.junit.jupiter.api.Assertions.*;

/** A standard OIDC provider fixture: real signed tokens, discovery and PKCE code exchange. */
public final class OidcProviderFixture implements OidcClient.Transport {
    public String issuer = "https://idp.example/tenant";
    public String discoveryIssuer = issuer;
    public String tokenEndpoint = issuer + "/token";
    public RSAKey key;
    public RSAKey signingKey;
    public int tokenCalls;
    public int jwksCalls;
    public boolean tokenError;
    public boolean unsigned;
    public boolean responseIssuerSupported;
    public Consumer<JWTClaimsSet.Builder> customize = claims -> {};
    private final Map<String, Map<String, String>> codes = new HashMap<>();
    private final ObjectMapper json = new ObjectMapper();
    public OidcProviderFixture() throws Exception { rotateKey(); }
    public void rotateKey() throws Exception {
        key = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).generate();
        signingKey = key;
    }
    public OidcConfig config(OidcConfig.AccessPolicy policy) {
        return new OidcConfig(URI.create(issuer), "samlscope", "fixture-secret", "client_secret_basic", "RS256", policy);
    }
    public String authorize(URI authorization, String subject) {
        var params = query(authorization.getRawQuery());
        assertEquals(issuer + "/authorize", authorization.toString().split("\\?")[0]);
        assertEquals("code", params.get("response_type"));
        assertEquals("S256", params.get("code_challenge_method"));
        assertEquals("query", params.get("response_mode"));
        assertTrue(params.get("scope").contains("openid"));
        assertNotNull(params.get("nonce"));
        var code = UUID.randomUUID().toString();
        params.put("subject", subject);
        codes.put(code, params);
        return code;
    }
    @Override public HTTPResponse send(HTTPRequest request) throws java.io.IOException {
        try {
            var uri = request.getURI().toString();
            if (uri.endsWith("/.well-known/openid-configuration")) {
                return response(200, Map.of("issuer", discoveryIssuer, "authorization_endpoint", issuer + "/authorize",
                        "token_endpoint", tokenEndpoint, "jwks_uri", issuer + "/jwks", "response_types_supported", List.of("code"),
                        "subject_types_supported", List.of("public"), "id_token_signing_alg_values_supported", List.of("RS256"),
                        "token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"),
                        "authorization_response_iss_parameter_supported", responseIssuerSupported));
            }
            if (uri.equals(issuer + "/jwks")) {
                jwksCalls++;
                return response(200, Map.of("keys", List.of(key.toPublicJWK().toJSONObject())));
            }
            if (uri.equals(issuer + "/token")) {
                tokenCalls++;
                assertEquals(HTTPRequest.Method.POST, request.getMethod());
                var values = query(request.getQuery());
                if (request.getAuthorization() != null) {
                    assertEquals("Basic " + Base64.getEncoder().encodeToString(
                            "samlscope:fixture-secret".getBytes(StandardCharsets.UTF_8)), request.getAuthorization());
                } else {
                    assertEquals("samlscope", values.get("client_id"));
                    assertEquals("fixture-secret", values.get("client_secret"));
                }
                var authorized = codes.remove(values.get("code"));
                if (tokenError || authorized == null) return response(400, Map.of("error", "invalid_grant", "error_description", "secret-detail"));
                assertEquals(authorized.get("redirect_uri"), values.get("redirect_uri"));
                assertEquals(authorized.get("code_challenge"), CodeChallenge.compute(CodeChallengeMethod.S256,
                        new CodeVerifier(values.get("code_verifier"))).getValue());
                var claims = new JWTClaimsSet.Builder().issuer(issuer).subject(authorized.get("subject"))
                        .audience("samlscope").issueTime(Date.from(Instant.now()))
                        .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                        .claim("nonce", authorized.get("nonce")).claim("name", "Test user");
                customize.accept(claims);
                var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), claims.build());
                jwt.sign(new RSASSASigner(signingKey));
                var token = unsigned ? new com.nimbusds.jwt.PlainJWT(claims.build()).serialize() : jwt.serialize();
                return response(200, Map.of("token_type", "Bearer", "access_token", "never-expose-this-token", "id_token", token));
            }
            throw new java.io.IOException("Unexpected fixture endpoint");
        } catch (java.io.IOException failure) { throw failure; }
        catch (Exception failure) { throw new java.io.IOException(failure); }
    }
    private HTTPResponse response(int status, Object body) throws Exception {
        var response = new HTTPResponse(status);
        response.setHeader("Content-Type", "application/json");
        response.setContent(json.writeValueAsString(body));
        return response;
    }
    public static Map<String, String> query(String query) {
        var result = new HashMap<String, String>();
        for (var part : query.split("&")) {
            var pair = part.split("=", 2);
            result.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8));
        }
        return result;
    }
}
