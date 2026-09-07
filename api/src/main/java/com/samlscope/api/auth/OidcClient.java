package com.samlscope.api.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.*;
import com.nimbusds.oauth2.sdk.http.*;
import com.nimbusds.oauth2.sdk.id.*;
import com.nimbusds.oauth2.sdk.pkce.*;
import com.nimbusds.openid.connect.sdk.*;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/** Standard OIDC RP. No Test Peer parsers, outbound policy, or Recorder are used here. */
public final class OidcClient {
    @FunctionalInterface public interface Transport { HTTPResponse send(HTTPRequest request) throws IOException; }
    private final OidcConfig config;
    private final URI callback;
    private final Transport transport;
    private final OIDCProviderMetadata metadata;
    private final IDTokenValidator validator;

    public OidcClient(OidcConfig config, URI callback) {
        this(config, callback, OidcClient::sendBounded);
    }

    /** Transport injection permits local protocol fixtures without relaxing production TLS. */
    public OidcClient(OidcConfig config, URI callback, Transport transport) {
        this.config = config;
        this.callback = callback;
        this.transport = transport;
        OidcConfig.requireHttps(callback);
        try {
            var discovery = config.issuer().toString().replaceAll("/$", "") + "/.well-known/openid-configuration";
            metadata = OIDCProviderMetadata.parse(get(URI.create(discovery)).getContent());
            if (!metadata.getIssuer().getValue().equals(config.issuer().toString())) throw new IOException();
            OidcConfig.requireHttps(metadata.getAuthorizationEndpointURI());
            OidcConfig.requireHttps(metadata.getTokenEndpointURI());
            OidcConfig.requireHttps(metadata.getJWKSetURI());
            var algorithm = JWSAlgorithm.parse(config.signingAlgorithm());
            if (metadata.getIDTokenJWSAlgs() == null || !metadata.getIDTokenJWSAlgs().contains(algorithm)) {
                throw new IOException();
            }
            var methods = metadata.getTokenEndpointAuthMethods();
            var method = ClientAuthenticationMethod.parse(config.clientAuthMethod());
            if (methods != null && !methods.contains(method)) throw new IOException();
            validator = new IDTokenValidator(new Issuer(config.issuer().toString()),
                    new ClientID(config.clientId()), algorithm, metadata.getJWKSetURI().toURL(), url -> {
                        var response = get(URI.create(url.toString()));
                        return new Resource(response.getContent(), "application/json");
                    });
            validator.setMaxClockSkew(60);
        } catch (Exception failure) {
            // Provider documents and secrets must never appear in logs / API errors.
            throw new IllegalStateException("OIDC initialization failed; check issuer, client settings, and provider availability");
        }
    }

    public boolean requiresResponseIssuer() { return metadata.supportsAuthorizationResponseIssuerParam(); }

    public URI authorizationUri(String state, String nonce, String verifier) {
        return new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid", "profile"),
                new ClientID(config.clientId()), callback)
                .endpointURI(metadata.getAuthorizationEndpointURI())
                .state(new State(state)).nonce(new Nonce(nonce)).responseMode(ResponseMode.QUERY)
                .codeChallenge(new CodeVerifier(verifier), CodeChallengeMethod.S256).build().toURI();
    }

    public OidcIdentity exchange(String code, String nonce, String verifier) {
        try {
            ClientAuthentication authentication = config.clientAuthMethod().equals("client_secret_post")
                    ? new ClientSecretPost(new ClientID(config.clientId()), new Secret(config.clientSecret()))
                    : new ClientSecretBasic(new ClientID(config.clientId()), new Secret(config.clientSecret()));
            var request = new TokenRequest(metadata.getTokenEndpointURI(), authentication,
                    new AuthorizationCodeGrant(new AuthorizationCode(code), callback, new CodeVerifier(verifier)));
            var response = OIDCTokenResponseParser.parse(transport.send(request.toHTTPRequest()));
            if (!response.indicatesSuccess()) throw new SecurityException();
            var token = response.toSuccessResponse().getTokens().toOIDCTokens().getIDToken();
            if (!(token instanceof SignedJWT signed)
                    || !signed.getHeader().getAlgorithm().equals(JWSAlgorithm.parse(config.signingAlgorithm()))) {
                throw new SecurityException();
            }
            var claims = validator.validate(token, new Nonce(nonce));
            // Nimbus deliberately leaves azp policy to the RP.
            var jwtClaims = signed.getJWTClaimsSet();
            var azp = jwtClaims.getStringClaim("azp");
            if ((azp != null && !azp.equals(config.clientId()))
                    || (jwtClaims.getAudience().size() > 1 && azp == null)) throw new SecurityException();
            var nbf = jwtClaims.getNotBeforeTime();
            if (nbf != null && nbf.toInstant().isAfter(java.time.Instant.now().plusSeconds(60))) throw new SecurityException();
            return new OidcIdentity(claims.getIssuer().getValue(), claims.getSubject().getValue(),
                    jwtClaims.getStringClaim("name"));
        } catch (Exception failure) {
            throw new SecurityException("OIDC login could not be completed");
        }
    }

    private HTTPResponse get(URI uri) throws IOException {
        var response = transport.send(new HTTPRequest(HTTPRequest.Method.GET, uri));
        if (response.getStatusCode() != 200) throw new IOException("OIDC provider request failed");
        return response;
    }

    public static HTTPResponse sendBounded(HTTPRequest request) throws IOException {
        OidcConfig.requireHttps(request.getURI());
        request.setConnectTimeout(5_000);
        request.setReadTimeout(10_000);
        request.setFollowRedirects(false);
        var connection = request.toHttpURLConnection();
        try {
            var status = connection.getResponseCode();
            // Do not follow redirects, in particular with a client secret or authorization code.
            if (status >= 300 && status < 400) throw new IOException("OIDC redirects are not allowed");
            try (var body = status >= 400 ? connection.getErrorStream() : connection.getInputStream()) {
                var bytes = body == null ? new byte[0] : body.readNBytes(1024 * 1024 + 1);
                if (bytes.length > 1024 * 1024) throw new IOException("OIDC response is too large");
                var response = new HTTPResponse(status);
                response.setHeader("Content-Type", "application/json");
                response.setContent(new String(bytes, StandardCharsets.UTF_8));
                return response;
            }
        } finally {
            connection.disconnect();
        }
    }
}
