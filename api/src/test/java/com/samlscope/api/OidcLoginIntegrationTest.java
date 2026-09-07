package com.samlscope.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.api.auth.*;
import io.javalin.Javalin;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

class OidcLoginIntegrationTest {
    @TempDir Path data;
    final ObjectMapper json = new ObjectMapper();
    final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    Javalin app;
    URI base;
    URI publicBase;
    OidcProviderFixture provider;

    @ParameterizedTest @EnumSource(AppConfig.Mode.class)
    void loginGrantsOnlyOwnPlansAndLogoutRevokesSession(AppConfig.Mode mode) throws Exception {
        start(mode, OidcConfig.AccessPolicy.OPTIONAL);
        try {
            var alice = login("alice");
            assertEquals(200, call("GET", "/api/plans", null, alice, false).statusCode());
            assertEquals("[]", call("GET", "/api/plans", null, alice, false).body());
            assertEquals(403, call("POST", "/api/plans", plan("alice"), alice, false).statusCode());
            var created = call("POST", "/api/plans", plan("alice"), alice, true);
            assertEquals(201, created.statusCode(), created.body());
            var planId = json.readTree(created.body()).at("/plan/plan/id").asText();
            var runId = json.readTree(created.body()).at("/initialRun/run/id").asText();
            assertFalse(runId.isEmpty());
            assertEquals(200, call("GET", "/api/runs/" + runId, null, alice, false).statusCode());
            assertEquals(200, call("GET", "/api/plans/" + planId + "/runs", null, alice, false).statusCode());
            assertEquals(1, json.readTree(call("GET", "/api/plans", null, alice, false).body()).size());
            var bob = login("bob");
            assertEquals("[]", call("GET", "/api/plans", null, bob, false).body());
            for (var path : new String[]{"/api/plans/" + planId, "/api/plans/" + planId + "/runs",
                    "/api/runs/" + runId, "/api/runs/" + runId + "/transcript", "/api/runs/" + runId + "/result.json"}) {
                assertEquals(403, call("GET", path, null, bob, false).statusCode(), path);
                assertEquals(403, call("GET", path, null, null, false).statusCode(), path);
            }
            assertEquals(403, call("DELETE", "/api/plans/" + planId, null, bob, true).statusCode());
            assertEquals(403, call("POST", "/api/runs/" + runId + "/quick-check", "{}", bob, true).statusCode());
            assertEquals(403, call("POST", "/auth/logout", null, alice, false).statusCode());
            assertEquals(403, send("POST", "/auth/logout", null, alice.cookie(), alice.csrf(), "https://evil.example").statusCode());
            assertEquals(204, call("POST", "/auth/logout", null, alice, true).statusCode());
            assertEquals(403, call("GET", "/api/runs/" + runId, null, alice, false).statusCode());
            var aliceAgain = login("alice");
            assertEquals(200, call("GET", "/api/plans/" + planId, null, aliceAgain, false).statusCode());
            assertEquals(204, call("DELETE", "/api/plans/" + planId, null, aliceAgain, true).statusCode());
            assertEquals("[]", call("GET", "/api/plans", null, aliceAgain, false).body());
        } finally { app.stop(); }
    }

    @Test void callbackRequiresMatchingBrowserStateAndRejectsReplayAndProviderErrors() throws Exception {
        start(AppConfig.Mode.HOSTED, OidcConfig.AccessPolicy.OPTIONAL);
        try {
            var start = call("GET", "/auth/login", null, null, false);
            var authorization = URI.create(start.headers().firstValue("Location").orElseThrow());
            var query = OidcProviderFixture.query(authorization.getRawQuery());
            var code = provider.authorize(authorization, "alice");
            var path = "/auth/callback?code=" + code + "&state=" + query.get("state");
            assertEquals(400, call("GET", path, null, null, false).statusCode());
            assertEquals(0, provider.tokenCalls);
            var binding = cookie(start, OidcRoutes.LOGIN_COOKIE);
            assertEquals(400, send("GET", path + "&state=another", null, binding, null, null).statusCode());
            assertEquals(0, provider.tokenCalls);
            assertEquals(302, send("GET", path, null, binding, null, null).statusCode());
            assertEquals(400, send("GET", path, null, binding, null, null).statusCode());
            assertEquals(1, provider.tokenCalls);

            var next = call("GET", "/auth/login", null, null, false);
            var nextQuery = OidcProviderFixture.query(URI.create(next.headers().firstValue("Location").orElseThrow()).getRawQuery());
            var failed = send("GET", "/auth/callback?state=" + nextQuery.get("state")
                    + "&error=access_denied&error_description=do-not-echo", null, cookie(next, OidcRoutes.LOGIN_COOKIE), null, null);
            assertEquals(400, failed.statusCode());
            assertFalse(failed.body().contains("do-not-echo"));
            assertEquals("no-store", failed.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals(1, provider.tokenCalls);
            var peerOrigin = URI.create("http://localhost:" + base.getPort());
            var peerRequest = HttpRequest.newBuilder(peerOrigin.resolve("/auth/session")).GET().build();
            assertEquals(421, http.send(peerRequest, HttpResponse.BodyHandlers.ofString()).statusCode());
        } finally { app.stop(); }
    }

    @Test void checksResponseIssuerBeforeExchangingCode() throws Exception {
        start(AppConfig.Mode.HOSTED, OidcConfig.AccessPolicy.OPTIONAL);
        try {
            var response = call("GET", "/auth/login", null, null, false);
            var authorization = URI.create(response.headers().firstValue("Location").orElseThrow());
            var state = OidcProviderFixture.query(authorization.getRawQuery()).get("state");
            var code = provider.authorize(authorization, "alice");
            var failed = send("GET", "/auth/callback?state=" + state + "&code=" + code + "&iss=https://wrong.example",
                    null, cookie(response, OidcRoutes.LOGIN_COOKIE), null, null);
            assertEquals(400, failed.statusCode());
            assertEquals(0, provider.tokenCalls);
        } finally { app.stop(); }
    }

    @Test void optionalAnonymousRunsAreNotClaimedByLoginAndSecretLinksStillWork() throws Exception {
        start(AppConfig.Mode.HOSTED, OidcConfig.AccessPolicy.OPTIONAL);
        try {
            var created = call("POST", "/api/plans", plan("anonymous"), null, true);
            assertEquals(201, created.statusCode());
            var node = json.readTree(created.body());
            var runId = node.at("/initialRun/run/id").asText();
            var management = URI.create(node.at("/initialRun/managementUrl").asText());
            var alice = login("alice");
            assertEquals("[]", call("GET", "/api/plans", null, alice, false).body());
            assertEquals(403, call("GET", "/api/runs/" + runId, null, alice, false).statusCode());
            var exchanged = call("POST", "/api/manage/session", json.writeValueAsString(Map.of(
                    "runId", runId, "token", management.getFragment().substring(2))), null, true);
            assertEquals(200, exchanged.statusCode());
            assertEquals(200, send("GET", "/api/runs/" + runId, null,
                    cookie(exchanged, ManagementSessionRoutes.COOKIE_NAME), null, null).statusCode());
        } finally { app.stop(); }
    }

    @ParameterizedTest @EnumSource(value = OidcConfig.AccessPolicy.class, names = {"NEW_PLANS", "REQUIRED"})
    void enforcesConfiguredLoginRequirement(OidcConfig.AccessPolicy policy) throws Exception {
        start(AppConfig.Mode.HOSTED, policy);
        try {
            assertEquals(403, call("POST", "/api/plans", plan("anonymous"), null, true).statusCode());
            var alice = login("alice");
            var created = call("POST", "/api/plans", plan("alice"), alice, true);
            assertEquals(201, created.statusCode(), created.body());
            var node = json.readTree(created.body());
            var runId = node.at("/initialRun/run/id").asText();
            var management = URI.create(node.at("/initialRun/managementUrl").asText());
            var exchange = call("POST", "/api/manage/session", json.writeValueAsString(Map.of(
                    "runId", runId, "token", management.getFragment().substring(2))), null, true);
            assertEquals(policy == OidcConfig.AccessPolicy.REQUIRED ? 403 : 200, exchange.statusCode());
        } finally { app.stop(); }
    }

    @Test void ownershipSurvivesRestartButLoginSessionsDoNot() throws Exception {
        start(AppConfig.Mode.HOSTED, OidcConfig.AccessPolicy.OPTIONAL);
        var alice = login("alice");
        var created = call("POST", "/api/plans", plan("alice"), alice, true);
        var planId = json.readTree(created.body()).at("/plan/plan/id").asText();
        app.stop();
        start(AppConfig.Mode.HOSTED, OidcConfig.AccessPolicy.OPTIONAL);
        try {
            assertEquals(403, call("GET", "/api/plans/" + planId, null, alice, false).statusCode());
            var renewed = login("alice");
            assertEquals(200, call("GET", "/api/plans/" + planId, null, renewed, false).statusCode());
        } finally { app.stop(); }
    }

    void start(AppConfig.Mode mode, OidcConfig.AccessPolicy policy) throws Exception {
        int port;
        try (var socket = new ServerSocket(0)) { port = socket.getLocalPort(); }
        base = URI.create("http://127.0.0.1:" + port);
        publicBase = URI.create("https://127.0.0.1:" + port);
        provider = new OidcProviderFixture();
        var config = new AppConfig(mode, publicBase, URI.create("https://localhost:" + port), data, port,
                mode == AppConfig.Mode.SELFHOSTED, false, true, "sha256:" + "a".repeat(64), "127.0.0.1", provider.config(policy));
        app = SamlScopeApplication.create(config, new OidcClient(config.oidc(), publicBase.resolve("/auth/callback"), provider)).start(port);
    }
    Account login(String subject) throws Exception {
        var response = call("GET", "/auth/login", null, null, false);
        assertEquals(302, response.statusCode());
        var authorization = URI.create(response.headers().firstValue("Location").orElseThrow());
        var state = OidcProviderFixture.query(authorization.getRawQuery()).get("state");
        var code = provider.authorize(authorization, subject);
        var completed = send("GET", "/auth/callback?state=" + state + "&code=" + code, null,
                cookie(response, OidcRoutes.LOGIN_COOKIE), null, null);
        assertEquals(302, completed.statusCode(), completed.body());
        assertEquals("/", completed.headers().firstValue("Location").orElseThrow());
        var cookie = cookie(completed, OidcRoutes.COOKIE);
        var session = send("GET", "/auth/session", null, cookie, null, null);
        assertEquals("no-store", session.headers().firstValue("Cache-Control").orElseThrow());
        assertFalse(session.body().contains("never-expose-this-token"));
        assertFalse(session.body().contains("fixture-secret"));
        return new Account(cookie, json.readTree(session.body()).path("csrfToken").asText());
    }
    static String cookie(HttpResponse<String> response, String name) {
        var value = response.headers().allValues("Set-Cookie").stream()
                .filter(header -> header.startsWith(name + "=")).findFirst().orElseThrow();
        assertTrue(value.contains("Secure"));
        assertTrue(value.contains("HttpOnly"));
        assertTrue(value.contains("Path=/"));
        assertFalse(value.contains("Domain="));
        return value.split(";", 2)[0];
    }
    HttpResponse<String> call(String method, String path, String body, Account account, boolean csrf) throws Exception {
        return send(method, path, body, account == null ? null : account.cookie(),
                csrf && account != null ? account.csrf() : null, csrf ? publicBase.toString() : null);
    }
    HttpResponse<String> send(String method, String path, String body, String cookie, String csrf, String origin) throws Exception {
        var request = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(10));
        if (cookie != null) request.header("Cookie", cookie);
        if (csrf != null) request.header(OidcRoutes.CSRF_HEADER, csrf);
        if (origin != null) request.header("Origin", origin);
        if (body != null) request.header("Content-Type", "application/json");
        request.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
    String plan(String label) {
        return """
                {"name":"%s","profile":"IDP_CORE","targetKind":"IDP",
                 "targetEntityId":"https://%s.example/idp","metadataSourceKind":"URL",
                 "metadataSourceLocation":"https://%s.example/metadata","suiteMetadataDelivery":"MANUAL",
                 "declaredFeatures":{},"parameters":{"clockSkewToleranceSeconds":180,"metadataRefreshWaitSeconds":300,"testUserHint":""},
                 "interaction":{"allowBrowserSteps":true,"allowAttestation":true},"authorizedTarget":true}
                """.formatted(label, label, label);
    }
    record Account(String cookie, String csrf) {}
}
