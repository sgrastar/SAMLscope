package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HostedPlanAccessTest {
    @TempDir Path dataDirectory;
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void hostedPlansAndRunsAreScopedToTheManagementSession() throws Exception {
        var port = availablePort();
        var appOrigin = "https://127.0.0.1:" + port;
        var config = new AppConfig(
                AppConfig.Mode.HOSTED, URI.create(appOrigin), URI.create("https://peer.example"),
                dataDirectory, port, false, false, true,
                "sha256:" + "a".repeat(64), "127.0.0.1");
        var app = SamlScopeApplication.create(config).start(port);
        try {
            var base = URI.create("http://127.0.0.1:" + port);
            var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
            var first = createPlan(client, base, "First", "https://first.internal.example/idp",
                    "https://first.internal.example/metadata", "svc-user / secret-value");
            assertEquals(201, first.statusCode(), first.body());
            assertFalse(first.body().contains("testUserHint"));
            assertFalse(first.body().contains("metadataSource"));
            assertFalse(first.body().contains("secret-value"));
            assertFalse(first.body().contains("first.internal.example/metadata"));
            var firstJson = json.readTree(first.body());
            var planId = firstJson.at("/plan/plan/id").asText();
            var runId = firstJson.at("/initialRun/run/id").asText();
            var managementUrl = URI.create(firstJson.at("/initialRun/managementUrl").asText());
            assertTrue(managementUrl.toString().contains("/manage/" + runId + "#t="));

            var duplicateTarget = createPlan(client, base, "Duplicate target",
                    "https://first.internal.example/idp",
                    "https://duplicate.example/metadata", "duplicate-secret");
            assertEquals(429, duplicateTarget.statusCode(), duplicateTarget.body());
            assertFalse(duplicateTarget.body().contains("managementUrl"));
            assertFalse(duplicateTarget.body().contains("plan_"));

            var second = createPlan(client, base, "Second", "https://second.example/idp",
                    "https://second.example/metadata", "another-secret");
            var secondJson = json.readTree(second.body());
            var secondPlanId = secondJson.at("/plan/plan/id").asText();
            var secondRunId = secondJson.at("/initialRun/run/id").asText();
            var secondManagementUrl = URI.create(secondJson.at("/initialRun/managementUrl").asText());
            var secondExchange = request(client, base, "POST", "/api/manage/session",
                    "{\"runId\":\"" + secondRunId + "\",\"token\":\""
                            + secondManagementUrl.getFragment().substring(2) + "\"}",
                    null, null, appOrigin);
            assertEquals(200, secondExchange.statusCode(), secondExchange.body());
            var secondCookie = secondExchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            var secondCsrf = json.readTree(secondExchange.body()).path("csrfToken").asText();
            var retarget = request(client, base, "PUT", "/api/plans/" + secondPlanId,
                    planBody("Second", "https://first.internal.example/idp",
                            "https://second.example/metadata", "another-secret"),
                    secondCookie, secondCsrf, null);
            assertEquals(409, retarget.statusCode(), retarget.body());
            var unchangedSecond = request(client, base, "GET", "/api/plans/" + secondPlanId,
                    null, secondCookie, null, null);
            assertEquals(200, unchangedSecond.statusCode(), unchangedSecond.body());
            assertTrue(unchangedSecond.body().contains("https://second.example/idp"));
            assertFalse(unchangedSecond.body().contains("https://first.internal.example/idp"));

            assertDenied(client, base, "GET", "/api/plans", null, null, null);
            assertDenied(client, base, "GET", "/api/plans/" + planId, null, null, null);
            assertDenied(client, base, "PUT", "/api/plans/" + planId,
                    planBody("Changed", "https://first.internal.example/idp",
                            "https://first.internal.example/metadata", "secret"), null, null);
            assertDenied(client, base, "DELETE", "/api/plans/" + planId, null, null, null);
            assertDenied(client, base, "GET", "/api/plans/" + planId + "/runs", null, null, null);
            assertDenied(client, base, "POST", "/api/plans/" + planId + "/runs", "{}", null, null);
            assertDenied(client, base, "GET", "/api/runs/" + runId, null, null, null);
            assertDenied(client, base, "POST", "/api/runs/" + runId + "/preflight", "{}", null, null);
            assertDenied(client, base, "GET", "/api/runs/" + runId + "/events", null, null, null);

            var token = managementUrl.getFragment().substring(2);
            var exchange = request(client, base, "POST", "/api/manage/session",
                    "{\"runId\":\"" + runId + "\",\"token\":\"" + token + "\"}",
                    null, null, appOrigin);
            assertEquals(200, exchange.statusCode(), exchange.body());
            var cookie = exchange.headers().firstValue("Set-Cookie").orElseThrow().split(";", 2)[0];
            var csrf = json.readTree(exchange.body()).path("csrfToken").asText();

            var workspacePath = "/api/runs/" + runId + "/workspace-evidence";
            assertDenied(client, base, "GET", workspacePath, null, null, null);
            assertDenied(client, base, "GET", workspacePath, null, secondCookie, null);
            for (int i = 0; i < 4; i++) {
                var workspace = request(client, base, "GET", workspacePath, null, cookie, null, null);
                assertEquals(200, workspace.statusCode(), workspace.body());
                assertEquals("no-store", workspace.headers().firstValue("Cache-Control").orElseThrow());
                var snapshot = json.readTree(workspace.body());
                for (var section : new String[] { "interactions", "bootstrapContracts",
                        "protocolEvidence", "activeProbe", "campaigns" }) assertTrue(snapshot.has(section));
            }
            assertEquals(429, request(client, base, "GET", workspacePath, null, cookie, null, null).statusCode());

            var resumeBody = "{\"runId\":\"" + runId + "\",\"resume\":true}";
            var resumed = request(client, base, "POST", "/api/manage/session",
                    resumeBody, cookie, null, appOrigin);
            assertEquals(200, resumed.statusCode(), resumed.body());
            assertTrue(resumed.headers().firstValue("Set-Cookie").isEmpty());
            assertEquals("no-store", resumed.headers().firstValue("Cache-Control").orElseThrow());
            var resumedCsrf = json.readTree(resumed.body()).path("csrfToken").asText();
            assertFalse(resumedCsrf.equals(csrf));
            assertEquals(403, request(client, base, "POST", "/api/manage/session",
                    resumeBody, secondCookie, null, appOrigin).statusCode());
            assertEquals(403, request(client, base, "POST", "/api/manage/session",
                    resumeBody, null, null, appOrigin).statusCode());
            assertEquals(403, request(client, base, "POST", "/api/manage/session",
                    resumeBody, cookie, null, "https://peer.example").statusCode());
            assertEquals(200, request(client, base, "PUT", "/api/plans/" + planId,
                    planBody("Resumed", "https://first.internal.example/idp",
                            "https://first.internal.example/metadata", "secret"),
                    cookie, resumedCsrf, null).statusCode());

            var visiblePlans = request(client, base, "GET", "/api/plans", null, cookie, null, null);
            assertEquals(200, visiblePlans.statusCode(), visiblePlans.body());
            assertTrue(visiblePlans.body().contains(planId));
            assertFalse(visiblePlans.body().contains(secondPlanId));
            assertFalse(visiblePlans.body().contains("testUserHint"));
            assertFalse(visiblePlans.body().contains("metadataSource"));
            assertEquals(200, request(client, base, "GET", "/api/plans/" + planId,
                    null, cookie, null, null).statusCode());
            assertEquals(200, request(client, base, "GET", "/api/plans/" + planId + "/runs",
                    null, cookie, null, null).statusCode());
            assertEquals(200, request(client, base, "GET", "/api/runs/" + runId,
                    null, cookie, null, null).statusCode());

            assertDenied(client, base, "PUT", "/api/plans/" + planId,
                    planBody("Changed", "https://first.internal.example/idp",
                            "https://first.internal.example/metadata", "secret"), cookie, null);
            assertDenied(client, base, "DELETE", "/api/plans/" + secondPlanId, null, cookie, csrf);
            assertEquals(200, request(client, base, "PUT", "/api/plans/" + planId,
                    planBody("Changed", "https://first.internal.example/idp",
                            "https://first.internal.example/metadata", "new-secret"), cookie, csrf, null).statusCode());

            var artifacts = new com.samlscope.store.FileRunArtifactRepository(dataDirectory);
            artifacts.saveResult(runId, "{}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            assertDenied(client, base, "DELETE", "/api/plans/" + planId, null, cookie, null);
            assertTrue(artifacts.findResult(runId).isPresent());
            assertEquals(204, request(client, base, "DELETE", "/api/plans/" + planId,
                    null, cookie, csrf, null).statusCode());
            assertTrue(artifacts.findResult(runId).isEmpty());
            assertDenied(client, base, "GET", "/api/runs/" + runId, null, cookie, null);
            assertEquals(200, request(client, base, "GET", "/api/plans/" + secondPlanId,
                    null, secondCookie, null, null).statusCode());
        } finally {
            app.stop();
        }
    }

    private HttpResponse<String> createPlan(
            HttpClient client, URI base, String name, String entityId, String metadata, String hint)
            throws Exception {
        return request(client, base, "POST", "/api/plans", planBody(name, entityId, metadata, hint),
                null, null, null);
    }

    private String planBody(String name, String entityId, String metadata, String hint) {
        return """
                {"name":"%s","profile":"IDP_CORE","targetKind":"IDP",
                 "targetEntityId":"%s","metadataSourceKind":"URL","metadataSourceLocation":"%s",
                 "suiteMetadataDelivery":"MANUAL","declaredFeatures":{},
                 "parameters":{"clockSkewToleranceSeconds":180,"metadataRefreshWaitSeconds":300,
                               "testUserHint":"%s"},
                 "interaction":{"allowBrowserSteps":true,"allowAttestation":true},
                 "authorizedTarget":true}
                """.formatted(name, entityId, metadata, hint);
    }

    private void assertDenied(
            HttpClient client, URI base, String method, String path, String body, String cookie, String csrf)
            throws Exception {
        var response = request(client, base, method, path, body, cookie, csrf, null);
        assertEquals(403, response.statusCode(), method + " " + path + " -> " + response.body());
        assertFalse(response.body().contains("internal.example"));
        assertFalse(response.body().contains("secret"));
    }

    private HttpResponse<String> request(
            HttpClient client, URI base, String method, String path, String body,
            String cookie, String csrf, String origin) throws Exception {
        var builder = HttpRequest.newBuilder(base.resolve(path)).timeout(Duration.ofSeconds(3));
        if (cookie != null) builder.header("Cookie", cookie);
        if (csrf != null) builder.header("X-CSRF-Token", csrf);
        if (origin != null) builder.header("Origin", origin);
        if (body != null) builder.header("Content-Type", "application/json");
        builder.method(method, body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private int availablePort() throws Exception {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
