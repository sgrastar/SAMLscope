package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.run.RunStatus;
import com.samlscope.store.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ActiveProbeReportFreshnessTest {
    @TempDir Path data;
    private final JsonCodec json = new JsonCodec();
    private final HttpClient client = HttpClient.newHttpClient();
    private URI base;

    @Test
    void completedCaseAppearsInBothReportsWhileTheNextCaseAwaitsResponse() throws Exception {
        var config = new AppConfig(AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"), URI.create("http://127.0.0.1:8080"),
                data, 8080, true, false, false, "sha256:" + "1".repeat(64), "");
        // Keep WAL shared memory alive while HTTP and Transcript workers use separate
        // connections. This test targets report freshness, not connection-lifecycle races.
        try (var keepAlive = new SqliteDatabase(data).open()) {
            var app = SamlScopeApplication.create(config).start(0);
            try {
                base = URI.create("http://127.0.0.1:" + app.port());
                var plan = post("/api/plans", """
                        {"name":"Report regression","profile":"IDP_CORE","targetKind":"IDP",
                        "targetEntityId":"https://idp.example/entity","metadataSourceKind":"URL",
                        "metadataSourceLocation":"https://idp.example/metadata","suiteMetadataDelivery":"HTTP_URL",
                        "declaredFeatures":{},"parameters":{"clockSkewToleranceSeconds":180,
                        "metadataRefreshWaitSeconds":300,"testUserHint":""},
                        "interaction":{"allowBrowserSteps":true,"allowAttestation":true},"authorizedTarget":true}
                        """, "application/json").path("plan").path("plan").path("id").asText();
                var runId = post("/api/plans/" + plan + "/runs", "", "application/json")
                        .path("run").path("id").asText();
                // Seed only the completed M0 prerequisite; the active-probe path below is real HTTP.
                var runs = new SqliteRunRepository(new SqliteDatabase(data), json);
                var run = runs.find(runId).orElseThrow();
                runs.save(new TestRun(run.id(), run.planId(), RunStatus.COMPLETED,
                        run.targetToSuiteReachability(), run.context(), run.createdAt(), run.updatedAt()));
                new MetadataCache(data).putIfAbsent(runId, """
                        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
                        <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/>
                        </md:IDPSSODescriptor></md:EntityDescriptor>
                        """.getBytes(StandardCharsets.UTF_8));
                var api = "/api/runs/" + runId;
                post(api + "/quick-check", "", "application/json");
                var initial = get(api + "/active-probe");
                var start = URI.create(initial.path("startUrl").asText());
                send(start.getRawPath() + "?" + start.getRawQuery(),
                        "freshSessionConfirmed=true", "application/x-www-form-urlencoded");
                for (int i = 0; i < 4; i++) {
                    var active = get(api + "/active-probe");
                    assertEquals("IIP-IDP05-a-idp-01", active.path("caseId").asText());
                    var action = active.path("actionId").asText();
                    var response = """
                            <p:Response xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol"
                            xmlns:a="urn:oasis:names:tc:SAML:2.0:assertion" ID="response-%s"
                            Version="2.0" IssueInstant="2026-09-07T00:00:00Z" InResponseTo="_%s">
                            <a:Issuer>https://idp.example/entity</a:Issuer>
                            <p:Status><p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:%s"/></p:Status>%s</p:Response>
                            """.formatted(i, action, i == 1 ? "Success" : "Responder", i == 1 ? "<a:Assertion/>" : "");
                    send("/p/" + plan + "/sp/acs/0", "SAMLResponse=" + encode(Base64.getEncoder()
                            .encodeToString(response.getBytes(StandardCharsets.UTF_8)))
                            + "&RelayState=" + encode("sp1:" + runId + ":" + action),
                            "application/x-www-form-urlencoded");
                }
                var next = get(api + "/active-probe");
                assertEquals("AWAITING_RESPONSE", next.path("state").asText());
                assertNotEquals("IIP-IDP05-a-idp-01", next.path("caseId").asText());
                var report = get(api + "/result.json");
                JsonNode completed = null;
                for (var requirement : report.path("requirements")) {
                    for (var entry : requirement.path("cases")) {
                        if (entry.path("id").asText().equals("IIP-IDP05-a-idp-01")) completed = entry;
                    }
                }
                assertNotNull(completed);
                assertEquals("SATISFIED", completed.path("outcome").asText());
                assertEquals("idp.error-response.satisfied", completed.path("reason_code").asText());
                assertEquals(4, completed.path("evidence").size());
                var html = client.send(HttpRequest.newBuilder(base.resolve(api + "/report.html")).build(),
                        HttpResponse.BodyHandlers.ofString());
                assertEquals(200, html.statusCode());
                var embedded = java.util.regex.Pattern.compile("atob\\('([^']+)'\\)")
                        .matcher(html.body());
                assertTrue(embedded.find(), "Report must contain its standalone result data");
                var htmlResult = json.mapper().readTree(Base64.getDecoder().decode(embedded.group(1)));
                assertEquals(report.path("requirements"), htmlResult.path("requirements"));
            } finally { app.stop(); }
        }
    }

    private JsonNode get(String path) throws Exception {
        var result = client.send(HttpRequest.newBuilder(base.resolve(path)).build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, result.statusCode(), result.body());
        return json.mapper().readTree(result.body());
    }
    private JsonNode post(String path, String body, String type) throws Exception {
        return json.mapper().readTree(send(path, body, type));
    }
    private String send(String path, String body, String type) throws Exception {
        var result = client.send(HttpRequest.newBuilder(base.resolve(path)).header("Content-Type", type)
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(result.statusCode() == 200 || result.statusCode() == 201, result.body());
        return result.body();
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
