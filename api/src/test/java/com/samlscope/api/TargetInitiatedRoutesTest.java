package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The IdP-initiated checks are prepared explicitly and are single profile-scoped. */
class TargetInitiatedRoutesTest {
    @TempDir Path dataDirectory;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void prepareAndStatusAreBoundedByProfileAndKind() throws Exception {
        var config = new AppConfig(
                AppConfig.Mode.SELFHOSTED, URI.create("http://127.0.0.1:8080"),
                URI.create("http://127.0.0.1:8080"), dataDirectory, 8080, true, false, false,
                "sha256:" + "a".repeat(64), "");
        var app = SamlScopeApplication.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var planId = createPlan(base, "browser_sso_idp");
            var runId = json.readTree(postJson(base, "/api/plans/" + planId + "/runs", null).body())
                    .path("run").path("id").asText();

            var status = get(base, "/api/runs/" + runId + "/target-initiated");
            assertEquals(200, status.statusCode(), status.body());
            assertTrue(json.readTree(status.body()).isNull());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/target-initiated",
                    "{\"kind\":\"TARGET_LOGOUT\"}").statusCode());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/target-initiated",
                    "{\"kind\":\"UNKNOWN\"}").statusCode());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/target-initiated",
                    "{\"kind\":\"UNSOLICITED_SSO\",\"extra\":true}").statusCode());

            var prepared = postJson(base, "/api/runs/" + runId + "/target-initiated",
                    "{\"kind\":\"UNSOLICITED_SSO\"}");
            assertEquals(200, prepared.statusCode(), prepared.body());
            assertEquals("UNSOLICITED_SSO", json.readTree(prepared.body()).path("kind").asText());
            assertEquals(runId, json.readTree(prepared.body()).path("runId").asText());
            var after = json.readTree(get(base, "/api/runs/" + runId + "/target-initiated").body());
            assertEquals("UNSOLICITED_SSO", after.path("kind").asText());
        } finally {
            app.stop();
        }
    }

    private String createPlan(URI base, String profile) throws Exception {
        var metadata = """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://target.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="https://target.example/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """;
        var target = postJson(base, "/api/targets", new ObjectMapper().writeValueAsString(Map.of(
                "name", "Target", "entityId", "https://target.example/entity",
                "metadataXml", metadata, "authorizedTarget", true)));
        assertEquals(201, target.statusCode(), target.body());
        var targetId = json.readTree(target.body()).path("id").asText();
        var revisionId = json.readTree(target.body()).path("revisions").get(0).path("id").asText();
        var plan = postJson(base, "/api/plans", new ObjectMapper().writeValueAsString(Map.ofEntries(
                Map.entry("name", "Target-initiated"),
                Map.entry("profile", profile),
                Map.entry("targetKind", "IDP"),
                Map.entry("targetConnectionId", targetId),
                Map.entry("targetRevisionId", revisionId),
                Map.entry("suiteMetadataDelivery", "MANUAL"),
                Map.entry("declaredFeatures", Map.of()),
                Map.entry("parameters", Map.of(
                        "clockSkewToleranceSeconds", 180, "metadataRefreshWaitSeconds", 300,
                        "testUserHint", "", "requestSigningMode", "OPTIONAL")),
                Map.entry("interaction", Map.of(
                        "allowBrowserSteps", true, "allowAttestation", false, "preset", "quick")),
                Map.entry("authorizedTarget", true))));
        assertEquals(201, plan.statusCode(), plan.body());
        return json.readTree(plan.body()).at("/plan/plan/id").asText();
    }

    private HttpResponse<String> postJson(URI base, String path, String body) throws Exception {
        var request = HttpRequest.newBuilder(base.resolve(path));
        if (body != null) request.header("Content-Type", "application/json");
        return http.send(request.POST(body == null
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(URI base, String path) throws Exception {
        return http.send(HttpRequest.newBuilder(base.resolve(path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
