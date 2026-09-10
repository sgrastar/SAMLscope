package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.store.JsonCodec;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TargetConnectionRoutesTest {
    @TempDir Path directory;
    private final HttpClient client = HttpClient.newHttpClient();
    private final JsonCodec json = new JsonCodec();

    @Test
    void hostedModeWithoutOidcCanRegisterTargetAndCreateProtectedPlan() throws Exception {
        int port;
        try (var socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        var config = new AppConfig(
                AppConfig.Mode.HOSTED, URI.create("https://127.0.0.1:" + port),
                URI.create("https://peer.example"), directory, port,
                false, false, true, "sha256:" + "a".repeat(64), "127.0.0.1");
        var app = FunctionalProfileTestInstallation.create(config).start(port);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var metadata = """
                    <EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='https://mockidp.dev/entityid'>
                      <IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
                        <SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                          Location='https://mockidp.dev/api/saml/sso'/>
                      </IDPSSODescriptor>
                    </EntityDescriptor>
                    """;
            var target = post(base, "/api/targets", Map.of(
                    "name", "MockIdP", "entityId", "https://mockidp.dev/entityid",
                    "metadataXml", metadata, "authorizedTarget", true));

            var created = post(base, "/api/plans", Map.ofEntries(
                    Map.entry("name", "MockIdP browser SSO"),
                    Map.entry("profile", "browser_sso_idp"),
                    Map.entry("suiteMetadataDelivery", "MANUAL"),
                    Map.entry("authorizedTarget", true),
                    Map.entry("targetConnectionId", target.path("id").asText()),
                    Map.entry("targetRevisionId", target.at("/revisions/0/id").asText())));

            assertEquals("https://mockidp.dev/entityid", created.at("/plan/plan/target/entityId").asText());
            assertTrue(created.at("/initialRun/managementUrl").asText().contains("#t="));
            var list = client.send(HttpRequest.newBuilder(base.resolve("/api/targets")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(403, list.statusCode(), list.body());
        } finally {
            app.stop();
        }
    }

    @Test
    void oneImmutableMetadataRevisionFeedsCompatibleProfilesAndTheirPreflights() throws Exception {
        var config = new AppConfig(
                AppConfig.Mode.SELFHOSTED, URI.create("http://127.0.0.1:8080"),
                URI.create("http://127.0.0.1:8080"), directory, 8080,
                true, false, false);
        var app = FunctionalProfileTestInstallation.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var metadata = """
                    <EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='urn:example'>
                      <IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'>
                        <SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                          Location='https://idp.example/sso'/>
                      </IDPSSODescriptor>
                    </EntityDescriptor>
                    """;
            var target = post(base, "/api/targets", Map.of(
                    "name", "Example IdP", "entityId", "urn:example",
                    "metadataXml", metadata, "authorizedTarget", true));
            var connectionId = target.path("id").asText();
            var revisionId = target.at("/revisions/0/id").asText();
            assertFalse(target.toString().contains("metadataXml"));

            for (var profile : java.util.List.of("browser_sso_idp", "metadata_idp")) {
                var created = post(base, "/api/plans", Map.of(
                        "name", profile, "profile", profile,
                        "suiteMetadataDelivery", "HTTP_URL", "authorizedTarget", true,
                        "targetConnectionId", connectionId, "targetRevisionId", revisionId));
                var plan = created.at("/plan/plan");
                assertEquals(profile, plan.path("profile").asText());
                assertEquals(connectionId, plan.at("/target/connectionId").asText());
                assertEquals(revisionId, plan.at("/target/metadataRevisionId").asText());
                var run = post(base, "/api/plans/" + plan.path("id").asText() + "/runs", Map.of());
                var preflight = post(base, "/api/runs/" + run.at("/run/id").asText() + "/preflight", Map.of());
                assertEquals(revisionId, preflight.at("/observations/metadataRevisionId").asText());
                assertEquals("PASS", preflight.at("/checks/1/status").asText());
            }
        } finally {
            app.stop();
        }
    }

    @Test
    void targetImportLimiterDefaultsToUnlimited() {
        assertEquals(0, AppConfig.from(Map.of()).targetImportsPerHour());
    }

    private JsonNode post(URI base, String path, Map<String,?> body) throws Exception {
        var response = client.send(
                HttpRequest.newBuilder(base.resolve(path))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json.mapper().writeValueAsString(body)))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() == 200 || response.statusCode() == 201, response.body());
        return json.mapper().readTree(response.body());
    }
}
