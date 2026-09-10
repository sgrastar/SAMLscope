package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.store.JsonCodec;
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
