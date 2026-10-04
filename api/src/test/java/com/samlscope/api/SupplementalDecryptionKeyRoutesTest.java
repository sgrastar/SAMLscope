package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqliteRunRepository;
import com.samlscope.store.SqliteSupplementalDecryptionKeys;

/** Explicit Run input lifecycle: read-only status, fixed first submission, and start-path sealing. */
class SupplementalDecryptionKeyRoutesTest {
    @TempDir Path dataDirectory;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void submissionIsRunBoundIdempotentAndSealedBeforeTheFirstFixture() throws Exception {
        var config = new AppConfig(
                AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"),
                URI.create("http://127.0.0.1:8080"),
                dataDirectory, 8080, true, false, false, "sha256:" + "a".repeat(64), "");
        var app = SamlScopeApplication.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var planId = createSingleLogoutPlan(base);
            var runId = jsonOf(postJson(base, "/api/plans/" + planId + "/runs", null)).path("run").path("id").asText();
            assertEquals(200, postJson(base, "/api/runs/" + runId + "/preflight", null).statusCode());
            var repository = new SqliteSupplementalDecryptionKeys(
                    new SqliteDatabase(dataDirectory), new JsonCodec());

            var status = get(base, "/api/runs/" + runId + "/supplemental-decryption-keys");
            assertEquals(200, status.statusCode(), status.body());
            var initial = json.readTree(status.body());
            assertTrue(initial.path("input").isNull());
            assertFalse(initial.path("testsStarted").asBoolean());
            assertTrue(initial.path("metadataSha256").asText().matches("[0-9a-f]{64}"));
            assertTrue(repository.find(runId).isEmpty(), "reading the status must not fix the Run");
            var targetEntityId = initial.path("targetEntityId").asText();
            var metadataSha256 = initial.path("metadataSha256").asText();

            var valid = publicKeyBase64();
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    "{\"targetEntityId\":\"" + targetEntityId + "\"}").statusCode());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, "b".repeat(64), "https://idp.example/keys", valid)).statusCode());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://idp.example/keys",
                            Base64.getEncoder().encodeToString("not-a-key".getBytes()))).statusCode());
            assertEquals(400, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://user:secret@idp.example/keys", valid)).statusCode());
            assertTrue(repository.find(runId).isEmpty());

            var accepted = postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://idp.example/admin/keys", valid));
            assertEquals(200, accepted.statusCode(), accepted.body());
            var recordedAt = json.readTree(accepted.body()).path("recordedAt").asText();
            assertFalse(recordedAt.isBlank(), accepted.body());
            assertEquals(valid, json.readTree(accepted.body()).path("publicKeysSpkiBase64").get(0).asText());

            var repeated = postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://idp.example/admin/keys", valid));
            assertEquals(200, repeated.statusCode(), repeated.body());
            assertEquals(recordedAt, json.readTree(repeated.body()).path("recordedAt").asText());
            var conflict = postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://other.example/keys", valid));
            assertEquals(409, conflict.statusCode(), conflict.body());

            completeInitialLogin(runId);
            assertEquals(200, postJson(base, "/api/runs/" + runId + "/tests/start", null).statusCode());
            var sealed = get(base, "/api/runs/" + runId + "/supplemental-decryption-keys");
            assertEquals(200, sealed.statusCode(), sealed.body());
            assertTrue(json.readTree(sealed.body()).path("testsStarted").asBoolean());
            assertEquals(recordedAt, json.readTree(sealed.body()).path("input").path("recordedAt").asText());
            assertEquals(200, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://idp.example/admin/keys", valid)).statusCode());
            assertEquals(409, postJson(base, "/api/runs/" + runId + "/supplemental-decryption-keys/submit",
                    body(targetEntityId, metadataSha256, "https://other.example/keys", valid)).statusCode());

            var lateRunId = jsonOf(postJson(base, "/api/plans/" + planId + "/runs", null)).path("run").path("id").asText();
            assertEquals(200, postJson(base, "/api/runs/" + lateRunId + "/preflight", null).statusCode());
            assertTrue(json.readTree(get(base, "/api/runs/" + lateRunId
                    + "/supplemental-decryption-keys").body()).path("input").isNull());
            completeInitialLogin(lateRunId);
            assertEquals(200, postJson(base, "/api/runs/" + lateRunId + "/tests/start", null).statusCode());
            var lateStatus = get(base, "/api/runs/" + lateRunId + "/supplemental-decryption-keys");
            assertEquals(200, lateStatus.statusCode(), lateStatus.body());
            var lateInput = json.readTree(lateStatus.body()).path("input");
            assertTrue(lateInput.path("publicKeysSpkiBase64").isArray());
            assertEquals(0, lateInput.path("publicKeysSpkiBase64").size(), "absence is fixed, not left editable");
            assertTrue(lateInput.path("sourceUri").isNull());
            assertEquals(409, postJson(base, "/api/runs/" + lateRunId + "/supplemental-decryption-keys/submit",
                    body(json.readTree(lateStatus.body()).path("targetEntityId").asText(),
                            json.readTree(lateStatus.body()).path("metadataSha256").asText(),
                            "https://idp.example/keys", publicKeyBase64())).statusCode());
        } finally {
            app.stop();
        }
    }

    private String createSingleLogoutPlan(URI base) throws Exception {
        var metadata = """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://target.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                        Location="https://target.example/sso"/>
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://target.example/slo"/>
                  </md:IDPSSODescriptor>
                  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:AssertionConsumerService index="0"
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://target.example/acs"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                """;
        var target = postJson(base, "/api/targets", new ObjectMapper().writeValueAsString(Map.of(
                "name", "Logout target", "entityId", "https://target.example/entity",
                "metadataXml", metadata, "authorizedTarget", true)));
        assertEquals(201, target.statusCode(), target.body());
        var targetId = json.readTree(target.body()).path("id").asText();
        var revisionId = json.readTree(target.body()).path("revisions").get(0).path("id").asText();
        var plan = postJson(base, "/api/plans", new ObjectMapper().writeValueAsString(Map.ofEntries(
                Map.entry("name", "Single logout candidate"),
                Map.entry("profile", "single_logout_idp"),
                Map.entry("targetKind", "IDP"),
                Map.entry("targetConnectionId", targetId),
                Map.entry("targetRevisionId", revisionId),
                Map.entry("suiteMetadataDelivery", "MANUAL"),
                Map.entry("declaredFeatures", Map.of()),
                Map.entry("parameters", Map.of(
                        "clockSkewToleranceSeconds", 180,
                        "metadataRefreshWaitSeconds", 300,
                        "testUserHint", "",
                        "requestSigningMode", "OPTIONAL")),
                Map.entry("interaction", Map.of(
                        "allowBrowserSteps", true, "allowAttestation", false, "preset", "quick")),
                Map.entry("authorizedTarget", true))));
        assertEquals(201, plan.statusCode(), plan.body());
        return json.readTree(plan.body()).at("/plan/plan/id").asText();
    }

    private void completeInitialLogin(String runId) throws Exception {
        var runs = new SqliteRunRepository(new SqliteDatabase(dataDirectory), new JsonCodec());
        var existing = runs.find(runId).orElseThrow();
        runs.save(new TestRun(existing.id(), existing.planId(), RunStatus.COMPLETED,
                existing.targetToSuiteReachability(), existing.context(),
                existing.createdAt(), existing.updatedAt()));
    }

    private static String publicKeyBase64() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
    }

    private static String body(String target, String digest, String source, String key) {
        try {
            return new ObjectMapper().writeValueAsString(Map.of(
                    "targetEntityId", target, "metadataSha256", digest,
                    "sourceUri", source, "publicKeysSpkiBase64", java.util.List.of(key)));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private com.fasterxml.jackson.databind.JsonNode jsonOf(HttpResponse<String> response) throws Exception {
        return json.readTree(response.body());
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
