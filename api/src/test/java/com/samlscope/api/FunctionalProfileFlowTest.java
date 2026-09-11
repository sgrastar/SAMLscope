package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqliteRunRepository;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Proves the normal product flow using the exact release-pinned case sets. */
class FunctionalProfileFlowTest {
    @TempDir Path dataDirectory;
    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper json = new ObjectMapper();

    @ParameterizedTest
    @EnumSource(FunctionalProfile.class)
    void everyReleasedProfileRunsFromSharedTargetThroughStandaloneResult(FunctionalProfile profile) throws Exception {
        var config = new AppConfig(
                AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"),
                URI.create("http://127.0.0.1:8080"),
                dataDirectory,
                8080,
                true,
                false,
                false,
                "sha256:" + "a".repeat(64),
                "");
        var app = SamlScopeApplication.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var metadata = """
                    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                        entityID="https://target.example/entity">
                      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="https://target.example/sso"/>
                      </md:IDPSSODescriptor>
                      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <md:AssertionConsumerService index="0"
                            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="https://target.example/acs"/>
                      </md:SPSSODescriptor>
                    </md:EntityDescriptor>
                    """;
            var target = post(base, "/api/targets", json.writeValueAsString(java.util.Map.of(
                    "name", "Shared target",
                    "entityId", "https://target.example/entity",
                    "metadataXml", metadata,
                    "authorizedTarget", true)));
            assertEquals(201, target.statusCode(), target.body());
            var targetDocument = json.readTree(target.body());
            var targetId = targetDocument.path("id").asText();
            var revisionId = targetDocument.path("revisions").get(0).path("id").asText();

            var plan = post(base, "/api/plans", json.writeValueAsString(java.util.Map.ofEntries(
                    java.util.Map.entry("name", profile.id() + " candidate"),
                    java.util.Map.entry("profile", profile.id()),
                    java.util.Map.entry("targetKind", profile.role().name()),
                    java.util.Map.entry("targetConnectionId", targetId),
                    java.util.Map.entry("targetRevisionId", revisionId),
                    java.util.Map.entry("suiteMetadataDelivery", "MANUAL"),
                    java.util.Map.entry("declaredFeatures", java.util.Map.of()),
                    java.util.Map.entry("parameters", java.util.Map.of(
                            "clockSkewToleranceSeconds", 180,
                            "metadataRefreshWaitSeconds", 300,
                            "testUserHint", "",
                            "requestSigningMode", "OPTIONAL")),
                    java.util.Map.entry("interaction", java.util.Map.of(
                            "allowBrowserSteps", true,
                            "allowAttestation", false,
                            "preset", "quick")),
                    java.util.Map.entry("authorizedTarget", true))));
            assertEquals(201, plan.statusCode(), plan.body());
            var planId = json.readTree(plan.body()).at("/plan/plan/id").asText();

            var run = post(base, "/api/plans/" + planId + "/runs", null);
            assertEquals(201, run.statusCode(), run.body());
            var runId = json.readTree(run.body()).path("run").path("id").asText();
            var preflight = post(base, "/api/runs/" + runId + "/preflight", null);
            assertEquals(200, preflight.statusCode(), preflight.body());

            var premature = post(base, "/api/runs/" + runId + "/tests/start", null);
            assertEquals(400, premature.statusCode(), premature.body());

            if (profile == FunctionalProfile.BROWSER_SSO_IDP) {
                completeBrowserSsoIdpBaseline(base, planId, runId);
            } else {
                // Role-specific baseline protocol paths already have dedicated integration tests.
                // This test isolates the exact candidate's common Plan/Run/result pipeline.
                var runs = new SqliteRunRepository(new SqliteDatabase(dataDirectory), new JsonCodec());
                var existing = runs.find(runId).orElseThrow();
                runs.save(new TestRun(existing.id(), existing.planId(), RunStatus.COMPLETED,
                        existing.targetToSuiteReachability(), existing.context(),
                        existing.createdAt(), existing.updatedAt()));
            }

            var started = post(base, "/api/runs/" + runId + "/tests/start", null);
            assertEquals(200, started.statusCode(), started.body());
            assertEquals(profile == FunctionalProfile.ECP_IDP,
                    json.readTree(started.body()).path("ecpProbesRequired").asBoolean());
            var executions = new com.samlscope.store.SqliteCaseExecutionRepository(
                    new SqliteDatabase(dataDirectory), new JsonCodec());
            var firstCaseIds = executions.list(runId).stream().map(value -> value.caseId())
                    .collect(java.util.stream.Collectors.toSet());
            assertTrue(!firstCaseIds.isEmpty());
            var resumed = post(base, "/api/runs/" + runId + "/tests/start", null);
            assertEquals(200, resumed.statusCode(), resumed.body());
            assertEquals(firstCaseIds, executions.list(runId).stream().map(value -> value.caseId())
                    .collect(java.util.stream.Collectors.toSet()));


            // The old entry points must not discover any additional applicable cases.
            for (var milestone : java.util.List.of("M1", "M2", "M3")) {
                var legacy = post(base, "/api/runs/" + runId + "/milestones/" + milestone + "/start", null);
                assertEquals(profile == FunctionalProfile.ECP_IDP && milestone.equals("M3") ? 400 : 200,
                        legacy.statusCode(), legacy.body());
            }
            assertEquals(firstCaseIds, executions.list(runId).stream().map(value -> value.caseId())
                    .collect(java.util.stream.Collectors.toSet()));

            if (profile == FunctionalProfile.ECP_IDP) {
                // Model completed outbox fixtures locally; never send credentials or network probes.
                for (var fixture : com.samlscope.runner.outbox.EcpProbeService.requiredFixtureIds()) {
                    var actionId = com.samlscope.runner.outbox.EcpProbeService.actionId(runId, fixture);
                    var execution = new com.samlscope.core.caseexec.CaseExecution(runId, fixture, 0,
                            com.samlscope.core.caseexec.CaseExecutionStatus.RUNNING,
                            new com.samlscope.core.caseexec.CaseState("send-baseline", Map.of()),
                            null, null, Instant.now());
                    executions.apply(-1, execution, java.util.List.of(new com.samlscope.core.caseexec.OutboundAction(
                            actionId, com.samlscope.core.caseexec.OutboundKind.ECP_SOAP,
                            new byte[] { 1 }, URI.create("https://target.example/ecp"), true)));
                    executions.transitionOutbox(actionId, com.samlscope.core.caseexec.OutboxStatus.PENDING,
                            com.samlscope.core.caseexec.OutboxStatus.SENDING, Map.of(), null, Instant.now());
                    executions.transitionOutbox(actionId, com.samlscope.core.caseexec.OutboxStatus.SENDING,
                            com.samlscope.core.caseexec.OutboxStatus.SENT, Map.of(), null, Instant.now());
                }
                var continued = post(base, "/api/runs/" + runId + "/tests/start", null);
                assertEquals(200, continued.statusCode(), continued.body());
                assertEquals(false, json.readTree(continued.body()).path("ecpProbesRequired").asBoolean());
                var afterEcp = executions.list(runId).stream().map(value -> value.caseId())
                        .collect(java.util.stream.Collectors.toSet());
                assertEquals(200, post(base, "/api/runs/" + runId + "/milestones/M3/start", null).statusCode());
                assertEquals(afterEcp, executions.list(runId).stream().map(value -> value.caseId())
                        .collect(java.util.stream.Collectors.toSet()));
            }

            var result = get(base, "/api/runs/" + runId + "/result.json");
            assertEquals(200, result.statusCode(), result.body());
            var resultDocument = json.readTree(result.body());
            assertEquals(profile.id().replace('_', '-'), resultDocument.at("/profile/id").asText());
            assertEquals("INCOMPLETE", resultDocument.at("/run/completeness").asText());
            assertTrue(resultDocument.at("/summary/cases/total").asInt() > 0);

            var report = get(base, "/api/runs/" + runId + "/report.html");
            assertEquals(200, report.statusCode(), report.body());
            assertTrue(report.body().contains("Licenses and sources"));
            assertTrue(report.body().contains("Retained specification notices"));
        } finally {
            app.stop();
        }
    }

    private HttpResponse<String> post(URI base, String path, String body) throws Exception {
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

    private HttpResponse<String> postForm(URI base, String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(base.resolve(path))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private void completeBrowserSsoIdpBaseline(URI base, String planId, String runId) throws Exception {
        var roundTrip = get(base, "/p/" + planId + "/start/m0-roundtrip?run=" + runId);
        assertEquals(302, roundTrip.statusCode(), roundTrip.body());
        var protocol = new SamlProtocolService(
                base,
                new FilePlanKeyStore(dataDirectory, Clock.systemUTC()),
                new XmlSigner(),
                new OpenSamlReader(),
                Clock.systemUTC());
        var authnRequest = protocol.decodeRedirect(
                URI.create(roundTrip.headers().firstValue("Location").orElseThrow()).getRawQuery(),
                "SAMLRequest");
        var now = Instant.now();
        var respondingIdp = new TestPlan(
                "plan_1123456789ABCDEFGHJKMNPQRS",
                "Target IdP fixture",
                FunctionalProfile.BROWSER_SSO_SP,
                new TestPlan.Target(
                        TargetKind.SP,
                        base.resolve("/p/" + planId).toString(),
                        new TestPlan.MetadataSource(
                                MetadataSourceKind.URL,
                                base.resolve("/p/" + planId + "/metadata").toString())),
                MetadataDeliveryKind.HTTP_URL,
                Map.of(),
                TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(),
                now,
                now);
        var response = protocol.buildResponse(
                respondingIdp,
                authnRequest,
                base.resolve("/p/" + planId + "/sp/acs/0"),
                "flow-user");
        var completed = postForm(base, "/p/" + planId + "/sp/acs/0",
                "SAMLResponse=" + encode(response.base64()) + "&RelayState=" + encode(runId));
        assertEquals(200, completed.statusCode(), completed.body());
    }
}
