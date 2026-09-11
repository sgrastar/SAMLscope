package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SamlScopeApplicationTest {
    @TempDir Path dataDirectory;

    @Test
    void createsPlanAndPublishesSignedMetadata() throws Exception {
        var config = new AppConfig(AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"), URI.create("http://127.0.0.1:8080"),
                dataDirectory, 8080, true, false, false);
        var app = FunctionalProfileTestInstallation.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var client = HttpClient.newHttpClient();
            var health = client.send(HttpRequest.newBuilder(base.resolve("/api/health")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, health.statusCode());
            assertTrue(health.body().contains("\"status\":\"ok\""));
            assertTrue(health.headers().firstValue("Content-Security-Policy").orElseThrow()
                    .contains("form-action 'self'"));

            var completionStyle = client.send(HttpRequest.newBuilder(
                    base.resolve("/p/plan_test/ui/completion.css")).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, completionStyle.statusCode());
            assertTrue(completionStyle.headers().firstValue("Content-Type").orElseThrow().startsWith("text/css"));
            assertTrue(completionStyle.body().contains("prefers-color-scheme"));

            var licenses = client.send(HttpRequest.newBuilder(base.resolve("/licenses")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, licenses.statusCode());
            assertTrue(licenses.body().contains("<div id=\"root\"></div>"));
            var browserNotices = client.send(HttpRequest.newBuilder(
                    base.resolve("/licenses/browser-dependencies.json")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, browserNotices.statusCode());
            assertTrue(browserNotices.headers().firstValue("Content-Type").orElseThrow()
                    .startsWith("application/json"));
            assertTrue(browserNotices.body().contains("\"name\": \"react\""));
            var sourceNotices = client.send(HttpRequest.newBuilder(
                    base.resolve("/licenses/source-notices.json")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, sourceNotices.statusCode());
            assertTrue(sourceNotices.body().contains("\"unresolved_sources\""));
            for (var file : java.util.List.of("source-membership.json", "java-dependencies.json")) {
                var inventory = client.send(HttpRequest.newBuilder(
                        base.resolve("/licenses/" + file)).build(), HttpResponse.BodyHandlers.ofByteArray());
                assertEquals(200, inventory.statusCode(), file);
                assertTrue(inventory.headers().firstValue("Content-Type").orElseThrow()
                        .startsWith("application/json"));
                try (var expected = getClass().getResourceAsStream("/public/licenses/" + file)) {
                    assertNotNull(expected, file);
                    assertArrayEquals(expected.readAllBytes(), inventory.body(), file);
                }
            }

            var requestBody = """
                    {
                      "name":"Example IdP",
                      "profile":"browser_sso_idp",
                      "targetKind":"IDP",
                      "targetEntityId":"https://idp.example/entity",
                      "metadataSourceKind":"URL",
                      "metadataSourceLocation":"https://idp.example/metadata",
                      "suiteMetadataDelivery":"HTTP_URL",
                      "declaredFeatures":{},
                      "parameters":{"clockSkewToleranceSeconds":180,"metadataRefreshWaitSeconds":300,"testUserHint":""},
                      "interaction":{"allowBrowserSteps":true,"allowAttestation":true},
                      "authorizedTarget":true
                    }
                    """;
            var unauthorized = client.send(HttpRequest.newBuilder(base.resolve("/api/plans"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    requestBody.replace("\"authorizedTarget\":true", "\"authorizedTarget\":false")))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, unauthorized.statusCode());
            assertTrue(unauthorized.body().contains("authorized to test"));
            var created = client.send(HttpRequest.newBuilder(base.resolve("/api/plans"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(requestBody)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            var planId = created.body().replaceFirst("(?s).*\"id\":\"(plan_[0-9A-Z]+)\".*", "$1");
            assertTrue(planId.matches("plan_[0-9A-HJKMNP-TV-Z]{26}"));
            assertTrue(created.body().contains("\"requestSigningMode\":\"OPTIONAL\""));
            var requiredBody = requestBody.replace("\"testUserHint\":\"\"",
                    "\"testUserHint\":\"\",\"requestSigningMode\":\"REQUIRED\"");
            var changedMode = client.send(HttpRequest.newBuilder(base.resolve("/api/plans/" + planId))
                    .header("Content-Type", "application/json")
                    .PUT(HttpRequest.BodyPublishers.ofString(requiredBody)).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, changedMode.statusCode());
            var separatePlan = client.send(HttpRequest.newBuilder(base.resolve("/api/plans"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requiredBody)).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(201, separatePlan.statusCode());
            assertTrue(separatePlan.body().contains("\"requestSigningMode\":\"REQUIRED\""));

            assertTrue(created.body().contains("\"secondaryIdpEntityId\":\"http://127.0.0.1:8080/p/"
                    + planId + "/idp/secondary\""));

            var createdRun = client.send(HttpRequest.newBuilder(base.resolve("/api/plans/" + planId + "/runs"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, createdRun.statusCode(), createdRun.body());
            assertTrue(createdRun.body().contains("\"managementUrl\":null"));
            var runId = createdRun.body().replaceFirst("(?s).*\"id\":\"(run_[0-9A-Z]+)\".*", "$1");
            assertTrue(runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
            var unpreparedRoundTrip = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/start/m0-roundtrip?run=" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(409, unpreparedRoundTrip.statusCode(), unpreparedRoundTrip.body());
            assertTrue(unpreparedRoundTrip.body().contains("\"error\":\"preflight_required\""));
            assertFalse(unpreparedRoundTrip.body().contains(dataDirectory.toString()));
            var activeProbe = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/active-probe")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, activeProbe.statusCode(), activeProbe.body());
            assertTrue(activeProbe.body().contains("\"state\":\"NOT_STARTED\""));
            var prematureProbe = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/probe/action_not_ready?run=" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, prematureProbe.statusCode(), prematureProbe.body());
            var protocolEvidence = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/protocol-evidence")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, protocolEvidence.statusCode(), protocolEvidence.body());
            assertTrue(protocolEvidence.body().contains("\"eligibleCases\":0"));
            assertTrue(protocolEvidence.body().contains("\"readyCases\":0"));
            var confirmedCampaign = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/protocol-evidence/confirm-attempts"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, confirmedCampaign.statusCode(), confirmedCampaign.body());
            assertTrue(confirmedCampaign.body().contains("\"completed\":[]"));
            var lab = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, lab.statusCode(), lab.body());
            assertTrue(lab.body().contains("\"selectedVariant\":\"control\""));
            assertTrue(lab.body().contains("/p/" + planId + "/metadata/live?run=" + runId));
            assertFalse(lab.body().contains("\"baseline\""));

            var uncorrelated = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/variant"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{\"variant\":\"baseline\"}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(400, uncorrelated.statusCode(), uncorrelated.body());

            var selected = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/variant"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{\"variant\":\"no-key-info\"}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, selected.statusCode(), selected.body());
            assertTrue(selected.body().contains("\"selectedVariant\":\"no-key-info\""));
            var liveMetadata = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/metadata/live?run=" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, liveMetadata.statusCode(), liveMetadata.body());
            assertEquals("no-store", liveMetadata.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals(4, occurrences(liveMetadata.body(), "<ds:KeyInfo"), liveMetadata.body());
            assertTrue(liveMetadata.body().contains("mdv=no-key-info&amp;run=" + runId));

            var redirectSelected = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/variant"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{\"variant\":\"redirect-307\"}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, redirectSelected.statusCode(), redirectSelected.body());
            var redirect = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/metadata/live?run=" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(307, redirect.statusCode(), redirect.body());
            var canonicalLocation = URI.create(redirect.headers().firstValue("Location").orElseThrow());
            var redirectedMetadata = client.send(HttpRequest.newBuilder(base.resolve(
                            canonicalLocation.getRawPath() + "?" + canonicalLocation.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, redirectedMetadata.statusCode(), redirectedMetadata.body());
            assertTrue(redirectedMetadata.body().contains("mdv=redirect-307&amp;run=" + runId));

            var automatic = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/automatic-polling"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    "{\"variants\":[\"control\",\"expired\"],\"pollingDelaySeconds\":17}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, automatic.statusCode(), automatic.body());
            assertTrue(automatic.body().contains("\"ingestionMode\":\"AUTOMATIC_POLLING\""));
            assertTrue(automatic.body().contains("\"campaignIndex\":0"));
            assertTrue(automatic.body().contains("\"pollingDelaySeconds\":17"));
            assertTrue(automatic.body().contains("/start/metadata-polling/0"), automatic.body());
            var automaticUrl = automatic.body().replaceFirst(
                    "(?s).*\"metadataUrl\":\"([^\"]+)\".*", "$1");
            var reportedAutomaticUrl = URI.create(automaticUrl);
            var automaticControl = client.send(HttpRequest.newBuilder(base.resolve(
                            reportedAutomaticUrl.getRawPath() + "?" + reportedAutomaticUrl.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, automaticControl.statusCode(), automaticControl.body());
            assertTrue(automaticControl.body().contains("mdv=control&amp;run=" + runId));
            var advanced = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(advanced.body().contains("\"selectedVariant\":\"control\""), advanced.body());
            assertTrue(advanced.body().contains("\"campaignIndex\":0"), advanced.body());
            assertTrue(advanced.body().contains("/start/metadata-polling/0"), advanced.body());
            var preloaded = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/preloaded"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, preloaded.statusCode(), preloaded.body());
            assertTrue(preloaded.body().contains("\"ingestionMode\":\"PRELOADED_AGGREGATE\""));
            assertTrue(preloaded.body().contains("\"preloadedFetched\":false"));
            var preloadedDownloadUrl = URI.create(preloaded.body().replaceFirst(
                    "(?s).*\"preloadedDownloadUrl\":\"([^\"]+)\".*", "$1"));
            var preloadedUrl = URI.create(preloaded.body().replaceFirst(
                    "(?s).*\"preloadedMetadataUrl\":\"([^\"]+)\".*", "$1"));
            var filesBeforeRejectedFetch = regularFiles(dataDirectory.resolve("keys"));
            var rejectedFetchQuery = preloadedUrl.getRawQuery().replaceFirst(
                    "(^|&)preload=[^&]+", "$1preload=invalid");
            var rejectedFetch = client.send(HttpRequest.newBuilder(base.resolve(
                            preloadedUrl.getRawPath() + "?" + rejectedFetchQuery)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, rejectedFetch.statusCode(), rejectedFetch.body());
            assertEquals(filesBeforeRejectedFetch, regularFiles(dataDirectory.resolve("keys")),
                    "an unauthorized preloaded fetch must not generate keys or fixtures");
            var download = client.send(HttpRequest.newBuilder(base.resolve(
                            preloadedDownloadUrl.getRawPath() + "?" + preloadedDownloadUrl.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, download.statusCode(), download.body());
            assertEquals("attachment; filename=\"samlscope-metadata-campaign.xml\"",
                    download.headers().firstValue("Content-Disposition").orElseThrow());
            var afterDownload = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(afterDownload.body().contains("\"preloadedFetched\":false"),
                    "an operator download must not claim a Target metadata fetch");
            var aggregate = client.send(HttpRequest.newBuilder(base.resolve(
                            preloadedUrl.getRawPath() + "?" + preloadedUrl.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, aggregate.statusCode(), aggregate.body());
            assertEquals("no-store", aggregate.headers().firstValue("Cache-Control").orElseThrow());
            assertTrue(aggregate.headers().firstValue("Content-Disposition").isEmpty(),
                    "the Target fetch URL is not the operator download surface");
            assertTrue(aggregate.body().contains("<md:EntitiesDescriptor"));
            assertTrue(aggregate.body().contains("metadata-peer/unknown-extension"));
            assertFalse(aggregate.body().contains("metadata-peer/bad-signature"));
            var rearmed = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab/preloaded"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString("{}"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, rearmed.statusCode(), rearmed.body());
            var rearmedUrl = URI.create(rearmed.body().replaceFirst(
                    "(?s).*\"preloadedMetadataUrl\":\"([^\"]+)\".*", "$1"));
            assertNotEquals(preloadedUrl.getRawQuery(), rearmedUrl.getRawQuery(),
                    "rearming must rotate the campaign capability");
            var staleTokenFetch = client.send(HttpRequest.newBuilder(base.resolve(
                            preloadedUrl.getRawPath() + "?" + preloadedUrl.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(400, staleTokenFetch.statusCode(), staleTokenFetch.body());
            var rearmedFetch = client.send(HttpRequest.newBuilder(base.resolve(
                            rearmedUrl.getRawPath() + "?" + rearmedUrl.getRawQuery())).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, rearmedFetch.statusCode(), rearmedFetch.body());
            assertEquals(aggregate.body(), rearmedFetch.body(),
                    "token rotation must not force regeneration of the stable Run fixture");
            var aggregateState = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/metadata-lab")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertTrue(aggregateState.body().contains("\"preloadedFetched\":true"), aggregateState.body());
            var reportShell = client.send(HttpRequest.newBuilder(base.resolve("/reports/" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, reportShell.statusCode());
            assertTrue(reportShell.body().contains("<div id=\"root\"></div>"));

            var metadata = client.send(HttpRequest.newBuilder(base.resolve("/p/" + planId + "/metadata")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, metadata.statusCode());
            assertEquals("application/samlmetadata+xml", metadata.headers()
                    .firstValue("Content-Type").orElseThrow());
            assertTrue(metadata.body().contains("<ds:Signature"));
            assertTrue(metadata.body().contains("<md:SPSSODescriptor"));
            assertTrue(metadata.body().contains("<md:IDPSSODescriptor"));

            var secondaryMetadata = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/idp/secondary/metadata")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, secondaryMetadata.statusCode());
            assertTrue(secondaryMetadata.body().contains("entityID=\"http://127.0.0.1:8080/p/"
                    + planId + "/idp/secondary\""));
            assertTrue(secondaryMetadata.body().contains("<md:IDPSSODescriptor"));
            assertFalse(secondaryMetadata.body().contains("<md:SPSSODescriptor"));

            var variant = client.send(HttpRequest.newBuilder(base.resolve(
                            "/p/" + planId + "/metadata?variant=no-key-info&run=" + runId)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, variant.statusCode(), variant.body());
            assertEquals("no-store", variant.headers().firstValue("Cache-Control").orElseThrow());
            assertTrue(variant.body().contains("mdv=no-key-info&amp;run=" + runId));
            var transcript = client.send(HttpRequest.newBuilder(base.resolve(
                            "/api/runs/" + runId + "/transcript")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, transcript.statusCode());
            assertTrue(transcript.body().contains("MetadataFetch"));
            assertTrue(transcript.body().contains("no-key-info"));
            assertTrue(transcript.body().contains("\"feed\":\"live\""));
        } finally {
            app.stop();
        }
    }

    @Test
    void automaticMetadataTransitionWaitsWithoutChangingTheOutcome() {
        var page = SamlScopeApplication.metadataPollingTransitionPage(
                "/p/plan/start/metadata-polling/1?run=run&poll=token", 17);
        assertTrue(page.contains("content=\"17;url="), page);
        assertTrue(page.contains("run=run&amp;poll=token"), page);
        assertTrue(page.contains("does not affect the conformance outcome"), page);
        assertFalse(page.contains("FAIL"), page);
        assertFalse(page.contains("WARNING"), page);
    }

    @Test
    void receivesResponsesAtUncataloguedAcsIndexes() throws Exception {
        var config = new AppConfig(AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"), URI.create("http://127.0.0.1:8080"),
                dataDirectory, 8080, true, false, false);
        var app = FunctionalProfileTestInstallation.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(base.resolve(
                            "/p/plan_0123456789ABCDEFGHJKMNPQRS/sp/acs/999999"))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(HttpRequest.BodyPublishers.ofString(
                                    "SAMLResponse=PFJlc3BvbnNlLz4%3D&RelayState=run_unknown"))
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertNotEquals(404, response.statusCode(), response.body());
        } finally {
            app.stop();
        }
    }

    @Test
    void postPageUsesNonceAndEscapesUntrustedValues() {
        var page = HtmlPostPage.render(URI.create("https://sp.example/acs?x=1&y=2"),
                "<response>", "\"relay\"", "nonce-value");
        assertTrue(page.contains("nonce=\"nonce-value\""));
        assertTrue(page.contains("action=\"https://sp.example/acs?x=1&amp;y=2\""));
        assertTrue(page.contains("value=\"&lt;response&gt;\""));
        assertTrue(page.contains("value=\"&quot;relay&quot;\""));
        assertFalse(page.contains("<response>"));

        var requestPage = HtmlPostPage.renderRequest(
                URI.create("https://idp.example/sso"), "request+base64", "sp1:run:action", "probe-nonce");
        assertTrue(requestPage.contains("name=\"SAMLRequest\""));
        assertTrue(requestPage.contains("value=\"request+base64\""));
        assertTrue(requestPage.contains("sp1:run:action"));
        assertFalse(requestPage.contains("name=\"SAMLResponse\""));
    }

    @Test
    void preflightKeepsAnImmutableTargetMetadataSnapshotForEachRun() throws Exception {
        var metadata = """
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://idp.example/entity">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                    <md:SingleSignOnService
                      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                      Location="https://idp.example/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                """;
        var currentMetadata = new java.util.concurrent.atomic.AtomicReference<>(metadata);
        var source = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        source.createContext("/metadata", exchange -> {
            var bytes = currentMetadata.get().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/samlmetadata+xml");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var body = exchange.getResponseBody()) { body.write(bytes); }
        });
        source.start();
        var config = new AppConfig(AppConfig.Mode.SELFHOSTED,
                URI.create("http://127.0.0.1:8080"), URI.create("https://peer.example"),
                dataDirectory, 8080, true, false, false);
        var app = FunctionalProfileTestInstallation.create(config).start(0);
        try {
            var base = URI.create("http://127.0.0.1:" + app.port());
            var client = HttpClient.newHttpClient();
            var requestBody = """
                    {"name":"Snapshot IdP","profile":"browser_sso_idp","targetKind":"IDP",
                     "targetEntityId":"https://idp.example/entity","metadataSourceKind":"URL",
                     "metadataSourceLocation":"http://127.0.0.1:%d/metadata",
                     "suiteMetadataDelivery":"HTTP_URL","declaredFeatures":{},
                     "parameters":{"clockSkewToleranceSeconds":180,"metadataRefreshWaitSeconds":300,"testUserHint":""},
                     "interaction":{"allowBrowserSteps":true,"allowAttestation":true},"authorizedTarget":true}
                    """.formatted(source.getAddress().getPort());
            var created = client.send(HttpRequest.newBuilder(base.resolve("/api/plans"))
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(requestBody)).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, created.statusCode(), created.body());
            var planId = created.body().replaceFirst("(?s).*\"id\":\"(plan_[0-9A-Z]+)\".*", "$1");
            var createdRun = client.send(HttpRequest.newBuilder(base.resolve("/api/plans/" + planId + "/runs"))
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(201, createdRun.statusCode(), createdRun.body());
            var runId = createdRun.body().replaceFirst("(?s).*\"id\":\"(run_[0-9A-Z]+)\".*", "$1");

            var preflight = client.send(HttpRequest.newBuilder(base.resolve("/api/runs/" + runId + "/preflight"))
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, preflight.statusCode(), preflight.body());
            assertTrue(preflight.body().contains("https://peer.example/p/" + planId
                    + "/metadata?probe=" + runId), preflight.body());
            var snapshots = dataDirectory.resolve("target-metadata");
            assertEquals(metadata, Files.readString(snapshots.resolve(planId + ".xml")));
            assertEquals(metadata, Files.readString(snapshots.resolve(runId + ".xml")));

            var changed = metadata.replace("https://idp.example/sso", "https://idp.example/sso-v2");
            currentMetadata.set(changed);
            var repeated = client.send(
                    HttpRequest.newBuilder(base.resolve("/api/runs/" + runId + "/preflight"))
                            .POST(HttpRequest.BodyPublishers.noBody()).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(200, repeated.statusCode(), repeated.body());
            assertEquals(changed, Files.readString(snapshots.resolve(planId + ".xml")));
            assertEquals(metadata, Files.readString(snapshots.resolve(runId + ".xml")));
        } finally {
            app.stop();
            source.stop(0);
        }
    }

    private static int occurrences(String value, String needle) {
        var count = 0;
        var offset = 0;
        while ((offset = value.indexOf(needle, offset)) >= 0) {
            count++;
            offset += needle.length();
        }
        return count;
    }

    private static long regularFiles(Path root) throws java.io.IOException {
        if (!Files.exists(root)) return 0;
        try (var paths = Files.walk(root)) {
            return paths.filter(Files::isRegularFile).count();
        }
    }
}
