package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.Direction;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;
import com.samlscope.store.TranscriptOriginalDigestReader;
import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TranscriptOriginalDigestRoutesTest {
    @TempDir Path temporary;
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    private static final byte[] XML = ("<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
            + "ID='_private-protocol-sentinel'/>").getBytes(StandardCharsets.UTF_8);

    @Test
    void actualRecorderOriginalIsReturnedAsDigestOnlyWithoutStateMutation() throws Exception {
        var directory = temporary.toRealPath();
        var database = new SqliteDatabase(directory);
        var json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Owned digest API control",
                FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        var runs = new SqliteRunRepository(database, json);
        var run = new TestRun(RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW);
        runs.save(run);
        var recorder = new FileTranscriptRecorder(database, json, directory);
        var original = recorder.record(new TranscriptInput(RUN, Direction.INBOUND, NOW, "_request", "POST",
                "https://suite.example/sp/acs/0", 200, Map.of("Cookie", java.util.List.of("owned=private-cookie-sentinel")),
                new byte[0], "application/xml", null, XML, Map.of("type", "Response")));
        var reader = new TranscriptOriginalDigestReader(database, json, directory);
        var before = recorder.list(RUN);
        var app = Javalin.create(config -> TranscriptOriginalDigestRoutes.register(config, reader::read)).start(0);
        try {
            var result = get(app, RUN, original.id());
            assertEquals(200, result.statusCode());
            assertEquals("no-store", result.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("nosniff", result.headers().firstValue("X-Content-Type-Options").orElseThrow());
            var body = json.mapper().readTree(result.body());
            assertEquals(RUN, body.path("runId").asText()); assertEquals(original.id(), body.path("txId").asText());
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(XML)),
                    body.path("decodedSamlSha256").asText());
            assertEquals(XML.length, body.path("decodedSamlBytes").asInt());
            var fields = new java.util.HashSet<String>(); body.fieldNames().forEachRemaining(fields::add);
            assertEquals(Set.of("schema", "runId", "txId", "decodedSamlSha256", "decodedSamlBytes"), fields);
            assertFalse(result.body().contains("sentinel")); assertFalse(result.body().contains("Cookie"));
            assertEquals(before, recorder.list(RUN)); assertEquals(run, runs.find(RUN).orElseThrow());
        } finally { app.stop(); }
    }

    @Test
    void unavailableDigestReturnsOnlyTheFixedErrorAndNoStoreHeaders() throws Exception {
        var app = Javalin.create(config -> TranscriptOriginalDigestRoutes.register(config,
                (run, tx) -> { throw new TranscriptOriginalDigestReader.Unavailable(); })).start(0);
        try {
            var result = get(app, RUN, "tx_00000000000000000000000000");
            assertEquals(404, result.statusCode());
            assertEquals("no-store", result.headers().firstValue("Cache-Control").orElseThrow());
            assertEquals("nosniff", result.headers().firstValue("X-Content-Type-Options").orElseThrow());
            assertEquals("{\"error\":\"transcript_original_unavailable\",\"message\":\"Transcript original digest is unavailable\"}", result.body());
        } finally { app.stop(); }
    }

    private static HttpResponse<String> get(Javalin app, String run, String tx) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + app.port()
                + "/api/runs/" + run + "/transcript/" + tx + "/original-digest")).build(), HttpResponse.BodyHandlers.ofString());
    }
}
