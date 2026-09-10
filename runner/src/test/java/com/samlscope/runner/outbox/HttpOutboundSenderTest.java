package com.samlscope.runner.outbox;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboundKind;
import com.samlscope.core.plan.MetadataDeliveryKind;
import com.samlscope.core.plan.MetadataSourceKind;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.TargetKind;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.run.TestRun;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

class HttpOutboundSenderTest {
    private static final Instant NOW = Instant.parse("2026-08-29T00:00:00Z");
    private static final String RUN_ID = "run_0123456789ABCDEFGHJKMNPQRS";
    @TempDir java.nio.file.Path directory;

    @Test
    void sendsBasicOnlyAtTheHttpBoundaryAndRecordsRedactedTranscripts() throws Exception {
        var seenAuthorization = new AtomicReference<String>();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ecp", exchange -> {
            seenAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getRequestBody().readAllBytes();
            var response = "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body/></S:Envelope>"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/xml");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            var recorder = recorder();
            var sender = new HttpOutboundSender(
                    HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), recorder,
                    Clock.fixed(NOW, ZoneOffset.UTC));
            var request = "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\"><S:Body/></S:Envelope>"
                    .getBytes(StandardCharsets.UTF_8);
            var action = new OutboundAction("action_0123456789abcdef0123456789abcdef", OutboundKind.ECP_SOAP,
                    request, URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/ecp"), true);

            var result = sender.send(RUN_ID, action, "alice:secret".getBytes(StandardCharsets.UTF_8));

            assertEquals("Basic YWxpY2U6c2VjcmV0", seenAuthorization.get());
            assertEquals(200, result.details().get("http_status"));
            var entries = recorder.list(RUN_ID);
            assertEquals(2, entries.size());
            var outbound = entries.stream().filter(value -> value.direction()
                    == com.samlscope.core.transcript.Direction.OUTBOUND).findFirst().orElseThrow();
            var inbound = entries.stream().filter(value -> value.direction()
                    == com.samlscope.core.transcript.Direction.INBOUND).findFirst().orElseThrow();
            assertTrue(outbound.headers().get("Authorization").getFirst().contains("redacted: Basic"));
            assertFalse(outbound.headers().toString().contains("YWxpY2U6c2VjcmV0"));
            assertEquals(result.transcriptEntryId(), inbound.id());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rejectsAnOversizedResponseBeforeRecordingIt() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ecp", exchange -> {
            exchange.getRequestBody().readAllBytes();
            var response = new byte[1024 * 1024 + 1];
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            var recorder = recorder();
            var sender = new HttpOutboundSender(HttpClient.newHttpClient(), recorder, Clock.fixed(NOW, ZoneOffset.UTC));
            var action = new OutboundAction("action_0123456789abcdef0123456789abcdea", OutboundKind.ECP_SOAP,
                    "<Envelope/>".getBytes(StandardCharsets.UTF_8),
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/ecp"), true);
            assertThrows(java.io.IOException.class,
                    () -> sender.send(RUN_ID, action, "alice:secret".getBytes(StandardCharsets.UTF_8)));
            assertEquals(1, recorder.list(RUN_ID).size(), "only the redacted outbound entry is retained");
        } finally {
            server.stop(0);
        }
    }

    private FileTranscriptRecorder recorder() {
        var json = new JsonCodec();
        var database = new SqliteDatabase(directory);
        var plan = new TestPlan(
                "plan_0123456789ABCDEFGHJKMNPQRS", "ECP sender", FunctionalProfile.BROWSER_SSO_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://idp.example/entity",
                        new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://idp.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(),
                TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(database, json).save(plan);
        new SqliteRunRepository(database, json).save(new TestRun(
                RUN_ID, plan.id(), RunStatus.RUNNING, Reachability.UNKNOWN, Map.of(), NOW, NOW));
        return new FileTranscriptRecorder(database, json, directory);
    }
}
