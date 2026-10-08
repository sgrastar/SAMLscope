package com.samlscope.runner.outbox;

import static org.junit.jupiter.api.Assertions.*;
import com.sun.net.httpserver.HttpServer;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.run.*;
import com.samlscope.core.transcript.*;
import com.samlscope.store.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class MetadataFetchOutboundSenderTest {
    static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    static final Instant NOW = Instant.parse("2026-10-08T00:00:00Z");
    @TempDir Path folder;
    FileTranscriptRecorder recorder() {
        var db = new SqliteDatabase(folder); var json = new JsonCodec();
        var plan = new TestPlan("plan_0123456789ABCDEFGHJKMNPQRS", "Example", FunctionalProfile.METADATA_IDP,
                new TestPlan.Target(TargetKind.IDP, "https://target.example/entity", new TestPlan.MetadataSource(MetadataSourceKind.URL, "https://target.example/metadata")),
                MetadataDeliveryKind.MANUAL, Map.of(), TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), NOW, NOW);
        new SqlitePlanRepository(db, json).save(plan); new SqliteRunRepository(db, json).save(new TestRun(RUN, plan.id(), RunStatus.COMPLETED, Reachability.CONFIRMED, Map.of(), NOW, NOW));
        return new FileTranscriptRecorder(db, json, folder);
    }
    @Test void metadataDelegationDoesNotInheritParentCredentialsCookiesOrRedirects() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var seen = new AtomicReference<Map<String, List<String>>>();
        byte[] body = "<x:document xmlns:x='urn:test:reference'/>".getBytes(StandardCharsets.UTF_8);
        server.createContext("/document", e -> { seen.set(Map.copyOf(e.getRequestHeaders()));
            e.getResponseHeaders().set("Content-Type", "application/xml"); e.getResponseHeaders().set("Set-Cookie", "secret-cookie-sentinel");
            e.getResponseHeaders().set("Authorization", "secret-header-sentinel");
            e.sendResponseHeaders(200, body.length); e.getResponseBody().write(body); e.close(); }); server.start();
        try {
            var url = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/document");
            var cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
            cookies.getCookieStore().add(url, new HttpCookie("parent", "secret-parent-cookie"));
            var parent = HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER)
                    .authenticator(new Authenticator() { @Override protected PasswordAuthentication getPasswordAuthentication() {
                        throw new AssertionError("Parent authenticator must not be inherited"); } }).build();
            var recorder = recorder(); var sender = new HttpOutboundSender(parent, recorder, Clock.fixed(NOW, ZoneOffset.UTC));
            var result = sender.send(RUN, action(url), new byte[0]);
            assertTrue(seen.get().keySet().stream().noneMatch(k -> Set.of("cookie", "authorization").contains(k.toLowerCase(Locale.ROOT))));
            var response = recorder.list(RUN).stream().filter(e -> e.id().equals(result.transcriptEntryId())).findFirst().orElseThrow();
            assertArrayEquals(body, recorder.readBody(response));
            assertEquals(response.samlSummary().get("body_sha256"), response.samlSummary().get("original_body_sha256"));
            assertTrue(response.headers().keySet().stream().noneMatch(k -> Set.of("set-cookie", "authorization").contains(k.toLowerCase(Locale.ROOT))));
        } finally { server.stop(0); }
    }
    @Test void suppliedCredentialUnsafeUrlsAndPayloadAreRejectedBeforeNetwork() throws Exception {
        var recorder = recorder(); var sender = new MetadataFetchOutboundSender(recorder, Clock.fixed(NOW, ZoneOffset.UTC));
        var url = URI.create("http://127.0.0.1:1/document");
        assertThrows(IllegalArgumentException.class, () -> sender.send(RUN, action(url), new byte[]{1}));
        for (String value : List.of("http://alice:password@localhost/document", "http://localhost/document?token=secret", "file:///tmp/metadata", "http://localhost/document#fragment"))
            assertThrows(IllegalArgumentException.class, () -> sender.send(RUN, action(URI.create(value)), null));
        assertThrows(IllegalArgumentException.class, () -> sender.send(RUN,
                new OutboundAction("action_0123456789abcdef0123456789abcdef", OutboundKind.METADATA_FETCH, new byte[]{1}, url, false), null));
        assertTrue(recorder.list(RUN).isEmpty());
    }
    @Test void knownCredentialQueryNamesAndTheirEncodedVariantsAreRejectedBeforeRecording() {
        var recorder = recorder(); var sender = new MetadataFetchOutboundSender(recorder, Clock.fixed(NOW, ZoneOffset.UTC));
        for (String key : List.of("access_token", "ACCESS-TOKEN", "AccessToken", "%61ccess%5Ftoken",
                "refresh_token", "REFRESH-TOKEN", "refresh%2dtoken", "client_secret", "Client-Secret",
                "%43LIENT%5FSECRET", "api_key", "API-KEY", "apikey", "api%5fkey", "API%2dKEY",
                "id_token", "auth-token", "bearer_token", "session-token", "api_secret", "authorization", "credentials")) {
            var url = URI.create("http://127.0.0.1:1/document?" + key + "=opaque");
            assertFalse(MetadataFetchOutboundSender.supported(url));
            assertThrows(IllegalArgumentException.class, () -> sender.send(RUN, action(url), null));
        }
        assertTrue(recorder.list(RUN).isEmpty());
    }
    @Test void ordinaryQueriesAreAllowedWithoutRewritingTheirRawBytes() {
        var url = URI.create("https://target.example/reference?realm=example&entityID=urn%3Atest%3Aentity&client_id=public");
        String original = url.toString();
        assertTrue(MetadataFetchOutboundSender.supported(url));
        assertEquals(original, url.toString());
    }
    @Test void timeoutAndBodyLimitLeaveSuiteUncertaintyRatherThanAResponseOracle() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/large", e -> { var body = "<x:document xmlns:x='urn:test:reference'/>".getBytes(StandardCharsets.UTF_8);
            e.sendResponseHeaders(200, body.length); e.getResponseBody().write(body); e.close(); });
        server.createContext("/slow", e -> { try { Thread.sleep(150); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); } e.close(); });
        server.start();
        try {
            var recorder = recorder(); var sender = new MetadataFetchOutboundSender(recorder, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMillis(50), 8);
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            assertThrows(java.io.IOException.class, () -> sender.send(RUN, action(URI.create(base + "/large")), null));
            assertThrows(HttpTimeoutException.class, () -> sender.send(RUN, action(URI.create(base + "/slow")), null));
            assertTrue(recorder.list(RUN).stream().allMatch(e -> e.direction() == Direction.OUTBOUND));
        } finally { server.stop(0); }
    }
    static OutboundAction action(URI url) { return new OutboundAction("action_0123456789abcdef0123456789abcdef", OutboundKind.METADATA_FETCH, new byte[0], url, false); }
}
