package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ResultRoutesTest {
    @Test
    void unavailableHistoricalGenerationIsAFriendlyConflictAndStoredBytesStillRead() throws Exception {
        var unknown = new com.samlscope.core.profile.FunctionalDefinitionIdentity(
                com.samlscope.core.profile.FunctionalProfile.METADATA_IDP,"earlier-c204","sha256:"+"c".repeat(64));
        var policy = new com.samlscope.runner.HistoricalRunReadPolicy(
                new com.samlscope.runner.FunctionalReleaseRegistry(java.util.List.of(),java.util.List.of()));
        var original = "{\n\"stored_scope\":\"earlier-c204\"\n}\n".getBytes(StandardCharsets.UTF_8);
        var app = Javalin.create(config -> ResultRoutes.register(config,
                id -> policy.read(unknown,()-> id.equals("cached")?java.util.Optional.of(original):java.util.Optional.empty(),
                        ()->{throw new AssertionError("Unknown history cannot reconcile or generate");}),
                id -> { throw new com.samlscope.runner.HistoricalRunReadPolicy.DefinitionUnavailable(unknown); })).start(0);
        try {
            var client=HttpClient.newHttpClient();
            var cached=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+app.port()+"/api/runs/cached/result.json")).GET().build(),HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200,cached.statusCode());org.junit.jupiter.api.Assertions.assertArrayEquals(original,cached.body());
            for(String path:java.util.List.of("missing/result.json","missing/report.html")) {
                var unavailable=client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+app.port()+"/api/runs/"+path)).GET().build(),HttpResponse.BodyHandlers.ofString());
                assertEquals(409,unavailable.statusCode());
                org.junit.jupiter.api.Assertions.assertTrue(unavailable.body().contains("historical-definition-unavailable"));
                org.junit.jupiter.api.Assertions.assertFalse(unavailable.body().contains("500"));
            }
        } finally { app.stop(); }
    }

    @Test
    void returnsThePersistedBytesWithoutReserializingThem() throws Exception {
        var expected = "{\n  \"schema_version\": \"1\"\n}\n".getBytes(StandardCharsets.UTF_8);
        var report = "<!doctype html><title>report</title>".getBytes(StandardCharsets.UTF_8);
        var app = Javalin.create(config -> ResultRoutes.register(
                config, ignored -> expected, ignored -> report)).start(0);
        try {
            var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(
                            "http://127.0.0.1:" + app.port()
                                    + "/api/runs/run_0123456789ABCDEFGHJKMNPQRS/result.json"))
                            .GET().build(), HttpResponse.BodyHandlers.ofByteArray());

            assertEquals(200, response.statusCode());
            org.junit.jupiter.api.Assertions.assertArrayEquals(expected, response.body());
            assertEquals("no-store", response.headers().firstValue("cache-control").orElseThrow());
            assertEquals("nosniff", response.headers().firstValue("x-content-type-options").orElseThrow());
            assertEquals("application/json;charset=utf-8",
                    response.headers().firstValue("content-type").orElseThrow());
            var html = HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(
                            "http://127.0.0.1:" + app.port()
                                    + "/api/runs/run_0123456789ABCDEFGHJKMNPQRS/report.html"))
                            .GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, html.statusCode());
            org.junit.jupiter.api.Assertions.assertArrayEquals(report, html.body());
            assertEquals("attachment; filename=\"samlscope-report.html\"",
                    html.headers().firstValue("content-disposition").orElseThrow());
        } finally {
            app.stop();
        }
    }
}
