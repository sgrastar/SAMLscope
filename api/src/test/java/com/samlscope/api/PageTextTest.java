package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.javalin.Javalin;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;

class PageTextTest {
    private static final String PAGE = "<!doctype html><html lang=\"en\"><body>"
            + "<p class=\"notice\">Recorded does not mean conformance PASS. "
            + "The approved checks determine the result.</p>"
            + "<details><summary>Technical response details</summary>"
            + "<pre>{note=Technical response details}</pre></details>"
            + "<p>Technical response details</p></body></html>";

    @Test
    void choosesJapaneseOnlyWhenItIsTheMostPreferredLanguage() {
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("ja"));
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("ja-JP,ja;q=0.9,en;q=0.8"));
        assertSame(PageText.JAPANESE_FOR_TESTS, PageText.of("en;q=0.5, ja;q=0.8"));
        assertSame(PageText.ENGLISH, PageText.of("en-US,en;q=0.9,ja;q=0.8"));
        assertSame(PageText.ENGLISH, PageText.of("ja;q=0"));
        assertSame(PageText.ENGLISH, PageText.of("*"));
        assertSame(PageText.ENGLISH, PageText.of("jam"));
        assertSame(PageText.ENGLISH, PageText.of(""));
        assertSame(PageText.ENGLISH, PageText.of(null));
        assertSame(PageText.ENGLISH, PageText.of("ja;q=oops"));
    }

    @Test
    void neverRewritesTheContentOfPreBlocks() {
        var html = PageText.of("ja").localizeHtml(PAGE);
        assertTrue(html.contains("<html lang=\"ja\">"), html);
        assertTrue(html.contains("<pre>{note=Technical response details}</pre>"), html);
        assertTrue(html.contains("<summary>レスポンスの技術的な詳細</summary>"), html);
        assertTrue(html.endsWith("<p>レスポンスの技術的な詳細</p></body></html>"), html);
        assertFalse(html.contains("Recorded does not mean"));
        assertEquals(PAGE, PageText.ENGLISH.localizeHtml(PAGE));
    }

    @Test
    void japaneseEntriesAreCompleteAndKeepTheSafetyMeaning() {
        for (var entry : PageTextJa.ENTRIES.entrySet()) {
            assertFalse(entry.getValue().isBlank(), entry.getKey());
        }
        assertEquals("記録されたことは、適合（PASS）を意味しません。結果は承認済みのチェックによって決まります。",
                PageTextJa.ENTRIES.get(
                        "Recorded does not mean conformance PASS. The approved checks determine the result."));
    }

    @Test
    void servesJapaneseOnlyOnPeerAndLoginHtmlWhenRequested() throws Exception {
        var app = Javalin.create(config -> {
            PageText.register(config);
            config.routes.get("/p/page", ctx -> ctx.contentType("text/html; charset=utf-8").result(PAGE));
            config.routes.get("/p/data", ctx -> ctx.contentType("application/json").result(PAGE));
            config.routes.get("/api/page", ctx -> ctx.contentType("text/html; charset=utf-8").result(PAGE));
        }).start(0);
        try {
            var http = HttpClient.newHttpClient();
            assertEquals(PageText.of("ja").localizeHtml(PAGE), fetch(http, app.port(), "/p/page", "ja-JP,ja;q=0.9"));
            assertEquals(PAGE, fetch(http, app.port(), "/p/page", "en-US,en;q=0.9"));
            assertEquals(PAGE, fetch(http, app.port(), "/p/page", null));
            assertEquals(PAGE, fetch(http, app.port(), "/p/data", "ja"));
            assertEquals(PAGE, fetch(http, app.port(), "/api/page", "ja"));
        } finally {
            app.stop();
        }
    }

    private static String fetch(HttpClient http, int port, String path, String language) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
        if (language != null) request.header("Accept-Language", language);
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString()).body();
    }
}
