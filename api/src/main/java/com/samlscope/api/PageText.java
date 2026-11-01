package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import io.javalin.http.Context;
import java.util.Locale;

/**
 * Chooses the display language of the server-rendered peer pages from {@code Accept-Language}.
 * Only static page text is translated: server-provided prompts stay English and the content of
 * {@code <pre>} blocks, which shows recorded evidence verbatim, is never rewritten.
 */
public final class PageText {
    static final PageText ENGLISH = new PageText(false);
    private static final PageText JAPANESE = new PageText(true);
    static final PageText JAPANESE_FOR_TESTS = JAPANESE;

    private final boolean japanese;

    private PageText(boolean japanese) { this.japanese = japanese; }

    public static PageText from(Context ctx) { return of(ctx.header("Accept-Language")); }

    /** Localizes the HTML pages served by the peer ({@code /p/}) and login ({@code /auth/}) routes. */
    public static void register(JavalinConfig javalin) {
        javalin.routes.after(ctx -> {
            var path = ctx.path();
            if (!path.startsWith("/p/") && !path.startsWith("/auth/")) return;
            var type = ctx.res().getContentType();
            if (type == null || !type.toLowerCase(Locale.ROOT).startsWith("text/html")) return;
            var text = from(ctx);
            if (text == ENGLISH) return;
            var html = ctx.result();
            if (html == null) return;
            ctx.result(text.localizeHtml(html));
        });
    }

    static PageText of(String acceptLanguage) {
        if (acceptLanguage == null) return ENGLISH;
        String best = null;
        var bestQuality = 0.0;
        for (var part : acceptLanguage.split(",")) {
            var fields = part.trim().split(";");
            var tag = fields[0].trim().toLowerCase(Locale.ROOT);
            var quality = 1.0;
            for (var index = 1; index < fields.length; index++) {
                var field = fields[index].trim();
                if (field.startsWith("q=")) {
                    try { quality = Double.parseDouble(field.substring(2)); }
                    catch (NumberFormatException invalid) { quality = 0; }
                }
            }
            if (tag.isEmpty() || "*".equals(tag) || quality <= bestQuality) continue;
            best = tag;
            bestQuality = quality;
        }
        return best != null && (best.equals("ja") || best.startsWith("ja-")) ? JAPANESE : ENGLISH;
    }

    /** Localizes everything outside {@code <pre>} blocks. */
    String localizeHtml(String html) {
        var out = new StringBuilder();
        var from = 0;
        while (true) {
            var open = html.indexOf("<pre", from);
            var close = open < 0 ? -1 : html.indexOf("</pre>", open);
            if (close < 0) {
                out.append(localize(html.substring(from)));
                return out.toString();
            }
            close += "</pre>".length();
            out.append(localize(html.substring(from, open))).append(html, open, close);
            from = close;
        }
    }

    String localize(String template) {
        if (!japanese) return template;
        var out = template;
        for (var entry : PageTextJa.ENTRIES.entrySet()) out = out.replace(entry.getKey(), entry.getValue());
        return out.replace("lang=\"en\"", "lang=\"ja\"");
    }
}
