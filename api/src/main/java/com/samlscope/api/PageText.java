package com.samlscope.api;

import io.javalin.http.Context;
import java.util.Locale;

/**
 * Chooses the display language of the server-rendered peer pages from {@code Accept-Language}.
 * Only static page text is translated; server-provided prompts and recorded evidence stay as is.
 * Localize a static template before formatting dynamic values into it, never the finished page.
 */
public final class PageText {
    static final PageText ENGLISH = new PageText(false);
    private static final PageText JAPANESE = new PageText(true);
    static final PageText JAPANESE_FOR_TESTS = JAPANESE;

    private final boolean japanese;

    private PageText(boolean japanese) { this.japanese = japanese; }

    public static PageText from(Context ctx) { return of(ctx.header("Accept-Language")); }

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

    public String localize(String template) {
        if (!japanese) return template;
        var out = template;
        for (var entry : PageTextJa.ENTRIES.entrySet()) out = out.replace(entry.getKey(), entry.getValue());
        return out.replace("lang=\"en\"", "lang=\"ja\"");
    }
}
