package com.samlscope.api;

import com.samlscope.store.TranscriptOriginalDigestReader;
import io.javalin.config.JavalinConfig;
import java.util.Objects;
import java.util.function.BiFunction;

/** Read-only identity and digest of a native SAML original; no original content is exposed. */
final class TranscriptOriginalDigestRoutes {
    private TranscriptOriginalDigestRoutes() {}

    static void register(JavalinConfig app,
            BiFunction<String, String, TranscriptOriginalDigestReader.Digest> read) {
        Objects.requireNonNull(read, "read");
        app.routes.get("/api/runs/{id}/transcript/{txId}/original-digest", ctx -> {
            ctx.header("Cache-Control", "no-store");
            ctx.header("X-Content-Type-Options", "nosniff");
            try {
                ctx.json(read.apply(ctx.pathParam("id"), ctx.pathParam("txId")));
            } catch (TranscriptOriginalDigestReader.Unavailable unavailable) {
                ctx.status(404).json(new ApiModels.ErrorView(
                        "transcript_original_unavailable", "Transcript original digest is unavailable"));
            }
        });
    }
}
