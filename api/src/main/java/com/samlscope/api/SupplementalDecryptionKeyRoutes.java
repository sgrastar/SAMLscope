package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;
import com.samlscope.core.caseexec.SupplementalDecryptionKeys;
import com.samlscope.runner.SupplementalDecryptionKeyService.Submission;

/** Explicit Run input endpoints; references are stored without fetching their URLs. */
final class SupplementalDecryptionKeyRoutes {
    private SupplementalDecryptionKeyRoutes() {}

    static void register(JavalinConfig config, Function<String, M1Runtime.SupplementalKeyView> inspect,
            BiFunction<String, Submission, SupplementalDecryptionKeys> submit) {
        config.routes.get("/api/runs/{id}/supplemental-decryption-keys", ctx -> {
            ctx.header("Cache-Control", "no-store");
            ctx.json(inspect.apply(ctx.pathParam("id")));
        });
        config.routes.post("/api/runs/{id}/supplemental-decryption-keys/submit", ctx -> {
            ctx.header("Cache-Control", "no-store");
            ctx.json(submit.apply(ctx.pathParam("id"), request(ctx.bodyAsClass(Map.class))));
        });
    }

    static Submission request(Map<?, ?> body) {
        if (body == null || !body.keySet().equals(Set.of(
                "targetEntityId", "metadataSha256", "sourceUri", "publicKeysSpkiBase64"))) {
            throw new IllegalArgumentException("Public-key input requires target, metadata digest, source and keys");
        }
        if (!(body.get("targetEntityId") instanceof String entity)
                || !(body.get("metadataSha256") instanceof String digest)
                || !(body.get("sourceUri") instanceof String source)
                || !(body.get("publicKeysSpkiBase64") instanceof List<?> keys)
                || keys.isEmpty() || keys.stream().anyMatch(key -> !(key instanceof String))) {
            throw new IllegalArgumentException("Invalid public-key input fields");
        }
        return new Submission(entity, digest, source, keys.stream().map(String.class::cast).toList());
    }
}
