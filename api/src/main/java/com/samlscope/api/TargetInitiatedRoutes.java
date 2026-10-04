package com.samlscope.api;

import java.util.Map;
import io.javalin.config.JavalinConfig;

/** Explicit, single-use preparation for messages the target initiates. */
final class TargetInitiatedRoutes {
    private TargetInitiatedRoutes() {}

    static void register(JavalinConfig config,
            java.util.function.Function<String, M1Runtime.TargetInitiatedView> status,
            java.util.function.BiFunction<String, String, M1Runtime.TargetInitiatedView> prepare) {
        config.routes.get("/api/runs/{id}/target-initiated", ctx -> {
            ctx.header("Cache-Control", "no-store");
            var value = status.apply(ctx.pathParam("id"));
            if (value == null) ctx.contentType("application/json").result("null");
            else ctx.json(value);
        });
        config.routes.post("/api/runs/{id}/target-initiated", ctx -> {
            ctx.header("Cache-Control", "no-store");
            ctx.json(prepare.apply(ctx.pathParam("id"), kind(ctx.bodyAsClass(Map.class))));
        });
    }

    static String kind(Map<?, ?> body) {
        if (body == null || !body.keySet().equals(java.util.Set.of("kind"))
                || !(body.get("kind") instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException("The request requires exactly one target-initiated kind");
        }
        return value;
    }
}
