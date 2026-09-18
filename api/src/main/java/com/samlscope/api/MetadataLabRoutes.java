package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import com.samlscope.runner.MetadataLabService;

/** Management API for the Suite-controlled side of a standard SAML metadata feed. */
public final class MetadataLabRoutes {
    private MetadataLabRoutes() {}

    public static void register(JavalinConfig javalin, MetadataLabService lab) {
        Objects.requireNonNull(javalin, "javalin");
        Objects.requireNonNull(lab, "lab");
        javalin.routes.get("/api/runs/{id}/metadata-lab", ctx ->
                ctx.json(lab.state(ctx.pathParam("id"))));
        javalin.routes.post("/api/runs/{id}/metadata-lab/variant", ctx -> {
            var body = ctx.bodyAsClass(Map.class);
            if (body == null || !Set.of("variant").equals(body.keySet())
                    || !(body.get("variant") instanceof String variant) || variant.isBlank()) {
                throw new IllegalArgumentException("Metadata lab body must contain only a non-empty variant");
            }
            ctx.json(lab.select(ctx.pathParam("id"), variant));
        });
        javalin.routes.post("/api/runs/{id}/metadata-lab/automatic-polling", ctx -> {
            var body = ctx.bodyAsClass(Map.class);
            if (body == null || (!Set.of("variants").equals(body.keySet())
                    && !Set.of("variants", "pollingDelaySeconds").equals(body.keySet()))
                    || !(body.get("variants") instanceof List<?> values)
                    || values.isEmpty() || values.stream().anyMatch(value -> !(value instanceof String))) {
                throw new IllegalArgumentException(
                        "Automatic polling body must contain a non-empty string variants list "
                                + "and an optional integer pollingDelaySeconds");
            }
            var delay = MetadataLabService.DEFAULT_POLLING_DELAY_SECONDS;
            if (body.containsKey("pollingDelaySeconds")) {
                if (!(body.get("pollingDelaySeconds") instanceof Number value)
                        || value.doubleValue() != value.intValue()) {
                    throw new IllegalArgumentException("pollingDelaySeconds must be an integer");
                }
                delay = value.intValue();
            }
            ctx.json(lab.startAutomaticPolling(
                    ctx.pathParam("id"), values.stream().map(String.class::cast).toList(), delay));
        });
        javalin.routes.post("/api/runs/{id}/metadata-lab/preloaded", ctx -> {
            if (ctx.body().isBlank() || "{}".equals(ctx.body().trim())) {
                ctx.json(lab.startPreloadedCampaign(ctx.pathParam("id")));
                return;
            }
            var body = ctx.bodyAsClass(Map.class);
            if (body == null || !body.keySet().equals(java.util.Set.of("variants"))
                    || !(body.get("variants") instanceof java.util.List<?> values)
                    || values.isEmpty() || values.stream().anyMatch(value -> !(value instanceof String))) {
                throw new IllegalArgumentException("Preloaded body requires only a non-empty string variants list");
            }
            ctx.json(lab.startPreloadedCampaign(ctx.pathParam("id"), values.stream().map(String.class::cast).toList()));
        });
        javalin.routes.post("/api/runs/{id}/metadata-lab/manual-refresh", ctx -> {
            if (!ctx.body().isBlank() && !"{}".equals(ctx.body().trim())) {
                throw new IllegalArgumentException("Manual refresh body must be empty");
            }
            ctx.json(lab.useManualRefresh(ctx.pathParam("id")));
        });
    }
}
