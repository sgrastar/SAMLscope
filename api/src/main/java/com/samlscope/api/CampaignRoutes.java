package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.util.Objects;
import com.samlscope.runner.RunCampaignQuery;

/** Read-only projection of evidence campaigns for the selected functional profile. */
public final class CampaignRoutes {
    private CampaignRoutes() {}

    public static void register(JavalinConfig javalin, RunCampaignQuery campaigns) {
        Objects.requireNonNull(javalin, "javalin");
        Objects.requireNonNull(campaigns, "campaigns");
        javalin.routes.get("/api/runs/{id}/campaigns", ctx ->
                ctx.json(campaigns.report(ctx.pathParam("id"))));
    }
}
