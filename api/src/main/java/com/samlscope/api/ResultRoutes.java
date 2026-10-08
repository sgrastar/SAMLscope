package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.util.Objects;
import com.samlscope.runner.result.ResultArtifactQuery;
import com.samlscope.runner.result.ReportArtifactQuery;

/** Isolated public-result route pending the protected composition-root update. */
public final class ResultRoutes {
    private ResultRoutes() {}

    public static void register(JavalinConfig javalin, ResultArtifactQuery results) {
        register(javalin, results, runId -> { throw new IllegalArgumentException("Report artifact is unavailable"); });
    }

    public static void register(
            JavalinConfig javalin, ResultArtifactQuery results, ReportArtifactQuery reports) {
        Objects.requireNonNull(javalin, "javalin");
        Objects.requireNonNull(results, "results");
        Objects.requireNonNull(reports, "reports");
        // All existing mutation routes share this typed conflict; normal unknown-history reads may still serve cached bytes.
        javalin.routes.exception(com.samlscope.runner.HistoricalRunReadPolicy.DefinitionUnavailable.class,
                (error, context) -> unavailable(context,error));
        javalin.routes.get("/api/runs/{id}/result.json", ctx -> {
            byte[] bytes;
            try { bytes = results.require(ctx.pathParam("id")); }
            catch (com.samlscope.runner.HistoricalRunReadPolicy.DefinitionUnavailable unavailable) {
                unavailable(ctx, unavailable); return;
            }
            ctx.contentType("application/json; charset=utf-8");
            ctx.header("Cache-Control", "no-store");
            ctx.header("X-Content-Type-Options", "nosniff");
            ctx.result(bytes);
        });
        javalin.routes.get("/api/runs/{id}/report.html", ctx -> {
            byte[] bytes;
            try { bytes = reports.requireReport(ctx.pathParam("id")); }
            catch (com.samlscope.runner.HistoricalRunReadPolicy.DefinitionUnavailable unavailable) {
                unavailable(ctx, unavailable); return;
            }
            ctx.contentType("text/html; charset=utf-8");
            ctx.header("Content-Disposition", "attachment; filename=\"samlscope-report.html\"");
            ctx.header("Cache-Control", "no-store");
            ctx.header("X-Content-Type-Options", "nosniff");
            ctx.result(bytes);
        });
    }

    private static void unavailable(io.javalin.http.Context context,
            com.samlscope.runner.HistoricalRunReadPolicy.DefinitionUnavailable error) {
        context.header("Cache-Control", "no-store");
        context.header("X-Content-Type-Options", "nosniff");
        context.status(error.httpStatus()).json(java.util.Map.of(
                "code", error.code(), "message", error.getMessage(),
                "readOnlyStored", true, "newRunRequired", true));
    }
}
