package com.samlscope.api;

import io.javalin.config.JavalinConfig;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import com.samlscope.runner.access.ManagementSessionExecutor;

/** Exchanges a fragment-delivered management secret for an HttpOnly cookie. */
public final class ManagementSessionRoutes {
    public static final String COOKIE_NAME = "__Host-samlscope-management";
    private ManagementSessionRoutes() {}

    public static void register(JavalinConfig javalin, URI publicBase, ManagementSessionExecutor sessions) {
        register(javalin, publicBase, sessions, (run, cookie) -> {
            throw new SecurityException("Session resumption is unavailable");
        });
    }

    public static void register(JavalinConfig javalin, URI publicBase, ManagementSessionExecutor sessions,
            java.util.function.BiFunction<String, String,
                    com.samlscope.runner.access.RunAccessService.ManagementSession> resume) {
        Objects.requireNonNull(javalin, "javalin");
        Objects.requireNonNull(publicBase, "publicBase");
        Objects.requireNonNull(sessions, "sessions");
        Objects.requireNonNull(resume, "resume");
        javalin.routes.post("/api/manage/session", ctx -> {
            if (ctx.queryParam("t") != null || ctx.queryParam("token") != null) {
                ctx.status(400).json(Map.of("error", "token_in_query"));
                return;
            }
            if (!origin(publicBase).equals(ctx.header("Origin"))) {
                ctx.status(403).json(Map.of("error", "invalid_origin"));
                return;
            }
            var request = ctx.bodyAsClass(SessionWrite.class);
            if (request == null) throw new IllegalArgumentException("JSON body is required");
            if (request.resume() && request.token() != null) {
                throw new IllegalArgumentException("Resume must not include an access token");
            }
            var session = request.resume()
                    ? resume.apply(request.runId(), ctx.cookie(COOKIE_NAME))
                    : sessions.exchange(request.runId(), request.token());
            if (!request.resume()) {
                ctx.header("Set-Cookie", COOKIE_NAME + "=" + session.sessionToken()
                        + "; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Strict");
            }
            ctx.header("Cache-Control", "no-store");
            ctx.json(new SessionView(session.runId(), session.csrfToken()));
        });
    }

    private static String origin(URI value) {
        var port = value.getPort();
        return value.getScheme() + "://" + value.getHost() + (port < 0 ? "" : ":" + port);
    }

    record SessionWrite(String runId, String token, boolean resume) {}
    record SessionView(String runId, String csrfToken) {}
}
