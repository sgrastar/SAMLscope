package com.samlscope.api.auth;

import io.javalin.config.JavalinConfig;
import io.javalin.http.Context;
import java.net.URI;
import java.util.Map;
import java.util.Optional;

public final class OidcRoutes {
    public static final String COOKIE = "__Host-samlscope-login";
    public static final String LOGIN_COOKIE = "__Host-samlscope-login-state";
    public static final String CSRF_HEADER = "X-OIDC-CSRF-Token";
    private final OidcConfig config;
    private final URI publicBase;
    private final OidcClient client;
    private final OidcSessions sessions;

    public OidcRoutes(OidcConfig config, URI publicBase, OidcClient client, OidcSessions sessions) {
        this.config = config;
        this.publicBase = publicBase;
        this.client = client;
        this.sessions = sessions;
    }
    public OidcConfig config() { return config; }
    public Optional<OidcSessions.Session> session(Context ctx) {
        return config.enabled() ? sessions.find(ctx.cookie(COOKIE)) : Optional.empty();
    }
    public void requireMutation(Context ctx, OidcSessions.Session session) {
        requireOrigin(ctx);
        sessions.requireCsrf(session, ctx.header(CSRF_HEADER));
    }
    public void requireOrigin(Context ctx) {
        var origin = publicBase.getScheme().toLowerCase(java.util.Locale.ROOT) + "://"
                + publicBase.getHost().toLowerCase(java.util.Locale.ROOT)
                + (publicBase.getPort() < 0 || publicBase.getPort() == 443 ? "" : ":" + publicBase.getPort());
        if (!origin.equals(ctx.header("Origin"))) {
            throw new SecurityException("Invalid application origin");
        }
    }
    public void register(JavalinConfig javalin) {
        javalin.routes.get("/auth/session", ctx -> {
            ctx.header("Cache-Control", "no-store");
            var current = session(ctx);
            ctx.json(current.<Object>map(s -> new SessionView(true, true, config.accessPolicy().name().toLowerCase(),
                    s.identity().displayName(), s.csrfToken())).orElseGet(() ->
                    new SessionView(config.enabled(), false, config.accessPolicy().name().toLowerCase(), null, null)));
        });
        if (!config.enabled()) return;
        javalin.routes.before("/auth/*", ctx -> ctx.header("Cache-Control", "no-store"));
        javalin.routes.get("/auth/login", ctx -> {
            var login = sessions.start(ctx.cookie(LOGIN_COOKIE));
            cookie(ctx, LOGIN_COOKIE, login.binding(), 300);
            ctx.redirect(client.authorizationUri(login.state(), login.nonce(), login.verifier()).toString());
        });
        javalin.routes.get("/auth/callback", ctx -> {
            try {
                var state = single(ctx, "state", true);
                var pending = sessions.consume(state, ctx.cookie(LOGIN_COOKIE));
                cookie(ctx, LOGIN_COOKIE, "", 0);
                var issuer = single(ctx, "iss", false);
                if ((client.requiresResponseIssuer() && issuer == null)
                        || (issuer != null && !issuer.equals(config.issuer().toString()))) throw new SecurityException();
                if (single(ctx, "error", false) != null) throw new SecurityException();
                var code = single(ctx, "code", true);
                if (code.length() > 8192) throw new SecurityException();
                var identity = client.exchange(code, pending.nonce(), pending.verifier());
                var raw = sessions.signIn(identity, ctx.cookie(COOKIE));
                cookie(ctx, COOKIE, raw, (int) OidcSessions.SESSION_LIFETIME.toSeconds());
                ctx.redirect("/");
            } catch (Exception failure) {
                // Never echo provider error_description, authorization codes, or token parse errors.
                ctx.status(400).contentType("text/html; charset=utf-8")
                        .result("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Login failed</title>"
                                + "<h1>Login could not be completed</h1><p>The request expired or was rejected.</p>"
                                + "<a href=\"/auth/login\">Try signing in again</a></html>");
            }
        });
        javalin.routes.post("/auth/logout", ctx -> {
            var current = session(ctx).orElseThrow(() -> new SecurityException("Not signed in"));
            requireMutation(ctx, current);
            sessions.logout(ctx.cookie(COOKIE));
            cookie(ctx, COOKIE, "", 0);
            cookie(ctx, LOGIN_COOKIE, "", 0);
            cookie(ctx, "__Host-samlscope-management", "", 0);
            ctx.status(204);
        });
        javalin.routes.exception(OidcSessions.CapacityExceeded.class, (error, ctx) ->
                ctx.status(503).header("Retry-After", "30").json(Map.of("message", error.getMessage())));
    }
    private static String single(Context ctx, String name, boolean required) {
        var values = ctx.queryParams(name);
        if (values.size() > 1 || (required && (values.isEmpty() || values.getFirst().isBlank()))) {
            throw new SecurityException("Invalid login response");
        }
        return values.isEmpty() ? null : values.getFirst();
    }
    private static void cookie(Context ctx, String name, String value, int maxAge) {
        // Lax permits the top-level GET callback from the provider; no shared Domain cookie.
        ctx.res().addHeader("Set-Cookie", name + "=" + value
                + "; Path=/; Max-Age=" + maxAge + "; Secure; HttpOnly; SameSite=Lax");
    }
    public record SessionView(boolean enabled, boolean authenticated, String accessPolicy,
                               String displayName, String csrfToken) {}
}
