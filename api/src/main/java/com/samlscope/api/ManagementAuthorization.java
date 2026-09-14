package com.samlscope.api;

import com.samlscope.api.auth.OidcRoutes;
import com.samlscope.api.auth.OidcSessions;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunRepository;
import com.samlscope.store.SqlitePlanOwnerRepository;
import io.javalin.http.Context;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/** OIDC uses account authorization exclusively. Secret capabilities only apply with OIDC disabled. */
final class ManagementAuthorization {
    private final OidcRoutes oidc;
    private final SqlitePlanOwnerRepository owners;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final M1Runtime legacy;

    ManagementAuthorization(OidcRoutes oidc, SqlitePlanOwnerRepository owners,
                            PlanRepository plans, RunRepository runs, M1Runtime legacy) {
        this.oidc = oidc;
        this.owners = owners;
        this.plans = plans;
        this.runs = runs;
        this.legacy = legacy;
    }
    Optional<OidcSessions.Session> session(Context ctx) {
        var session = oidc.session(ctx);
        if (oidc.config().enabled() && session.isEmpty()) {
            throw new SecurityException("Sign in to manage Runs");
        }
        return session;
    }
    String creationOwner(Context ctx, String anonymousOwner) {
        var session = session(ctx);
        if (oidc.config().enabled()) {
            oidc.requireOrigin(ctx);
            session.ifPresent(s -> oidc.requireMutation(ctx, s));
        }
        return session.map(s -> s.identity().ownerId()).orElse(anonymousOwner);
    }
    String connectionOwner(Context ctx, boolean mutation, boolean protectedManagement) {
        if (!protectedManagement) return "local-operator";
        var current = session(ctx);
        if (current.isEmpty()) {
            if (!oidc.config().enabled() && mutation) return anonymousOwner(ctx.ip());
            throw new SecurityException("Sign in to reuse target connections");
        }
        if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
        return current.orElseThrow().identity().ownerId();
    }
    void authorizeRun(Context ctx, boolean mutation) {
        var current = session(ctx);
        var run = runs.find(ctx.pathParam("id"));
        if (run.isPresent() && owns(current, run.get().planId())) {
            if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
            return;
        }
        if (oidc.config().enabled()) {
            if (!mutation && isAdmin(current)) return;
            throw new SecurityException("Owner access required");
        }
        if (mutation) legacy.authorizeMutation(ctx.pathParam("id"),
                ctx.cookie(ManagementSessionRoutes.COOKIE_NAME), ctx.header("X-CSRF-Token"));
        else legacy.authorize(ctx.pathParam("id"), ctx.cookie(ManagementSessionRoutes.COOKIE_NAME));
    }
    void authorizePlan(Context ctx, boolean mutation) {
        var current = session(ctx);
        if (owns(current, ctx.pathParam("id"))) {
            if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
            return;
        }
        if (oidc.config().enabled()) {
            if (isAdmin(current) && (!mutation || ctx.method().name().equals("DELETE"))) {
                if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
                return;
            }
            throw new SecurityException("Owner access required");
        }
        if (mutation) legacy.authorizePlanMutation(ctx.pathParam("id"),
                ctx.cookie(ManagementSessionRoutes.COOKIE_NAME), ctx.header("X-CSRF-Token"));
        else legacy.authorizePlan(ctx.pathParam("id"), ctx.cookie(ManagementSessionRoutes.COOKIE_NAME));
    }
    List<TestPlan> list(Context ctx) {
        if (!oidc.config().enabled()) return legacy.authorizedPlans(ctx.cookie(ManagementSessionRoutes.COOKIE_NAME));
        var current = session(ctx);
        if (isAdmin(current)) return plans.list();
        return owners.ownedPlans(current.orElseThrow().identity().ownerId()).stream()
                .map(plans::find).flatMap(Optional::stream).toList();
    }
    boolean isAdmin(Optional<OidcSessions.Session> session) {
        return session.isPresent() && oidc.user(session.orElseThrow()).role() == com.samlscope.store.SqliteUserRepository.Role.ADMIN;
    }
    OidcSessions.Session requireAdmin(Context ctx, boolean mutation) {
        var current = session(ctx);
        if (!isAdmin(current)) throw new SecurityException("Admin access required");
        if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
        return current.orElseThrow();
    }
    private boolean owns(Optional<OidcSessions.Session> current, String planId) {
        return current.isPresent() && owners.ownedPlans(current.get().identity().ownerId()).contains(planId);
    }

    private static String anonymousOwner(String sourceAddress) {
        try {
            var digest = MessageDigest.getInstance("SHA-256")
                    .digest(sourceAddress.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
