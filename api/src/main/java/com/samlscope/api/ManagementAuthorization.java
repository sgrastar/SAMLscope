package com.samlscope.api;

import com.samlscope.api.auth.OidcConfig.AccessPolicy;
import com.samlscope.api.auth.OidcRoutes;
import com.samlscope.api.auth.OidcSessions;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.RunRepository;
import com.samlscope.store.SqlitePlanOwnerRepository;
import io.javalin.http.Context;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Optional;

/** Account ownership and the existing per-Run capability are independent authorization paths. */
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
        if (oidc.config().enabled() && oidc.config().accessPolicy() == AccessPolicy.REQUIRED && session.isEmpty()) {
            throw new SecurityException("Sign in to manage Runs");
        }
        return session;
    }
    String creationOwner(Context ctx, String anonymousOwner) {
        var session = session(ctx);
        if (oidc.config().enabled()) {
            if (session.isEmpty() && oidc.config().accessPolicy() == AccessPolicy.NEW_PLANS) {
                throw new SecurityException("Sign in to create a Plan");
            }
            oidc.requireOrigin(ctx);
            session.ifPresent(s -> oidc.requireMutation(ctx, s));
        }
        return session.map(s -> s.identity().ownerId()).orElse(anonymousOwner);
    }
    String connectionOwner(Context ctx, boolean mutation, boolean protectedManagement) {
        if (!protectedManagement) return "local-operator";
        var current = session(ctx).orElseThrow(
                () -> new SecurityException("Sign in to reuse target connections"));
        if (mutation) oidc.requireMutation(ctx, current);
        return current.identity().ownerId();
    }
    void authorizeRun(Context ctx, boolean mutation) {
        var current = session(ctx);
        var run = runs.find(ctx.pathParam("id"));
        if (run.isPresent() && owns(current, run.get().planId())) {
            if (mutation) oidc.requireMutation(ctx, current.orElseThrow());
            return;
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
        if (mutation) legacy.authorizePlanMutation(ctx.pathParam("id"),
                ctx.cookie(ManagementSessionRoutes.COOKIE_NAME), ctx.header("X-CSRF-Token"));
        else legacy.authorizePlan(ctx.pathParam("id"), ctx.cookie(ManagementSessionRoutes.COOKIE_NAME));
    }
    List<TestPlan> list(Context ctx) {
        if (!oidc.config().enabled()) return legacy.authorizedPlans(ctx.cookie(ManagementSessionRoutes.COOKIE_NAME));
        var result = new LinkedHashMap<String, TestPlan>();
        session(ctx).ifPresent(s -> owners.ownedPlans(s.identity().ownerId()).forEach(id ->
                plans.find(id).ifPresent(plan -> result.put(plan.id(), plan))));
        try {
            legacy.authorizedPlans(ctx.cookie(ManagementSessionRoutes.COOKIE_NAME))
                    .forEach(plan -> result.put(plan.id(), plan));
        } catch (SecurityException noCapability) {
            // A new account or anonymous visitor has no visible Plans until one is created.
        }
        return List.copyOf(result.values());
    }
    private boolean owns(Optional<OidcSessions.Session> current, String planId) {
        return current.isPresent() && owners.ownedPlans(current.get().identity().ownerId()).contains(planId);
    }
}
