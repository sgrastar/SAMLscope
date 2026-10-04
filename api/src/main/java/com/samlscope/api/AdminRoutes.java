package com.samlscope.api;

import com.samlscope.core.plan.PlanRepository;
import com.samlscope.store.*;
import io.javalin.config.JavalinConfig;
import java.time.Clock;
import java.time.Duration;

/** Local application administration. Never modifies the provider's account. */
final class AdminRoutes {
    static void register(JavalinConfig javalin, ManagementAuthorization authorization, SqliteUserRepository users,
                         SqlitePlanOwnerRepository owners, PlanRepository plans, FileTranscriptRecorder recorder,
                         AppConfig config, Clock clock) {
        javalin.routes.before("/api/admin/*", ctx -> {
            ctx.header("Cache-Control", "no-store");
            authorization.requireAdmin(ctx, !ctx.method().name().equals("GET"));
        });
        javalin.routes.get("/api/admin/users", ctx -> ctx.json(users.list().stream().map(user -> {
            var used = user.lastUsedAt() == null ? user.createdAt() : user.lastUsedAt();
            var expires = user.role() == SqliteUserRepository.Role.ANONYMOUS
                    ? java.time.Instant.parse(used).plus(Duration.ofDays(30)) : null;
            return new UserView(user, expires == null ? null : expires.toString(),
                    expires != null && !expires.isAfter(clock.instant()));
        }).toList()));
        javalin.routes.put("/api/admin/users/{id}", ctx -> {
            var input = ctx.bodyAsClass(UserWrite.class);
            if (input == null) throw new IllegalArgumentException("Account update is required");
            ctx.json(users.update(ctx.pathParam("id"), input.displayName(), input.role(), input.version(), clock.instant()));
        });
        javalin.routes.delete("/api/admin/users/{id}", ctx -> {
            var input = ctx.bodyAsClass(DeleteWrite.class);
            if (input == null) throw new IllegalArgumentException("Account version is required");
            var id = ctx.pathParam("id");
            users.beginDeletion(id, input.version());
            for (var plan : owners.ownedPlans(id)) recorder.deletePlanAndEvidence(plan);
            users.finishDeletion(id);
            ctx.status(204);
        });
        javalin.routes.get("/api/admin/plans", ctx -> ctx.json(plans.list().stream()
                .map(plan -> new PlanView(SamlScopeApplication.view(config, plan), owners.ownerOf(plan.id()), plan.createdAt().toString())).toList()));
        javalin.routes.delete("/api/admin/plans/{id}", ctx -> {
            ctx.status(recorder.deletePlanAndEvidence(ctx.pathParam("id")) ? 204 : 404);
        });
        javalin.routes.exception(SqliteUserRepository.Conflict.class, (e, ctx) ->
                ctx.status(409).json(new ApiModels.ErrorView("account_conflict", e.getMessage())));
    }
    record UserWrite(String displayName, SqliteUserRepository.Role role, long version) {}
    record DeleteWrite(long version) {}
    record UserView(SqliteUserRepository.User user, String expiresAt, boolean expiryCandidate) {}
    record PlanView(ApiModels.PlanView plan, String ownerId, String createdAt) {}
}
