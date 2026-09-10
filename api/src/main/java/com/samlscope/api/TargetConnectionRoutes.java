package com.samlscope.api;

import com.samlscope.core.plan.TargetConnection;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.Identifiers;
import com.samlscope.saml.metadata.TargetConnectionMetadata;
import com.samlscope.store.SqliteTargetConnectionRepository;
import java.time.Clock;
import java.util.List;
import java.util.Set;

final class TargetConnectionRoutes {
    record Write(String name, String entityId, String metadataXml, String metadataUrl, boolean authorizedTarget, String sourceRevisionId) {}
    record RevisionView(String id, Set<TargetRole> roles, String sha256, boolean refreshable) {}
    record View(String id, String name, String entityId, List<RevisionView> revisions) {}
    static void register(io.javalin.config.JavalinConfig app, AppConfig config,
            ManagementAuthorization auth, SqliteTargetConnectionRepository repository, Clock clock, com.samlscope.runner.PreflightService preflight, HostedRateLimiter limiter) {
        app.routes.before("/api/targets", ctx -> ctx.header("Cache-Control","no-store"));
        app.routes.before("/api/targets/{id}/revisions", ctx -> ctx.header("Cache-Control","no-store"));
        app.routes.get("/api/targets", ctx -> {
            var owner = auth.connectionOwner(ctx, false, config.managementProtected());
            ctx.json(repository.list(owner).stream().map(t -> view(repository, t)).toList());
        });
        app.routes.post("/api/targets", ctx -> {
            var owner = auth.connectionOwner(ctx, true, config.managementProtected());
            var input = ctx.bodyAsClass(Write.class);
            if (!input.authorizedTarget()) throw new IllegalArgumentException("Authorization to test the target is required");
            var target = new TargetConnection(Identifiers.newId("target"), owner, input.name(), input.entityId(), clock.instant());
            if (config.targetImportsPerHour() > 0) limiter.requireAllowed("target-import", owner,
                    config.targetImportsPerHour(), java.time.Duration.ofHours(1));
            var revision = accept(target, input, clock, preflight);
            repository.createWithRevision(target, revision);
            ctx.status(201).json(view(repository, target));
        });
        app.routes.post("/api/targets/{id}/revisions", ctx -> {
            var owner = auth.connectionOwner(ctx, true, config.managementProtected());
            var target = repository.list(owner).stream().filter(t -> t.id().equals(ctx.pathParam("id")))
                    .findFirst().orElseThrow(() -> new io.javalin.http.NotFoundResponse("Target connection unavailable"));
            var input = ctx.bodyAsClass(Write.class);
            if (!input.authorizedTarget()) throw new IllegalArgumentException("Authorization to test the target is required");
            if (input.entityId() != null && !target.entityId().equals(input.entityId()))
                throw new IllegalArgumentException("Register a separate connection for a different entityID");
            if (config.targetImportsPerHour() > 0) limiter.requireAllowed("target-import", owner,
                    config.targetImportsPerHour(), java.time.Duration.ofHours(1));
            if (input.metadataXml() == null && input.metadataUrl() == null) {
                var previous = (input.sourceRevisionId() == null
                        ? repository.latestRevision(owner, target.id())
                        : repository.findRevision(owner, target.id(), input.sourceRevisionId()))
                        .orElseThrow(() -> new IllegalArgumentException("Saved metadata revision unavailable"));
                if (previous.privateSourceUrl() == null)
                    throw new IllegalArgumentException("No saved metadata source; supply XML or a URL");
                input = new Write(input.name(), target.entityId(), null, previous.privateSourceUrl(), true, previous.id());
            }
            var revision = accept(target, input, clock, preflight);
            repository.appendRevision(owner, revision);
            ctx.status(201).json(view(repository, target));
        });
    }
    private static TargetConnection.Revision accept(TargetConnection target, Write input, Clock clock,
            com.samlscope.runner.PreflightService preflight) throws Exception {
        if ((input.metadataXml() == null) == (input.metadataUrl() == null))
            throw new IllegalArgumentException("Supply metadata XML or a URL");
        byte[] bytes = input.metadataXml() == null ? null : input.metadataXml().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (bytes == null) {
            try {
                bytes = preflight.retrieveMetadata(java.net.URI.create(input.metadataUrl()));
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw interrupted;
            } catch (Exception invalid) {
                throw new IllegalArgumentException("Target metadata could not be retrieved", invalid);
            }
        }
        try {
            return new TargetConnectionMetadata().accept(target.id(), Identifiers.newId("metadata"), target.entityId(), bytes, clock.instant()).withSourceUrl(input.metadataUrl());
        } catch (com.samlscope.saml.normal.SamlException invalid) {
            throw new IllegalArgumentException("Target metadata could not be parsed", invalid);
        }
    }
    private static View view(SqliteTargetConnectionRepository repository, TargetConnection target) {
        return new View(target.id(),target.name(),target.entityId(),repository.revisionSummaries(target.ownerId(),target.id())
                .stream().map(r -> new RevisionView(r.id(),r.roles(),r.sha256(),r.refreshable())).toList());
    }
}
