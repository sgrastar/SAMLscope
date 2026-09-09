package com.samlscope.api;

import com.fasterxml.jackson.databind.DeserializationFeature;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.http.HttpStatus;
import io.javalin.json.JavalinJackson;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.HexFormat;
import com.samlscope.core.Identifiers;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.peer.idp.IdpPeerService;
import com.samlscope.peer.sp.SpPeerService;
import com.samlscope.peer.logout.SloPeerService;
import com.samlscope.runner.OutboundPolicy;
import com.samlscope.runner.outbox.EcpProbeService;
import com.samlscope.runner.outbox.HttpOutboundSender;
import com.samlscope.runner.outbox.InMemoryEphemeralCredentialProvider;
import com.samlscope.runner.outbox.OutboundDispatcher;
import com.samlscope.runner.PreflightService;
import com.samlscope.runner.RunEvent;
import com.samlscope.runner.RunEventBus;
import com.samlscope.runner.RunService;
import com.samlscope.runner.TranscriptAutomationRecorder;
import com.samlscope.runner.MetadataLabService;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.crypto.XmlSigner;
import com.samlscope.saml.ecp.EcpProbeEnvelopeFactory;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.OpenSamlReader;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.store.FileTranscriptRecorder;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqlitePlanRepository;
import com.samlscope.store.SqliteRunRepository;

public final class SamlScopeApplication {
    private static final SecureRandom NONCE_RANDOM = new SecureRandom();

    private SamlScopeApplication() {}

    public static void main(String[] args) {
        var config = AppConfig.fromEnvironment();
        create(config).start(config.httpPort());
    }

    public static Javalin create(AppConfig config) {
        return create(config, null, Map.of(), Map.of());
    }

    static Javalin create(AppConfig config, com.samlscope.api.auth.OidcClient injectedOidcClient) {
        return create(config, injectedOidcClient, Map.of(), Map.of());
    }

    static Javalin create(
            AppConfig config,
            com.samlscope.api.auth.OidcClient injectedOidcClient,
            Map<com.samlscope.core.profile.FunctionalProfile,byte[]> profileArtifacts,
            Map<com.samlscope.core.profile.FunctionalProfile,String> approvedProfileDigests) {
        var clock = Clock.systemUTC();
        var oidcClient = config.oidc().enabled()
                ? (injectedOidcClient != null ? injectedOidcClient : new com.samlscope.api.auth.OidcClient(
                        config.oidc(), config.publicBaseUrl().resolve("/auth/callback"))) : null;
        var oidc = new com.samlscope.api.auth.OidcRoutes(config.oidc(), config.publicBaseUrl(),
                oidcClient, new com.samlscope.api.auth.OidcSessions(clock));
        var hostedRateLimiter = new HostedRateLimiter(clock);
        var json = new JsonCodec();
        var database = new SqliteDatabase(config.dataDirectory());
        PlanRepository plans = new SqlitePlanRepository(database, json);
        RunRepository runs = new SqliteRunRepository(database, json);
        var targetConnections = new com.samlscope.store.SqliteTargetConnectionRepository(database, json);
        var storedTranscript = config.mode() == AppConfig.Mode.HOSTED
                ? new FileTranscriptRecorder(
                        database, json, config.dataDirectory(),
                        new FileTranscriptRecorder.Limits(
                                2_048, 64L * 1024 * 1024,
                                200_000, 10L * 1024 * 1024 * 1024,
                                120, 1_200))
                : new FileTranscriptRecorder(database, json, config.dataDirectory());
        var transcript = new TranscriptAutomationRecorder(storedTranscript, storedTranscript);
        var metadataCache = new MetadataCache(config.dataDirectory());
        var eventBus = new RunEventBus();
        var runService = new RunService(plans, runs, eventBus, clock);
        var metadataLab = new MetadataLabService(config.peerBaseUrl(), plans, runs, runService, clock);
        var keyStore = new FilePlanKeyStore(config.dataDirectory(), clock);
        var signer = new XmlSigner();
        var metadataParser = new TargetMetadataParser();
        var saml = new SamlProtocolService(config.peerBaseUrl(), keyStore, signer, new OpenSamlReader(), clock);
        var metadata = new MetadataService(config.peerBaseUrl(), keyStore, signer, clock);
        var preflight = new PreflightService(config.peerBaseUrl(), plans, runs, runService, metadataCache,
                metadataParser, new OutboundPolicy(config.outboundAllowPrivate()), clock, json.mapper());
        var idpPeer = new IdpPeerService(plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock);
        var secondaryIdpPeer = new IdpPeerService(
                plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock, true);
        var sloPeer = new SloPeerService(plans, runs, metadataCache, metadataParser, saml, transcript, clock);
        var caseExecutions = new SqliteCaseExecutionRepository(database, json);
        var hostedRunProvisioner = new com.samlscope.store.SqliteHostedRunProvisioner(database, json, config.mode() == AppConfig.Mode.HOSTED);
        var ephemeralCredentials = new InMemoryEphemeralCredentialProvider();
        var outboundDispatcher = new OutboundDispatcher(
                caseExecutions, HttpOutboundSender.create(transcript, clock), ephemeralCredentials,
                new OutboundPolicy(config.outboundAllowPrivate()), clock);
        outboundDispatcher.recoverAfterRestart();
        var ecpProbe = new EcpProbeRuntime(
                config.peerBaseUrl(), plans, runs, metadataCache, metadataParser, saml,
                new EcpProbeEnvelopeFactory(),
                new EcpProbeService(caseExecutions, ephemeralCredentials, outboundDispatcher, clock));
        var m1 = M1Runtime.create(
                config, database, json, plans, runs, transcript, transcript, metadataCache,
                metadataParser, keyStore, caseExecutions, metadataLab, outboundDispatcher,
                hostedRateLimiter, hostedRunProvisioner, clock,
                profileArtifacts, approvedProfileDigests);
        var authorization = new ManagementAuthorization(oidc,
                new com.samlscope.store.SqlitePlanOwnerRepository(database), plans, runs, m1);
        transcript.onRecorded(m1::reconcileTranscriptEvidenceAutomatically);
        var spPeer = new SpPeerService(
                plans, runs, runService, metadataCache, metadataParser, saml, transcript, clock,
                m1::acceptActiveProbe);
        var preloadedMetadataCache = new BoundedByteArrayCache(128);

        return Javalin.create(javalin -> {
            javalin.startup.showJavalinBanner = false;
            javalin.events.serverStopped(transcript::close);
            javalin.http.maxRequestSize = 6L * 1024 * 1024;
            javalin.contextResolver.ip = ctx -> TrustedProxyClientAddress.resolve(
                    ctx.req().getRemoteAddr(), ctx.header("X-Forwarded-For"),
                    config.trustedProxyAddress());
            javalin.jsonMapper(new JavalinJackson().updateMapper(mapper -> {
                mapper.findAndRegisterModules();
                mapper.registerModule(new com.samlscope.store.FunctionalProfileJsonModule());
                mapper.enable(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS);
                mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            }));
            javalin.routes.before(ctx -> {
                securityHeaders(ctx);
                enforceConfiguredOrigin(ctx, config);
            });
            oidc.register(javalin);
            QuickCheckRoutes.register(javalin, m1::quickCheck);
            ResultRoutes.register(javalin, m1::requireResult, m1::requireReport);
            PublicationRoutes.register(javalin, m1::publish);
            InteractionRoutes.register(javalin, m1::pending);
            javalin.routes.get("/api/runs/{id}/workspace-evidence", ctx -> {
                ctx.header("Cache-Control", "no-store");
                ctx.json(m1.workspaceEvidence(ctx.pathParam("id")));
            });
            CampaignRoutes.register(javalin, m1::campaigns);
            CampaignActionRoutes.registerBounded(javalin, m1::completeCampaignAction);
            BootstrapContractRoutes.register(javalin, m1::bootstrapContracts);
            MetadataLabRoutes.register(javalin, metadataLab);
            ProtocolEvidenceRoutes.register(
                    javalin, m1::protocolEvidence, m1::evaluateProtocolEvidence,
                    m1::confirmProtocolEvidenceAttempts);
            AttestationRoutes.register(javalin, m1::attest);
            ConfigurationRoutes.register(javalin, m1::configure);
            BrowserCompletionRoutes.register(javalin, m1::completeBrowser);
            MilestoneRoutes.register(javalin, m1::startMilestone);
            EcpProbeRoutes.register(javalin, ecpProbe::execute);
            javalin.routes.get("/api/runs/{id}/active-probe", ctx ->
                    ctx.json(m1.activeProbeStatus(ctx.pathParam("id"))));
            javalin.routes.post("/api/runs/{id}/active-probe/abort", ctx ->
                    ctx.json(m1.abortActiveProbe(ctx.pathParam("id"))));
            javalin.routes.post("/api/runs/{id}/active-probe/retry", ctx ->
                    ctx.json(m1.retryActiveProbe(ctx.pathParam("id"))));
            if (config.managementProtected()) {
                ManagementSessionRoutes.register(javalin, config.publicBaseUrl(), m1::exchange,
                        m1::resumeManagementSession);
                javalin.routes.before("/api/manage/session", ctx -> authorization.session(ctx));
                javalin.routes.before("/api/plans/{id}", ctx -> {
                    if (ctx.method().name().equals("GET")) {
                        authorization.authorizePlan(ctx, false);
                    } else {
                        authorization.authorizePlan(ctx, true);
                    }
                });
                javalin.routes.before("/api/plans/{id}/runs", ctx -> {
                    if (ctx.method().name().equals("GET")) {
                        authorization.authorizePlan(ctx, false);
                    } else {
                        authorization.authorizePlan(ctx, true);
                    }
                });
                javalin.routes.before("/api/runs/{id}", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/preflight", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/events", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/quick-check", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/active-probe", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/active-probe/abort", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/active-probe/retry", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/interactions", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/workspace-evidence", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/campaigns", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/bootstrap-contracts", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/metadata-lab", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/metadata-lab/variant", ctx ->
                        authorization.authorizeRun(ctx, true));
                for (var path : List.of(
                        "/api/runs/{id}/metadata-lab/automatic-polling",
                        "/api/runs/{id}/metadata-lab/preloaded",
                        "/api/runs/{id}/metadata-lab/manual-refresh")) {
                    javalin.routes.before(path, ctx ->
                            authorization.authorizeRun(ctx, true));
                }
                javalin.routes.before("/api/runs/{id}/protocol-evidence", ctx ->
                        authorization.authorizeRun(ctx, false));
                javalin.routes.before("/api/runs/{id}/protocol-evidence/evaluate", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/protocol-evidence/confirm-attempts", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/cases/{caseId}/attest", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/cases/{caseId}/configure", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/cases/{caseId}/browser-complete", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before(
                        "/api/runs/{id}/campaigns/{campaignId}/actions/{actionId}/complete", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/milestones/{milestone}/start", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/ecp-probe", ctx ->
                        authorization.authorizeRun(ctx, true));
                javalin.routes.before("/api/runs/{id}/publish", ctx ->
                        authorization.authorizeRun(ctx, true));
                for (var path : List.of(
                        "/api/runs/{id}/result.json", "/api/runs/{id}/report.html")) {
                    javalin.routes.before(path, ctx -> {
                        if (!m1.isPublished(ctx.pathParam("id"))) {
                            authorization.authorizeRun(ctx, false);
                        }
                    });
                }
                javalin.routes.before("/api/runs/{id}/transcript", ctx -> {
                    authorization.authorizeRun(ctx, false);
                    if (config.mode() == AppConfig.Mode.HOSTED) hostedRateLimiter.requireAllowedTogether(
                            new HostedRateLimiter.Rule(
                                    "transcript-download-owner",
                                    hostedRunProvisioner.ownerForRun(ctx.pathParam("id")), 4,
                                    Duration.ofMinutes(1)),
                            new HostedRateLimiter.Rule(
                                    "transcript-download-run", ctx.pathParam("id"), 2,
                                    Duration.ofMinutes(1)),
                            new HostedRateLimiter.Rule(
                                    "transcript-download-global", "service", 10,
                                    Duration.ofMinutes(1)));
                });
            }
            TargetConnectionRoutes.register(
                    javalin, config, authorization, targetConnections, clock, preflight,
                    hostedRateLimiter);
            routes(javalin, config, plans, runs, transcript, storedTranscript,
                    eventBus, runService, preflight,
                    metadata, metadataLab, metadataCache, metadataParser, spPeer,
                    idpPeer, secondaryIdpPeer, sloPeer, m1,
                    hostedRateLimiter, hostedRunProvisioner, preloadedMetadataCache, authorization, clock,
                    targetConnections);
            javalin.routes.exception(MisdirectedRequest.class, (error, ctx) ->
                    ctx.status(421).json(new ApiModels.ErrorView("misdirected_request", error.getMessage())));
            javalin.routes.exception(IllegalArgumentException.class, (error, ctx) -> {
                ctx.status(HttpStatus.BAD_REQUEST).json(new ApiModels.ErrorView("invalid_request", error.getMessage()));
            });
            javalin.routes.exception(com.samlscope.core.plan.PlanConfigurationConflict.class, (error, ctx) ->
                    ctx.status(HttpStatus.CONFLICT).json(new ApiModels.ErrorView(
                            "plan_configuration_fixed", error.getMessage())));
            javalin.routes.exception(SecurityException.class, (error, ctx) ->
                    ctx.status(HttpStatus.FORBIDDEN)
                            .json(new ApiModels.ErrorView("access_denied", "Access denied")));
            javalin.routes.exception(HostedRateLimiter.RateLimitExceeded.class, (error, ctx) ->
                    ctx.status(HttpStatus.TOO_MANY_REQUESTS)
                            .json(new ApiModels.ErrorView("rate_limited", error.getMessage())));
            javalin.routes.exception(BoundedByteArrayCache.Busy.class, (error, ctx) ->
                    ctx.status(HttpStatus.SERVICE_UNAVAILABLE)
                            .header("Retry-After", "1")
                            .json(new ApiModels.ErrorView("generation_busy", error.getMessage())));
            javalin.routes.exception(HostedEvidenceWorkGate.Busy.class, (error, ctx) ->
                    ctx.status(HttpStatus.SERVICE_UNAVAILABLE)
                            .header("Retry-After", "1")
                            .json(new ApiModels.ErrorView("evidence_work_busy", error.getMessage())));
            javalin.routes.exception(FileTranscriptRecorder.CapacityExceeded.class, (error, ctx) ->
                    ctx.status(507).json(new ApiModels.ErrorView(
                            "transcript_capacity_exceeded", error.getMessage())));
            javalin.routes.exception(FileTranscriptRecorder.AdmissionRateExceeded.class, (error, ctx) ->
                    ctx.status(HttpStatus.TOO_MANY_REQUESTS).json(new ApiModels.ErrorView(
                            "transcript_rate_limited", error.getMessage())));
            javalin.routes.exception(MetadataCache.MetadataUnavailable.class, (error, ctx) ->
                    ctx.status(HttpStatus.CONFLICT).json(new ApiModels.ErrorView("preflight_required",
                            "Target metadata is not ready. Open Run workspace and complete Run preflight before starting SAML.")));
            javalin.routes.exception(Exception.class, (error, ctx) -> {
                error.printStackTrace();
                ctx.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .json(new ApiModels.ErrorView("internal_error", "The request could not be completed"));
            });
        });
    }

    private static void routes(io.javalin.config.JavalinConfig javalin, AppConfig config,
                               PlanRepository plans, RunRepository runs,
                               com.samlscope.core.transcript.TranscriptRecorder transcript,
                               FileTranscriptRecorder storedTranscript,
                               RunEventBus eventBus, RunService runService, PreflightService preflight,
                               MetadataService metadata, MetadataLabService metadataLab,
                               MetadataCache metadataCache, TargetMetadataParser metadataParser,
                               SpPeerService spPeer, IdpPeerService idpPeer,
                               IdpPeerService secondaryIdpPeer,
                               SloPeerService sloPeer,
                               M1Runtime m1, HostedRateLimiter hostedRateLimiter,
                               com.samlscope.store.SqliteHostedRunProvisioner hostedRunProvisioner,
                               BoundedByteArrayCache preloadedMetadataCache,
                               ManagementAuthorization authorization, Clock clock,
                               com.samlscope.store.SqliteTargetConnectionRepository targetConnections) {
        javalin.routes.get("/", SamlScopeApplication::serveIndex);
        javalin.routes.get("/reports/{run}", SamlScopeApplication::serveIndex);
        javalin.routes.get("/manage/{run}", SamlScopeApplication::serveIndex);
        javalin.routes.get("/browser/{run}/{caseId}", SamlScopeApplication::serveIndex);
        javalin.routes.get("/assets/{file}", SamlScopeApplication::serveAsset);
        javalin.routes.get("/api/health", ctx -> ctx.json(Map.of(
                "status", "ok", "version", "0.1.0", "mode", config.mode().name().toLowerCase(),
                "oidcEnabled", config.oidc().enabled())));
        javalin.routes.get("/api/profiles", ctx -> ctx.json(m1.installedProfiles().stream()
                .sorted(java.util.Comparator.comparing(com.samlscope.core.profile.FunctionalProfile::id))
                .toList()));
        javalin.routes.get("/api/plans", ctx -> ctx.json((config.managementProtected()
                        ? authorization.list(ctx)
                        : plans.list()).stream()
                .map(plan -> view(config, plan)).toList()));
        javalin.routes.post("/api/plans", ctx -> {
            var owner = authorization.creationOwner(ctx, hostedOwnerId(ctx.ip()));
            if (config.mode() == AppConfig.Mode.HOSTED) {
                hostedRateLimiter.requireAllowed("create-plan", ctx.ip(), 10, Duration.ofHours(1));
            }
            var request = ctx.bodyAsClass(ApiModels.PlanWrite.class);
            var now = clock.instant();
            var target = resolveTarget(request, targetConnections, authorization, ctx, config);
            var plan = fromWrite(Identifiers.newId("plan"), request,
                    m1.definitionIdentity(request.profile()), target, now, now);
            ApiModels.RunCreated initialRun = null;
            if (config.managementProtected()) {
                var run = runService.prepare(plan.id());
                var access = m1.prepareManagementAccess(run);
                if (!hostedRunProvisioner.createPlanWithInitialRun(
                        plan, run, access.grant(), owner)) {
                    throw new HostedRateLimiter.RateLimitExceeded(
                            "Another Run against this target is already active");
                }
                runService.publishCreated(run);
                initialRun = new ApiModels.RunCreated(run, access.access().managementUrl().toString());
            } else {
                plans.save(plan);
            }
            ctx.status(HttpStatus.CREATED).json(new ApiModels.PlanCreated(view(config, plan), initialRun));
        });
        javalin.routes.get("/api/plans/{id}", ctx -> ctx.json(view(config, requirePlan(plans, ctx.pathParam("id")))));
        javalin.routes.put("/api/plans/{id}", ctx -> {
            var existing = requirePlan(plans, ctx.pathParam("id"));
            var request = ctx.bodyAsClass(ApiModels.PlanWrite.class);
            var identity = request.profile() == existing.profile()
                    ? existing.definitionIdentity() : m1.definitionIdentity(request.profile());
            var target = resolveTarget(request, targetConnections, authorization, ctx, config);
            var updated = fromWrite(existing.id(), request, identity, target,
                    existing.createdAt(), clock.instant());
            if (config.mode() == AppConfig.Mode.HOSTED) {
                hostedRunProvisioner.updatePlan(updated);
            } else {
                plans.save(updated);
            }
            ctx.json(view(config, updated));
        });
        javalin.routes.delete("/api/plans/{id}", ctx -> {
            if (!storedTranscript.deletePlanAndEvidence(ctx.pathParam("id"))) {
                ctx.status(HttpStatus.NOT_FOUND);
            }
            else ctx.status(HttpStatus.NO_CONTENT);
        });
        javalin.routes.get("/api/plans/{id}/runs", ctx -> ctx.json(runs.listForPlan(ctx.pathParam("id"))));
        javalin.routes.post("/api/plans/{id}/runs", ctx -> {
            var requestedPlan = requirePlan(plans, ctx.pathParam("id"));
            com.samlscope.core.run.TestRun run;
            String managementUrl;
            if (config.managementProtected()) {
                if (config.mode() == AppConfig.Mode.HOSTED) {
                    hostedRateLimiter.requireAllowed("create-run", ctx.ip(), 20, Duration.ofHours(1));
                }
                run = runService.prepare(requestedPlan.id());
                var access = m1.prepareManagementAccess(run);
                if (!hostedRunProvisioner.createRun(run, access.grant())) {
                    throw new HostedRateLimiter.RateLimitExceeded(
                            "Another Run against this target is already active");
                }
                runService.publishCreated(run);
                managementUrl = access.access().managementUrl().toString();
            } else {
                run = runService.create(requestedPlan.id());
                managementUrl = null;
            }
            ctx.status(HttpStatus.CREATED).json(new ApiModels.RunCreated(run, managementUrl));
        });
        javalin.routes.get("/api/runs/{id}", ctx -> ctx.json(requireRun(runs, ctx.pathParam("id"))));
        javalin.routes.post("/api/runs/{id}/preflight", ctx -> ctx.json(preflight.execute(ctx.pathParam("id"))));
        javalin.routes.get("/api/runs/{id}/transcript", ctx -> ctx.json(transcript.list(ctx.pathParam("id"))));
        javalin.routes.sse("/api/runs/{id}/events", client -> {
            var runId = client.ctx().pathParam("id");
            var run = requireRun(runs, runId);
            client.sendEvent("run", new RunEvent(runId, "run.snapshot", clock.instant(),
                    Map.of("status", run.status().name(), "reachability", run.targetToSuiteReachability().name())));
            client.keepAlive();
            var subscription = eventBus.subscribe(runId, event -> client.sendEvent("run", event));
            client.onClose(subscription::close);
        });

        javalin.routes.get("/p/{plan}/metadata", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            confirmReachabilityProbe(ctx.queryParam("probe"), plan.id(), runs, runService);
            var variant = MetadataService.Variant.parse(ctx.queryParam("variant"));
            var runId = ctx.queryParam("run");
            if (variant != MetadataService.Variant.BASELINE) {
                runId = requiredQuery(ctx, "run");
                var run = requireRun(runs, runId);
                if (!plan.id().equals(run.planId())) {
                    throw new IllegalArgumentException("Run belongs to another Test Plan");
                }
                transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                        run.id(), com.samlscope.core.transcript.Direction.INBOUND, clock.instant(),
                        "metadata:" + variant.id(), "GET", absoluteRequestUrl(ctx), 200,
                        headers(ctx), new byte[0], null, ctx.req().getQueryString(), new byte[0],
                        Map.of("type", "MetadataFetch", "variant", variant.id())));
                ctx.header("Cache-Control", "no-store");
            }
            ctx.contentType("application/samlmetadata+xml").result(metadata.generate(plan, variant, runId));
        });
        javalin.routes.get("/p/{plan}/metadata/live", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var runId = requiredQuery(ctx, "run");
            var labState = metadataLab.state(runId);
            var variant = MetadataService.Variant.parse(labState.selectedVariant());
            var run = requireRun(runs, runId);
            if (!plan.id().equals(run.planId())) {
                throw new IllegalArgumentException("Run belongs to another Test Plan");
            }
            var redirectStatus = metadataRedirectStatus(variant);
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.INBOUND, clock.instant(),
                    "metadata-live:" + variant.id(), "GET", absoluteRequestUrl(ctx),
                    redirectStatus == null ? 200 : redirectStatus.getCode(),
                    headers(ctx), new byte[0], null, ctx.req().getQueryString(), new byte[0],
                    Map.of("type", "MetadataFetch", "variant", variant.id(), "feed", "live")));
            // Automatic polling is opt-in. A fetch records evidence but does not advance: targets
            // often fetch more than once during one key reload, and every duplicate fetch must see
            // the same fixture. The correlated browser response advances the campaign.
            metadataLab.recordLiveFetch(run.id(), plan.id(), variant.id(), ctx.queryParam("poll"));
            ctx.header("Cache-Control", "no-store");
            if (redirectStatus != null) {
                var location = config.peerBaseUrl().resolve(
                        "/p/" + plan.id() + "/metadata/live/content?run=" + run.id()
                                + "&variant=" + variant.id()
                                + (ctx.queryParam("poll") == null ? "" : "&poll="
                                + java.net.URLEncoder.encode(
                                        ctx.queryParam("poll"), java.nio.charset.StandardCharsets.UTF_8)));
                ctx.redirect(location.toString(), redirectStatus);
                return;
            }
            ctx.contentType("application/samlmetadata+xml")
                    .result(labState.ingestionMode() == MetadataLabService.IngestionMode.AUTOMATIC_POLLING
                            ? metadata.generatePolling(plan, variant, runId)
                            : metadata.generate(plan, variant, runId));
        });
        javalin.routes.get("/p/{plan}/metadata/preloaded", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var runId = requiredQuery(ctx, "run");
            var run = requireRun(runs, runId);
            var preload = requiredQuery(ctx, "preload");
            metadataLab.authorizePreloadedFetch(run.id(), plan.id(), preload);
            var payload = preloadedMetadataCache.getOrCompute(
                    preloadedCacheKey(plan.id(), run.id()),
                    () -> {
                        if (config.mode() == AppConfig.Mode.HOSTED) {
                            hostedRateLimiter.requireAllowedTogether(
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation-owner",
                                            hostedRunProvisioner.ownerForRun(run.id()), 8,
                                            Duration.ofHours(1)),
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation", run.id(), 4,
                                            Duration.ofHours(1)),
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation-global", "service", 60,
                                            Duration.ofHours(1)));
                        }
                        return metadata.generatePreloadedCampaign(plan, run.id());
                    });
            var variants = metadataLab.recordPreloadedFetch(
                    run.id(), plan.id(), preload);
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.INBOUND, clock.instant(),
                    "metadata-preloaded", "GET", absoluteRequestUrl(ctx), 200,
                    headers(ctx), new byte[0], null, ctx.req().getQueryString(), new byte[0],
                    Map.of(
                            "type", "MetadataFetch",
                            "variant", "preloaded-aggregate",
                            "variants", variants,
                            "feed", "preloaded")));
            ctx.header("Cache-Control", "no-store");
            ctx.contentType("application/samlmetadata+xml")
                    .result(payload);
        });
        javalin.routes.get("/p/{plan}/metadata/preloaded/download", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var runId = requiredQuery(ctx, "run");
            var run = requireRun(runs, runId);
            var preload = requiredQuery(ctx, "preload");
            var variants = metadataLab.authorizePreloadedDownload(
                    run.id(), plan.id(), preload);
            var payload = preloadedMetadataCache.getOrCompute(
                    preloadedCacheKey(plan.id(), run.id()),
                    () -> {
                        if (config.mode() == AppConfig.Mode.HOSTED) {
                            hostedRateLimiter.requireAllowedTogether(
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation-owner",
                                            hostedRunProvisioner.ownerForRun(run.id()), 8,
                                            Duration.ofHours(1)),
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation", run.id(), 4,
                                            Duration.ofHours(1)),
                                    new HostedRateLimiter.Rule(
                                            "preloaded-generation-global", "service", 60,
                                            Duration.ofHours(1)));
                        }
                        return metadata.generatePreloadedCampaign(plan, run.id());
                    });
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.INBOUND, clock.instant(),
                    "metadata-preloaded-download", "GET", absoluteRequestUrl(ctx), 200,
                    Map.of(), new byte[0], null, ctx.req().getQueryString(), new byte[0],
                    Map.of(
                            "type", "MetadataExport",
                            "variant", "preloaded-aggregate",
                            "variants", variants,
                            "feed", "preloaded-download")));
            ctx.header("Cache-Control", "no-store");
            ctx.header("Content-Disposition", "attachment; filename=\"samlscope-metadata-campaign.xml\"");
            ctx.contentType("application/samlmetadata+xml").result(payload);
        });
        javalin.routes.get("/p/{plan}/metadata/live/content", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var runId = requiredQuery(ctx, "run");
            var run = requireRun(runs, runId);
            if (!plan.id().equals(run.planId())) {
                throw new IllegalArgumentException("Run belongs to another Test Plan");
            }
            var variant = MetadataService.Variant.parse(requiredQuery(ctx, "variant"));
            if (metadataRedirectStatus(variant) == null) {
                throw new IllegalArgumentException("Metadata content route requires a redirect fixture");
            }
            ctx.header("Cache-Control", "no-store");
            ctx.contentType("application/samlmetadata+xml")
                    .result(ctx.queryParam("poll") == null
                            ? metadata.generate(plan, variant, runId)
                            : metadata.generatePolling(plan, variant, runId));
        });
        javalin.routes.get("/mdq/<entityId>", ctx -> {
            var entityId = URLDecoder.decode(ctx.pathParam("entityId"), StandardCharsets.UTF_8);
            var plan = plans.list().stream().filter(candidate ->
                            peerEntityId(config, candidate).equals(entityId)
                                    || secondaryIdpEntityId(config, candidate).equals(entityId))
                    .findFirst().orElseThrow(() -> new IllegalArgumentException("Unknown entityID"));
            var payload = secondaryIdpEntityId(config, plan).equals(entityId)
                    ? metadata.generateSecondaryIdp(plan)
                    : metadata.generate(plan);
            ctx.contentType("application/samlmetadata+xml").result(payload);
        });
        javalin.routes.get("/p/{plan}/idp/secondary/metadata", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            ctx.contentType("application/samlmetadata+xml").result(metadata.generateSecondaryIdp(plan));
        });
        javalin.routes.get("/p/{plan}/start/m0-roundtrip", ctx ->
                ctx.redirect(spPeer.start(ctx.pathParam("plan"), requiredQuery(ctx, "run")).toString()));
        javalin.routes.get("/p/{plan}/start/metadata-polling/{index}", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var run = requireRun(runs, requiredQuery(ctx, "run"));
            var index = Integer.parseInt(ctx.pathParam("index"));
            var flow = metadataLab.requireAutomaticStartFlow(
                    run.id(), plan.id(), requiredQuery(ctx, "poll"), index);
            // requireAutomaticStartFlow records the attempted index in the Run context. Reload so
            // the request-correlation update below cannot overwrite that orchestration state.
            run = requireRun(runs, run.id());
            var target = metadataParser.parse(
                    metadataCache.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
            var destination = target.singleSignOnServices().stream()
                    .filter(endpoint -> MetadataService.POST.equals(endpoint.binding()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "The automatic metadata campaign requires an HTTP-POST SSO endpoint"))
                    .location();
            var requestId = "_" + Identifiers.newId("metadata");
            var acs = config.peerBaseUrl().resolve(
                    "/p/" + plan.id() + "/sp/acs/0?mdv=" + flow.variant().id() + "&run=" + run.id());
            var requestXml = new com.samlscope.saml.normal.SamlSignedRequestFactory().build(
                    com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID,
                    requestId, destination, peerEntityId(config, plan), acs,
                    clock.instant(), metadata.credentialsForPollingVariant(plan, flow.variant()));
            var relayState = "samlscope-metadata-polling|" + run.id() + "|"
                    + flow.campaignToken() + "|" + flow.index();
            var requests = new LinkedHashMap<String, Object>();
            if (run.context().get("metadata_polling_requests") instanceof Map<?, ?> existing) {
                existing.forEach((key, value) -> {
                    if (key instanceof String text) requests.put(text, value);
                });
            }
            requests.put(flow.variant().id(), requestId);
            var context = new LinkedHashMap<String, Object>(run.context());
            context.put("metadata_polling_requests", Map.copyOf(requests));
            runService.update(run, RunStatus.WAITING_BROWSER, run.targetToSuiteReachability(), context);
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.OUTBOUND, clock.instant(),
                    requestId, "POST", destination.toString(), null, Map.of(), new byte[0], null,
                    null, requestXml, Map.of(
                            "type", "AuthnRequest",
                            "id", requestId,
                            "variant", flow.variant().id(),
                            "campaign", "metadata-polling")));
            var nonceBytes = new byte[18];
            NONCE_RANDOM.nextBytes(nonceBytes);
            var nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce
                            + "'; form-action " + origin(destination)
                            + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result(HtmlPostPage.renderRequest(
                            destination, Base64.getEncoder().encodeToString(requestXml), relayState, nonce));
        });
        javalin.routes.post("/p/{plan}/continue/metadata-polling/{index}", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var runId = requiredQuery(ctx, "run");
            var index = Integer.parseInt(ctx.pathParam("index"));
            var flow = metadataLab.continueAfterObservedTargetResult(
                    runId, plan.id(), requiredQuery(ctx, "poll"), index);
            if (flow.hasNext()) {
                ctx.redirect("/p/" + plan.id() + "/start/metadata-polling/" + (index + 1)
                        + "?run=" + flow.runId() + "&poll="
                        + java.net.URLEncoder.encode(
                                flow.campaignToken(), java.nio.charset.StandardCharsets.UTF_8));
                return;
            }
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result("<!doctype html><html lang=\"en\"><body>"
                            + "<h1>Automatic metadata campaign completed</h1>"
                            + "<p>The Target fetched the final fixture but did not return a correlated "
                            + "SAML response. SAMLscope recorded no target outcome from this continuation.</p>"
                            + "</body></html>");
        });
        javalin.routes.get("/p/{plan}/start/metadata-preloaded/{index}", ctx -> {
            var plan = requirePlan(plans, ctx.pathParam("plan"));
            var run = requireRun(runs, requiredQuery(ctx, "run"));
            var index = Integer.parseInt(ctx.pathParam("index"));
            var flow = metadataLab.requirePreloadedFlow(
                    run.id(), plan.id(), requiredQuery(ctx, "preload"), index);
            var target = metadataParser.parse(
                    metadataCache.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
            var destination = target.singleSignOnServices().stream()
                    .filter(endpoint -> MetadataService.POST.equals(endpoint.binding()))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "The preloaded browser campaign requires an HTTP-POST SSO endpoint"))
                    .location();
            var requestId = "_" + Identifiers.newId("metadata");
            var acs = config.peerBaseUrl().resolve(
                    "/p/" + plan.id() + "/sp/acs/0?mdv=" + flow.variant().id() + "&run=" + run.id());
            var requestXml = new com.samlscope.saml.normal.SamlSignedRequestFactory().build(
                    com.samlscope.saml.normal.SamlSignedRequestFactory.Fixture.VALID,
                    requestId, destination, metadata.preloadedEntityId(plan, flow.variant()), acs,
                    clock.instant(), metadata.credentialsForVariant(plan, flow.variant()));
            var relayState = "samlscope-metadata-preloaded|" + run.id() + "|"
                    + flow.campaignToken() + "|" + flow.index();
            var requests = new LinkedHashMap<String, Object>();
            if (run.context().get("metadata_preloaded_requests") instanceof Map<?, ?> existing) {
                existing.forEach((key, value) -> {
                    if (key instanceof String text) requests.put(text, value);
                });
            }
            requests.put(flow.variant().id(), requestId);
            var context = new LinkedHashMap<String, Object>(run.context());
            context.put("metadata_preloaded_requests", Map.copyOf(requests));
            runService.update(run, RunStatus.WAITING_BROWSER, run.targetToSuiteReachability(), context);
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.OUTBOUND, clock.instant(),
                    requestId, "POST", destination.toString(), null, Map.of(), new byte[0], null,
                    null, requestXml, Map.of(
                            "type", "AuthnRequest",
                            "id", requestId,
                            "variant", flow.variant().id(),
                            "campaign", "metadata-preloaded")));
            var nonceBytes = new byte[18];
            NONCE_RANDOM.nextBytes(nonceBytes);
            var nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
            ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce
                            + "'; form-action " + origin(destination)
                            + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result(HtmlPostPage.renderRequest(
                            destination, Base64.getEncoder().encodeToString(requestXml), relayState, nonce));
        });
        javalin.routes.get("/p/{plan}/probe/{action}", ctx -> {
            var runId = requiredQuery(ctx, "run");
            var status = m1.activeProbeRouteStatus(runId);
            requireActiveProbeRoute(ctx, status);
            ctx.header("Cache-Control", "no-store");
            ctx.header("Content-Security-Policy", "default-src 'none'; form-action 'self'; "
                    + "frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
            ctx.contentType("text/html; charset=utf-8").result(activeProbeStartPage(status));
        });
        javalin.routes.post("/p/{plan}/probe/{action}", ctx -> {
            var runId = requiredQuery(ctx, "run");
            var status = m1.activeProbeRouteStatus(runId);
            requireActiveProbeRoute(ctx, status);
            var fresh = "true".equals(ctx.formParam("freshSessionConfirmed"));
            renderActiveProbe(ctx, m1.prepareActiveProbe(
                    runId, ctx.pathParam("action"), fresh));
        });
        // Publish only the catalogued ACS endpoints in metadata, but receive a response sent to
        // any Suite-controlled ACS index. Negative ACS-selection fixtures deliberately request an
        // unregistered path; recording that POST is what lets the scenario prove that the target
        // followed the unregistered URL instead of rejecting it or falling back to the default.
        javalin.routes.get("/p/{plan}/ui/completion.css", ctx ->
                serveClasspath(ctx, "/peer-completion.css", "text/css; charset=utf-8"));
        javalin.routes.post("/p/{plan}/sp/acs/{index}", ctx -> {
            var consumed = spPeer.consumeDetailed(
                    ctx.pathParam("plan"), ctx.bodyAsBytes(), headers(ctx), absoluteRequestUrl(ctx));
            renderSpResponse(ctx, consumed, m1, metadataLab);
        });
        javalin.routes.get("/p/{plan}/sp/acs/{index}", ctx -> {
            var consumed = spPeer.consumeRedirectDetailed(
                    ctx.pathParam("plan"), ctx.req().getQueryString(), headers(ctx), absoluteRequestUrl(ctx));
            renderSpResponse(ctx, consumed, m1, metadataLab);
        });
        javalin.routes.get("/p/{plan}/idp/sso", ctx -> serveIdp(ctx, idpPeer));
        javalin.routes.post("/p/{plan}/idp/sso", ctx -> serveIdp(ctx, idpPeer));
        javalin.routes.get("/p/{plan}/idp/secondary/sso", ctx -> serveIdp(ctx, secondaryIdpPeer));
        javalin.routes.post("/p/{plan}/idp/secondary/sso", ctx -> serveIdp(ctx, secondaryIdpPeer));
        for (var role : List.of("sp", "idp")) {
            javalin.routes.get("/p/{plan}/" + role + "/slo", ctx ->
                    serveSlo(ctx, sloPeer, SloPeerService.Transport.FRONT_CHANNEL));
            javalin.routes.post("/p/{plan}/" + role + "/slo", ctx ->
                    serveSlo(ctx, sloPeer, SloPeerService.Transport.FRONT_CHANNEL));
            javalin.routes.post("/p/{plan}/" + role + "/slo/soap", ctx ->
                    serveSlo(ctx, sloPeer, SloPeerService.Transport.SOAP));
        }
        javalin.routes.post("/p/{plan}/sp/paos", ctx -> {
            var runId = requiredQuery(ctx, "run");
            var run = requireRun(runs, runId);
            if (!ctx.pathParam("plan").equals(run.planId())) {
                throw new IllegalArgumentException("Run belongs to another Test Plan");
            }
            transcript.record(new com.samlscope.core.transcript.TranscriptInput(
                    run.id(), com.samlscope.core.transcript.Direction.INBOUND, clock.instant(),
                    "ecp-response-consumer", "POST", absoluteRequestUrl(ctx), 204,
                    headers(ctx), ctx.bodyAsBytes(), ctx.contentType(), ctx.req().getQueryString(),
                    ctx.bodyAsBytes(), Map.of("type", "EcpPaosResponse")));
            ctx.status(HttpStatus.NO_CONTENT);
        });
    }

    private static void requireActiveProbeRoute(
            Context ctx, com.samlscope.runner.ActiveProbeCoordinator.Status status) {
        if (!ctx.pathParam("plan").equals(status.planId())
                || status.state() != com.samlscope.runner.ActiveProbeCoordinator.State.READY
                || !ctx.pathParam("action").equals(status.actionId())) {
            throw new IllegalArgumentException("Active probe route does not match the ready action");
        }
    }

    private static String activeProbeStartPage(
            com.samlscope.runner.ActiveProbeCoordinator.Status status) {
        var fresh = status.requiresFreshSession()
                ? "<p>This first probe verifies IsPassive with no existing IdP session. Open this page in a new private browser window, then confirm below.</p>"
                        + "<label><input required type=\"checkbox\" name=\"freshSessionConfirmed\" value=\"true\"> "
                        + "This browser context has no active target IdP session.</label>"
                : "";
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Active SAML probes</title></head>"
                + "<body><h1>Run browser-assisted SAML scenario</h1>"
                + "<p><strong>" + htmlEscape(status.caseId()) + "</strong></p>"
                + "<p>" + htmlEscape(status.instructionsEn()) + "</p>"
                + "<form method=\"post\">" + fresh
                + "<p><button type=\"submit\">Continue scenario</button></p></form></body></html>";
    }

    private static void renderActiveProbe(
            Context ctx, com.samlscope.runner.ActiveProbeCoordinator.PreparedProbe probe) {
        var nonceBytes = new byte[18];
        NONCE_RANDOM.nextBytes(nonceBytes);
        var nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce
                        + "'; form-action " + origin(probe.destination())
                        + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
        ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                .result(HtmlPostPage.renderRequest(
                        probe.destination(), probe.samlRequest(), probe.relayState(), nonce));
    }

    private static void renderSpResponse(
            Context ctx, com.samlscope.peer.sp.SpPeerService.ConsumeResult consumed, M1Runtime m1,
            MetadataLabService metadataLab) {
        if (consumed.activeProbe()) {
            var status = m1.activeProbeRouteStatus(consumed.activeProbeRunId());
            if (status.state() == com.samlscope.runner.ActiveProbeCoordinator.State.READY) {
                renderActiveProbe(ctx, m1.prepareActiveProbe(
                        consumed.activeProbeRunId(), status.actionId(), false));
                return;
            }
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result("<!doctype html><html lang=\"en\"><body><h1>Active probes completed</h1>"
                            + "<p>The responses were recorded and evaluated automatically.</p></body></html>");
            return;
        }
        if (consumed.metadataProbe() && consumed.relayState() != null
                && consumed.relayState().startsWith("samlscope-metadata-polling|")) {
            var parts = consumed.relayState().split("\\|", -1);
            if (parts.length != 4 || !parts[1].equals(consumed.metadataProbeRunId())) {
                throw new IllegalArgumentException("Invalid automatic metadata campaign correlation");
            }
            var index = Integer.parseInt(parts[3]);
            var current = metadataLab.state(parts[1]);
            if (!current.selectedVariant().equals(consumed.metadataProbeVariant())) {
                throw new IllegalArgumentException("Automatic metadata campaign variant mismatch");
            }
            var correlated = Boolean.TRUE.equals(consumed.summary().get("metadataProbeAccepted"));
            if (!correlated) {
                throw new IllegalArgumentException(
                        "Automatic metadata campaign response does not match the issued AuthnRequest");
            }
            // Advance only after both the stable metadata fetch and the signed browser response
            // have been bound to the same current fixture and request ID.
            var flow = metadataLab.requireAutomaticCompletedFlow(
                    parts[1], ctx.pathParam("plan"), parts[2], index);
            var successful = "urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                    consumed.summary().get("statusCode"));
            var next = flow.hasNext()
                    ? "/p/" + flow.planId() + "/start/metadata-polling/" + (index + 1)
                            + "?run=" + flow.runId() + "&poll="
                            + java.net.URLEncoder.encode(
                                    flow.campaignToken(), java.nio.charset.StandardCharsets.UTF_8)
                    : null;
            if (successful && next != null) {
                ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                        .result(metadataPollingTransitionPage(next, flow.pollingDelaySeconds()));
                return;
            }
            if (!successful && next != null) {
                ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                        .result("<!doctype html><html lang=\"en\"><body>"
                                + "<h1>This polling fixture did not produce a correlated Success response</h1>"
                                + "<p>The metadata fetch and response were recorded. SAMLscope does not "
                                + "convert the missing Success response into a target violation.</p>"
                                + "<p><a href=\"" + htmlEscape(next)
                                + "\">Continue with the next polling fixture</a></p></body></html>");
                return;
            }
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result("<!doctype html><html lang=\"en\"><body>"
                            + "<h1>Automatic metadata campaign completed</h1>"
                            + "<p>Return to the Run page to evaluate the recorded evidence. Only "
                            + "correlated Success responses count as metadata-use evidence.</p></body></html>");
            return;
        }
        if (consumed.metadataProbe() && consumed.relayState() != null
                && consumed.relayState().startsWith("samlscope-metadata-preloaded|")) {
            var parts = consumed.relayState().split("\\|", -1);
            if (parts.length != 4 || !parts[1].equals(consumed.metadataProbeRunId())) {
                throw new IllegalArgumentException("Invalid preloaded metadata campaign correlation");
            }
            var index = Integer.parseInt(parts[3]);
            var flow = metadataLab.requirePreloadedFlow(parts[1], ctx.pathParam("plan"), parts[2], index);
            if (!flow.variant().id().equals(consumed.metadataProbeVariant())) {
                throw new IllegalArgumentException("Preloaded metadata campaign variant mismatch");
            }
            var successful = Boolean.TRUE.equals(consumed.summary().get("metadataProbeAccepted"))
                    && "urn:oasis:names:tc:SAML:2.0:status:Success".equals(
                            consumed.summary().get("statusCode"));
            var next = flow.hasNext()
                    ? "/p/" + flow.planId() + "/start/metadata-preloaded/" + (index + 1)
                            + "?run=" + flow.runId() + "&preload="
                            + java.net.URLEncoder.encode(
                                    flow.campaignToken(), java.nio.charset.StandardCharsets.UTF_8)
                    : null;
            if (successful && next != null) {
                ctx.redirect(next);
                return;
            }
            if (!successful && next != null) {
                ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                        .result("<!doctype html><html lang=\"en\"><body>"
                                + "<h1>This fixture did not produce a correlated Success response</h1>"
                                + "<p>SAMLscope recorded the response without turning it into a target "
                                + "violation. Continue only after reviewing the target's result.</p>"
                                + "<p><a href=\"" + htmlEscape(next)
                                + "\">Continue with the next imported fixture</a></p></body></html>");
                return;
            }
            ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                    .result("<!doctype html><html lang=\"en\"><body>"
                            + "<h1>Preloaded metadata campaign attempts completed</h1>"
                            + "<p>Return to the Run page to evaluate the recorded evidence. Only "
                            + "correlated Success responses count as metadata-use evidence.</p></body></html>");
            return;
        }
        ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                .result(PeerCompletionPage.render(m1.workspaceUrl(consumed.metadataProbe()
                                ? consumed.metadataProbeRunId() : consumed.relayState()),
                        "/p/" + ctx.pathParam("plan") + "/ui/completion.css", consumed.summary()));
    }

    private static void serveSlo(Context ctx, SloPeerService service, SloPeerService.Transport transport) {
        var result = service.consume(
                ctx.pathParam("plan"), transport, ctx.method().name(), ctx.req().getQueryString(),
                ctx.bodyAsBytes(), headers(ctx), absoluteRequestUrl(ctx));
        if (result.response() == null) {
            ctx.status(HttpStatus.NO_CONTENT);
            return;
        }
        if (transport == SloPeerService.Transport.SOAP) {
            ctx.contentType("text/xml; charset=utf-8").result(service.soapResponse(result));
            return;
        }
        if (MetadataService.REDIRECT.equals(result.responseBinding())) {
            ctx.redirect(service.redirectResponse(result).toString());
            return;
        }
        var nonceBytes = new byte[18];
        NONCE_RANDOM.nextBytes(nonceBytes);
        var nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce
                        + "'; form-action " + origin(result.response().destination())
                        + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
        ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                .result(HtmlPostPage.render(
                        result.response().destination(), result.response().base64(),
                        result.response().relayState(), nonce).replace("SAMLResponse", "SAMLResponse"));
    }

    private static void serveIdp(Context ctx, IdpPeerService service) {
        var response = service.consume(ctx.pathParam("plan"), ctx.method().name(), ctx.req().getQueryString(),
                ctx.bodyAsBytes(), headers(ctx), absoluteRequestUrl(ctx));
        var nonceBytes = new byte[18];
        NONCE_RANDOM.nextBytes(nonceBytes);
        var nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);
        var destinationOrigin = origin(response.destination());
        ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce
                        + "'; form-action " + destinationOrigin
                        + "; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
        ctx.header("Cache-Control", "no-store").contentType("text/html; charset=utf-8")
                .result(HtmlPostPage.render(response.destination(), response.base64(), response.relayState(), nonce));
    }

    private static void confirmReachabilityProbe(String runId, String planId, RunRepository runs, RunService runService) {
        if (runId == null) return;
        var run = requireRun(runs, runId);
        if (!run.planId().equals(planId)) throw new IllegalArgumentException("Reachability probe belongs to another plan");
        var context = new LinkedHashMap<String, Object>(run.context());
        context.put("reachabilityConfirmedBy", "metadata-probe");
        runService.update(run, run.status(), Reachability.CONFIRMED, context);
    }

    private static TestPlan fromWrite(String id, ApiModels.PlanWrite request,
            com.samlscope.core.profile.FunctionalDefinitionIdentity definitionIdentity,
            TestPlan.Target target,
            java.time.Instant createdAt, java.time.Instant updatedAt) {
        if (request == null) throw new IllegalArgumentException("JSON body is required");
        if (!request.authorizedTarget()) {
            throw new IllegalArgumentException(
                    "Confirm that you own or are authorized to test the target before creating the Test Plan");
        }
        return new TestPlan(id, request.name(), request.profile(), definitionIdentity, target,
                request.suiteMetadataDelivery(), request.declaredFeatures(), request.parameters(), request.interaction(),
                createdAt, updatedAt);
    }

    private static TestPlan.Target resolveTarget(
            ApiModels.PlanWrite request,
            com.samlscope.store.SqliteTargetConnectionRepository targets,
            ManagementAuthorization authorization,
            Context context,
            AppConfig config) {
        if (request.targetConnectionId() == null && request.targetRevisionId() == null) {
            return new TestPlan.Target(request.targetKind(), request.targetEntityId(),
                    new TestPlan.MetadataSource(
                            request.metadataSourceKind(), request.metadataSourceLocation()));
        }
        if (request.targetConnectionId() == null || request.targetRevisionId() == null) {
            throw new IllegalArgumentException("Select a target and metadata revision");
        }
        var owner = authorization.connectionOwner(context, true, config.managementProtected());
        var revision = targets.findRevision(
                        owner, request.targetConnectionId(), request.targetRevisionId())
                .orElseThrow(() -> new IllegalArgumentException("Target metadata unavailable"));
        var target = targets.list(owner).stream()
                .filter(value -> value.id().equals(revision.connectionId()))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Target unavailable"));
        if (!revision.roles().contains(request.profile().role())) {
            throw new IllegalArgumentException("Target does not have the selected role");
        }
        var kind = request.profile().role() == com.samlscope.core.plan.TargetRole.IDP
                ? com.samlscope.core.plan.TargetKind.IDP : com.samlscope.core.plan.TargetKind.SP;
        return new TestPlan.Target(
                kind, target.entityId(),
                new TestPlan.MetadataSource(
                        com.samlscope.core.plan.MetadataSourceKind.SNAPSHOT_BASE64,
                        revision.metadataBase64()),
                target.id(), revision.id());
    }

    private static ApiModels.PlanView view(AppConfig config, TestPlan plan) {
        var entityId = peerEntityId(config, plan);
        var secondaryEntityId = secondaryIdpEntityId(config, plan);
        var summary = new ApiModels.PlanSummary(
                plan.id(), plan.name(), plan.profile(),
                new ApiModels.TargetSummary(
                        plan.target().kind(), plan.target().entityId(),
                        plan.target().connectionId(), plan.target().metadataRevisionId()),
                plan.parameters().requestSigningMode());
        return new ApiModels.PlanView(summary, entityId, entityId + "/metadata",
                config.peerBaseUrl().resolve("/mdq/" + java.net.URLEncoder.encode(entityId, StandardCharsets.UTF_8)).toString(),
                secondaryEntityId, secondaryEntityId + "/metadata");
    }

    private static String peerEntityId(AppConfig config, TestPlan plan) {
        return com.samlscope.peer.PeerIdentity.primary(config.peerBaseUrl(), plan.id()).toString();
    }

    private static String secondaryIdpEntityId(AppConfig config, TestPlan plan) {
        return com.samlscope.peer.PeerIdentity.secondaryIdp(config.peerBaseUrl(), plan.id()).toString();
    }

    private static TestPlan requirePlan(PlanRepository plans, String id) {
        return plans.find(id).orElseThrow(() -> new IllegalArgumentException("Unknown Test Plan"));
    }

    private static com.samlscope.core.run.TestRun requireRun(RunRepository runs, String id) {
        return runs.find(id).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
    }

    private static String requiredQuery(Context ctx, String name) {
        var value = ctx.queryParam(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing query parameter " + name);
        return value;
    }

    private static Map<String, List<String>> headers(Context ctx) {
        var result = new LinkedHashMap<String, List<String>>();
        var names = ctx.req().getHeaderNames();
        while (names.hasMoreElements()) {
            var name = names.nextElement();
            result.put(name, java.util.Collections.list(ctx.req().getHeaders(name)));
        }
        return result;
    }

    private static String absoluteRequestUrl(Context ctx) {
        var query = ctx.req().getQueryString();
        return ctx.url() + (query == null ? "" : "?" + query);
    }

    private static HttpStatus metadataRedirectStatus(MetadataService.Variant variant) {
        return switch (variant) {
            case REDIRECT_301 -> HttpStatus.MOVED_PERMANENTLY;
            case REDIRECT_302 -> HttpStatus.FOUND;
            case REDIRECT_307 -> HttpStatus.TEMPORARY_REDIRECT;
            default -> null;
        };
    }

    private static void securityHeaders(Context ctx) {
        ctx.header("X-Content-Type-Options", "nosniff");
        ctx.header("Referrer-Policy", "no-referrer");
        ctx.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
        ctx.header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                + "connect-src 'self'; img-src 'self' data:; form-action 'self'; "
                + "frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
    }

    private static void enforceConfiguredOrigin(Context ctx, AppConfig config) {
        if (!config.managementProtected()) return;
        var peerRoute = ctx.path().startsWith("/p/") || ctx.path().startsWith("/mdq/");
        var expected = peerRoute ? config.peerBaseUrl() : config.publicBaseUrl();
        var host = ctx.header("Host");
        if (host == null || !authorityMatches(host, expected)) {
            throw new MisdirectedRequest("This endpoint is not available on the requested origin");
        }
    }

    private static String preloadedCacheKey(String planId, String runId) {
        // The aggregate is a stable Run fixture. Rearming rotates only the access token and a
        // mutable Plan is intentionally observed by a fresh Run, not by changing an active one.
        return planId + "\n" + runId;
    }

    private static String hostedOwnerId(String sourceAddress) {
        try {
            var digest = MessageDigest.getInstance("SHA-256")
                    .digest(sourceAddress.getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean authorityMatches(String hostHeader, URI expected) {
        try {
            var actual = URI.create(expected.getScheme() + "://" + hostHeader);
            return expected.getHost().equalsIgnoreCase(actual.getHost())
                    && effectivePort(expected) == effectivePort(actual);
        } catch (IllegalArgumentException invalidHost) {
            return false;
        }
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static void serveIndex(Context ctx) {
        serveClasspath(ctx, "/public/index.html", "text/html; charset=utf-8");
    }

    private static void serveAsset(Context ctx) {
        var file = ctx.pathParam("file");
        if (!file.matches("[A-Za-z0-9._-]+")) throw new IllegalArgumentException("Invalid asset name");
        var contentType = file.endsWith(".js") ? "text/javascript; charset=utf-8"
                : file.endsWith(".css") ? "text/css; charset=utf-8" : "application/octet-stream";
        serveClasspath(ctx, "/public/assets/" + file, contentType);
    }

    private static void serveClasspath(Context ctx, String name, String contentType) {
        try (var stream = SamlScopeApplication.class.getResourceAsStream(name)) {
            if (stream == null) {
                ctx.status(HttpStatus.NOT_FOUND);
                return;
            }
            ctx.contentType(contentType).result(stream.readAllBytes());
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Could not serve application asset", e);
        }
    }

    private static String origin(URI uri) {
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException("SAML destination must be an absolute HTTP(S) URL");
        }
        var scheme = uri.getScheme().toLowerCase(java.util.Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            throw new IllegalArgumentException("SAML destination must use HTTP or HTTPS");
        }
        var host = uri.getHost().contains(":") ? "[" + uri.getHost() + "]" : uri.getHost();
        var authority = host + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
        return scheme + "://" + authority;
    }

    private static String htmlEscape(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    static String metadataPollingTransitionPage(String next, int delaySeconds) {
        var delay = Math.max(0, delaySeconds);
        var escaped = htmlEscape(next);
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta http-equiv=\"refresh\" content=\"" + delay + ";url=" + escaped + "\">"
                + "<title>Waiting for the target metadata refresh window</title></head><body>"
                + "<h1>Fixture accepted</h1><p>SAMLscope recorded the correlated metadata fetch and "
                + "Success response.</p><p>The next signed request starts automatically in " + delay
                + " seconds. This pacing lets a target's standard metadata-key refresh window "
                + "elapse; it does not affect the conformance outcome.</p><p><a href=\"" + escaped
                + "\">Continue now</a></p></body></html>";
    }

    private static final class MisdirectedRequest extends RuntimeException {
        private MisdirectedRequest(String message) { super(message); }
    }
}
