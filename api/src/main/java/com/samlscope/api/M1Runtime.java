package com.samlscope.api;

import java.net.URI;
import java.time.Clock;
import java.util.Locale;
import java.util.Map;
import java.util.List;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.evaluation.CoverageCatalogMapper;
import com.samlscope.core.evaluation.PredicateCatalogMapper;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.TestRun;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.CaseRunProjection;
import com.samlscope.runner.ApprovedCaseStarter;
import com.samlscope.runner.ActiveProbeCoordinator;
import com.samlscope.runner.AttestationService;
import com.samlscope.runner.ConfigurationService;
import com.samlscope.runner.BrowserCompletionService;
import com.samlscope.runner.BootstrapContractService;
import com.samlscope.runner.CatalogApplicabilityProvider;
import com.samlscope.runner.CaseExecutionService;
import com.samlscope.runner.CaseTimeoutService;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.OutboxIncidentProjection;
import com.samlscope.runner.PendingInteractionService;
import com.samlscope.runner.PersistedApplicabilityInputProvider;
import com.samlscope.runner.ProtocolEvidenceAutomationService;
import com.samlscope.runner.QuickCheckService;
import com.samlscope.runner.RunEvaluationService;
import com.samlscope.runner.RunCampaignService;
import com.samlscope.runner.access.RunAccessService;
import com.samlscope.runner.cases.CachedTargetSigningCertificateProvider;
import com.samlscope.runner.cases.ApprovedAttestedCaseRegistry;
import com.samlscope.runner.cases.ApprovedConfigCaseRegistry;
import com.samlscope.runner.cases.ApprovedBrowserCaseRegistry;
import com.samlscope.runner.cases.M2AutomatedCaseRegistry;
import com.samlscope.runner.cases.M3AutomatedCaseRegistry;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.outbox.OutboundDispatcher;
import com.samlscope.runner.result.DefaultResultContextProvider;
import com.samlscope.runner.result.EvaluationArtifactDigests;
import com.samlscope.runner.result.ResultDocumentContext;
import com.samlscope.runner.result.ResultJsonWriter;
import com.samlscope.runner.result.ResultPublicationService;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.store.FileRunArtifactRepository;
import com.samlscope.store.JsonCodec;
import com.samlscope.store.MetadataCache;
import com.samlscope.store.SqliteApplicabilityInputRepository;
import com.samlscope.store.SqliteCaseExecutionRepository;
import com.samlscope.store.SqliteDatabase;
import com.samlscope.store.SqliteRunAccessGrantRepository;
import com.samlscope.store.SqlitePublicationRepository;
import com.samlscope.store.SqliteHostedRunProvisioner;

/** Phase 1 execution composition kept outside the HTTP root so its boundaries remain independently testable. */
final class M1Runtime {
    private final AppConfig config;
    private final QuickCheckService quickCheck;
    private final ResultPublicationService results;
    private final FileRunArtifactRepository artifacts;
    private final RunAccessService access;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final TranscriptRecorder transcript;
    private final Clock clock;
    private final Map<com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone, List<ApprovedCaseStarter>> starters;
    private final PendingInteractionService pendingInteractions;
    private final BootstrapContractService bootstrapContracts;
    private final ProtocolEvidenceAutomationService protocolEvidence;
    private final AttestationService attestations;
    private final ConfigurationService configurations;
    private final BrowserCompletionService browserCompletions;
    private final SqliteCaseExecutionRepository caseExecutions;
    private final SqlitePublicationRepository publications;
    private final HostedRateLimiter reconciliationLimiter;
    private final SqliteHostedRunProvisioner hostedRunProvisioner;
    private final HostedEvidenceWorkGate evidenceWorkGate = new HostedEvidenceWorkGate();
    private final ActiveProbeCoordinator activeProbes;
    private final CaseTimeoutService timeouts;
    private final RunCampaignService campaigns;
    private final com.samlscope.runner.CampaignActionCompletionService campaignActions;

    private M1Runtime(
            AppConfig config,
            QuickCheckService quickCheck,
            ResultPublicationService results,
            FileRunArtifactRepository artifacts,
            RunAccessService access,
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            Clock clock,
            Map<com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone, List<ApprovedCaseStarter>> starters,
            PendingInteractionService pendingInteractions,
            BootstrapContractService bootstrapContracts,
            ProtocolEvidenceAutomationService protocolEvidence,
            AttestationService attestations,
            ConfigurationService configurations,
            BrowserCompletionService browserCompletions,
            SqliteCaseExecutionRepository caseExecutions,
            SqlitePublicationRepository publications,
            HostedRateLimiter reconciliationLimiter,
            SqliteHostedRunProvisioner hostedRunProvisioner,
            ActiveProbeCoordinator activeProbes,
            CaseTimeoutService timeouts,
            RunCampaignService campaigns,
            com.samlscope.runner.CampaignActionCompletionService campaignActions) {
        this.config = config;
        this.quickCheck = quickCheck;
        this.results = results;
        this.artifacts = artifacts;
        this.access = access;
        this.plans = plans;
        this.runs = runs;
        this.transcript = transcript;
        this.clock = clock;
        this.starters = Map.copyOf(starters);
        this.pendingInteractions = pendingInteractions;
        this.bootstrapContracts = bootstrapContracts;
        this.protocolEvidence = protocolEvidence;
        this.attestations = attestations;
        this.configurations = configurations;
        this.browserCompletions = browserCompletions;
        this.caseExecutions = caseExecutions;
        this.publications = publications;
        this.reconciliationLimiter = reconciliationLimiter;
        this.hostedRunProvisioner = hostedRunProvisioner;
        this.activeProbes = activeProbes;
        this.timeouts = timeouts;
        this.campaigns = campaigns;
        this.campaignActions = campaignActions;
    }

    static M1Runtime create(
            AppConfig config,
            SqliteDatabase database,
            JsonCodec json,
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            TranscriptContentReader transcriptContent,
            MetadataCache metadataCache,
            TargetMetadataParser metadataParser,
            FilePlanKeyStore keys,
            SqliteCaseExecutionRepository caseExecutions,
            com.samlscope.runner.MetadataLabService metadataLab,
            OutboundDispatcher outboundDispatcher,
            HostedRateLimiter reconciliationLimiter,
            SqliteHostedRunProvisioner hostedRunProvisioner,
            Clock clock) {
        var documents = CatalogDocuments.load();
        var coverage = CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
        var predicates = PredicateCatalogMapper.fromDocument(documents.parsed("tests/predicates.yaml"));
        var definitions = CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));
        java.util.function.Function<String, byte[]> runMetadata = runId -> {
            var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            return metadataCache.getRunSnapshot(run.id(), run.planId());
        };
        var targetCertificates = new CachedTargetSigningCertificateProvider(metadataCache, metadataParser);
        java.util.function.BiFunction<com.samlscope.core.plan.TestPlan, String, IdpErrorProbeConfiguration> probeConfigurations = (plan, runId) -> {
            var inactive = config.peerBaseUrl().resolve("/p/" + plan.id() + "/inactive-idp-probe");
            var endpoint = inactive;
            var responseLocationKnown = false;
            try {
                var targetMetadata = metadataParser.parse(runMetadata.apply(runId), plan.target().entityId());
                endpoint = targetMetadata.singleSignOnServices().stream()
                        .filter(value -> com.samlscope.saml.metadata.MetadataService.POST.equals(value.binding()))
                        .map(com.samlscope.saml.metadata.TargetMetadata.Endpoint::location)
                        .findFirst().orElse(inactive);
                responseLocationKnown = !endpoint.equals(inactive);
            } catch (RuntimeException unavailable) {
                responseLocationKnown = false;
            }
            return new IdpErrorProbeConfiguration(
                    endpoint,
                    config.peerBaseUrl().resolve("/p/" + plan.id()).toString(),
                    config.peerBaseUrl().resolve("/p/" + plan.id() + "/sp/acs/0"),
                    // Browser-assisted scenarios are queued together. The timeout belongs to the
                    // target response after an operator starts a fixture, not to time spent waiting
                    // behind earlier fixtures in the Run-level queue. Keep queued scenarios alive
                    // for a normal interactive acceptance session; delivery uncertainty still maps
                    // to NOT_VERIFIED rather than a target failure.
                    java.time.Duration.ofHours(2),
                    plan.interaction().allowBrowserSteps(),
                    responseLocationKnown,
                    true);
        };
        var quickCheck = new QuickCheckService(
                plans, runs, transcript, transcriptContent, caseExecutions, keys, targetCertificates,
                config.peerBaseUrl(), clock, definitions, probeConfigurations);
        var applicability = new CatalogApplicabilityProvider(
                coverage, predicates,
                new PersistedApplicabilityInputProvider(new SqliteApplicabilityInputRepository(database, json)));
        var m1Attested = ApprovedAttestedCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1,
                config.publicBaseUrl(),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return probeConfigurations.apply(plan, runId);
                }, transcriptContent,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    try { return targetCertificates.certificatesFor(plan, runId); }
                    catch (RuntimeException unavailable) { return List.of(); }
                });
        var runDecryptionKeys = (com.samlscope.runner.cases.SamlDecryptionKeyProvider) runId -> {
            var run = runs.find(runId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            return java.util.Optional.of(keys.getOrCreate(run.planId()).privateKey());
        };
        var m1Config = ApprovedConfigCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1,
                runMetadata, transcriptContent, runDecryptionKeys);
        var m1Browser = ApprovedBrowserCaseRegistry.create(
                definitions, config.publicBaseUrl(), transcriptContent,
                runDecryptionKeys,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return targetCertificates.certificatesFor(plan, runId);
                },
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return probeConfigurations.apply(plan, runId);
                },
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    return java.util.Optional.of(keys.getOrCreate(run.planId()));
                });
        var m2Attested = ApprovedAttestedCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,
                null, null, null, null, null, runMetadata);
        var m2Config = ApprovedConfigCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,
                runMetadata);
        var m2Browser = ApprovedBrowserCaseRegistry.create(
                definitions, config.publicBaseUrl(),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,
                transcriptContent, runDecryptionKeys,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return targetCertificates.certificatesFor(plan, runId);
                },
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return probeConfigurations.apply(plan, runId);
                },
                runId -> java.util.Optional.empty());
        var m2Automated = M2AutomatedCaseRegistry.create(runId -> {
            try {
                return runMetadata.apply(runId);
            } catch (com.samlscope.store.StoreException unavailable) {
                return null;
            }
        });
        var m3Attested = ApprovedAttestedCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3,
                config.publicBaseUrl(), null, transcriptContent,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    try { return targetCertificates.certificatesFor(plan, runId); }
                    catch (RuntimeException unavailable) { return List.of(); }
                });
        var m3Config = ApprovedConfigCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3);
        var m3Browser = ApprovedBrowserCaseRegistry.create(
                definitions, config.publicBaseUrl(),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3,
                transcriptContent, runDecryptionKeys,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()),
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    try { return targetCertificates.certificatesFor(plan, runId); }
                    catch (RuntimeException unavailable) { return List.of(); }
                },
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return probeConfigurations.apply(plan, runId);
                },
                runId -> java.util.Optional.of(keys.getOrCreate(
                        runs.find(runId).orElseThrow().planId())));
        var m3Automated = M3AutomatedCaseRegistry.create(
                runId -> {
                    try { return runMetadata.apply(runId); }
                    catch (com.samlscope.store.StoreException unavailable) { return null; }
                },
                transcriptContent,
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    try { return targetCertificates.certificatesFor(plan, runId); }
                    catch (RuntimeException unavailable) { return List.of(); }
                },
                runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    return java.util.Optional.of(keys.getOrCreate(run.planId()).privateKey());
                });
        var interactiveRegistry = com.samlscope.runner.TestCaseRegistry.merge(
                m1Attested, m1Config, m1Browser,
                m2Automated, m2Attested, m2Config, m2Browser,
                m3Automated, m3Attested, m3Config, m3Browser);
        var executionService = new CaseExecutionService(caseExecutions,
                new com.samlscope.runner.PlanRequestSigning(plans, runs, keys));
        var caseContexts = (com.samlscope.runner.CaseContextProvider) runId -> caseContext(
                runId, plans, runs, transcript, clock);
        var activeProbes = new ActiveProbeCoordinator(
                config.peerBaseUrl(), plans, runs, caseExecutions, outboundDispatcher,
                transcript, caseContexts, probeConfigurations, interactiveRegistry, clock, executionService);
        var starters = Map.of(
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m1Attested, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m1Config, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m1Browser, executionService, applicability)),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m2Automated, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m2Attested, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m2Config, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m2Browser, executionService, applicability)),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m3Automated, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m3Attested, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m3Config, executionService, applicability),
                        new ApprovedCaseStarter(coverage, definitions, m3Browser, executionService, applicability)));
        var pendingInteractions = new PendingInteractionService(caseExecutions, interactiveRegistry);
        var bootstrapContracts = new BootstrapContractService(
                definitions, caseExecutions, plans, runs, transcript, metadataLab);
        var protocolEvidence = new ProtocolEvidenceAutomationService(
                caseExecutions, interactiveRegistry, executionService, caseContexts);
        var attestations = new AttestationService(interactiveRegistry, executionService, caseContexts);
        var configurations = new ConfigurationService(interactiveRegistry, executionService, caseContexts);
        var browserCompletions = new BrowserCompletionService(interactiveRegistry, executionService, caseContexts);
        var timeouts = new CaseTimeoutService(caseExecutions, interactiveRegistry, executionService);
        var campaigns = new RunCampaignService(
                caseExecutions, definitions, interactiveRegistry, caseContexts, metadataLab::state);
        var campaignActions = new com.samlscope.runner.CampaignActionCompletionService(
                campaigns, interactiveRegistry, browserCompletions);
        var evaluator = new RunEvaluationService(
                coverage, plans, runs,
                new CaseRunProjection(caseExecutions, definitions.byId().keySet()), applicability,
                new OutboxIncidentProjection(caseExecutions));
        var artifacts = new FileRunArtifactRepository(config.dataDirectory());
        ResultPublicationService results = null;
        if (!config.suiteImageDigest().isBlank()) {
            var components = EvaluationArtifactDigests.fromDocuments(
                    documents.bytes("tests/coverage.yaml"), documents.testDefinitions(),
                    documents.bytes("tests/specs.yaml"));
            var contexts = new DefaultResultContextProvider(
                    new ResultDocumentContext.Suite(
                            "SAMLscope", "0.1.0", config.suiteImageDigest(),
                            config.mode().name().toLowerCase(Locale.ROOT)),
                    components,
                    URI.create("https://github.com/sgrastar/samlscope/blob/main/docs/04-requirement-coverage.md"),
                    URI.create("https://github.com/sgrastar/samlscope/blob/main/tests/cases.yaml"),
                    run -> metadataCache.getRunSnapshot(run.id(), run.planId()),
                    campaigns::report);
            results = new ResultPublicationService(
                    coverage, evaluator, contexts, new ResultJsonWriter(), artifacts);
        }
        var access = new RunAccessService(
                config.publicBaseUrl(), runs, new SqliteRunAccessGrantRepository(database), clock);
        var publications = new SqlitePublicationRepository(database);
        return new M1Runtime(
                config, quickCheck, results, artifacts, access, plans, runs, transcript, clock,
                starters, pendingInteractions, bootstrapContracts, protocolEvidence, attestations,
                configurations, browserCompletions, caseExecutions, publications,
                reconciliationLimiter, hostedRunProvisioner, activeProbes, timeouts,
                campaigns, campaignActions);
    }

    QuickCheckService.QuickCheckResult quickCheck(String runId) {
        return withManualEvidenceWork(runId, () -> {
            var value = quickCheck.execute(runId);
            var run = requireRun(runId);
            var plan = requirePlan(run);
            startInteractive(run, plan, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1);
            reconcileTranscriptEvidenceNow(runId);
            if (results != null) results.generate(runId);
            return value;
        });
    }

    void reconcileTranscriptEvidenceAutomatically(String runId) {
        if (config.mode() == AppConfig.Mode.HOSTED
                && !publications.isTranscriptEvidenceComplete(runId)) return;
        if (config.mode() == AppConfig.Mode.HOSTED) {
            evidenceWorkGate.executeAutomatic(() -> reconcileTranscriptEvidenceNow(runId));
        } else {
            reconcileTranscriptEvidenceNow(runId);
        }
    }

    private void reconcileTranscriptEvidenceNow(String runId) {
        requireRun(runId);
        var expiredProbe = activeProbes.expireReady(runId);
        var expired = timeouts.expireReady(runId, caseContext(runId));
        var evaluation = protocolEvidence.evaluateReady(runId);
        if ((expiredProbe.isPresent() || !expired.isEmpty() || !evaluation.completed().isEmpty())
                && results != null) {
            results.generate(runId);
        }
    }

    ActiveProbeCoordinator.Status activeProbeStatus(String runId) {
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return activeProbes.status(runId);
        });
    }

    /** Public probe routes need only the coordinator state; Transcript automation runs separately. */
    ActiveProbeCoordinator.Status activeProbeRouteStatus(String runId) {
        requireRun(runId);
        var expired = activeProbes.expireReady(runId);
        if (expired.isPresent() && results != null) results.generate(runId);
        return activeProbes.status(runId);
    }

    ActiveProbeCoordinator.PreparedProbe prepareActiveProbe(
            String runId, String actionId, boolean freshSessionConfirmed) {
        requireRun(runId);
        return activeProbes.prepare(runId, actionId, freshSessionConfirmed);
    }

    ActiveProbeCoordinator.Status acceptActiveProbe(
            String runId,
            String actionId,
            byte[] decodedSaml,
            com.samlscope.core.evaluation.EvidenceRef evidence) {
        var status = activeProbes.accept(runId, actionId, decodedSaml, evidence);
        if (results != null) {
            // The coordinator may already be reporting the next case in the chain.
            // Publish the outcome of the case that received this response instead
            // of waiting for every queued scenario to finish.
            var completedCase = caseExecutions.findOutbox(actionId)
                    .flatMap(action -> caseExecutions.find(runId, action.caseId()))
                    .filter(execution -> execution.status()
                            == com.samlscope.core.caseexec.CaseExecutionStatus.FINISHED);
            if (completedCase.isPresent()) results.generate(runId);
        }
        return status;
    }

    ActiveProbeCoordinator.Status abortActiveProbe(String runId) {
        requireRun(runId);
        var status = activeProbes.abort(runId);
        if (results != null) results.generate(runId);
        return status;
    }

    ActiveProbeCoordinator.Status retryActiveProbe(String runId) {
        requireRun(runId);
        return activeProbes.retry(runId);
    }

    record WorkspaceEvidence(
            java.util.List<com.samlscope.runner.InteractionQuery.PendingInteraction> interactions,
            java.util.List<com.samlscope.runner.BootstrapContractQuery.BootstrapContract> bootstrapContracts,
            com.samlscope.runner.ProtocolEvidenceAutomationService.Status protocolEvidence,
            ActiveProbeCoordinator.Status activeProbe,
            com.samlscope.runner.RunCampaignQuery.CampaignReport campaigns) {}

    WorkspaceEvidence workspaceEvidence(String runId) {
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return new WorkspaceEvidence(pendingInteractions.pending(runId),
                    bootstrapContracts.contracts(runId), protocolEvidence.status(runId),
                    activeProbes.status(runId), campaigns.report(runId));
        });
    }

    java.util.List<com.samlscope.runner.InteractionQuery.PendingInteraction> pending(String runId) {
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return pendingInteractions.pending(runId);
        });
    }

    com.samlscope.runner.RunCampaignQuery.CampaignReport campaigns(String runId) {
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return campaigns.report(runId);
        });
    }

    java.util.List<com.samlscope.runner.BootstrapContractQuery.BootstrapContract> bootstrapContracts(String runId) {
        return withManualEvidenceWork(runId, () -> bootstrapContracts.contracts(runId));
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Status protocolEvidence(String runId) {
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return protocolEvidence.status(runId);
        });
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Evaluation evaluateProtocolEvidence(String runId) {
        return withManualEvidenceWork(runId, () -> {
            var value = protocolEvidence.evaluateReady(runId);
            if (results != null) results.generate(runId);
            return value;
        });
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Evaluation confirmProtocolEvidenceAttempts(
            String runId) {
        return withManualEvidenceWork(runId, () -> {
            var value = protocolEvidence.evaluateAttempted(runId);
            if (results != null) results.generate(runId);
            return value;
        });
    }

    com.samlscope.runner.AttestationExecutor.Result attest(
            String runId, String caseId, String value, String note) {
        return withManualEvidenceWork(runId, () -> {
            var result = attestations.attest(runId, caseId, value, note);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.ConfigurationExecutor.Result configure(
            String runId, String caseId, String value, String note) {
        return withManualEvidenceWork(runId, () -> {
            var result = configurations.answer(runId, caseId, value, note);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.BrowserCompletionExecutor.Result completeBrowser(String runId, String caseId) {
        return withManualEvidenceWork(runId, () -> {
            var result = browserCompletions.complete(runId, caseId);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.CampaignActionCompletionService.Result completeCampaignAction(
            String runId, String campaignId, String actionId) {
        return withManualEvidenceWork(runId, () -> {
            var result = campaignActions.complete(runId, campaignId, actionId);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    java.util.List<com.samlscope.core.caseexec.CaseExecution> startMilestone(
            String runId, String milestoneName) {
        return withManualEvidenceWork(runId, () -> {
            var milestone = parseMilestone(milestoneName);
            var run = requireRun(runId);
            var plan = requirePlan(run);
            if (milestone == com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3
                    && plan.profile() == com.samlscope.core.plan.PlanProfile.IDP_FULL
                    && !com.samlscope.runner.outbox.EcpProbeService.allRequiredFixturesSent(
                            caseExecutions, run.id())) {
                throw new IllegalArgumentException(
                        "Run the ECP, channel-binding, and SAML-EC probes before starting M3 for an IdP Full Profile Run");
            }
            var started = startInteractive(run, plan, milestone);
            reconcileTranscriptEvidenceNow(runId);
            if (results != null) results.generate(runId);
            return started;
        });
    }

    byte[] requireResult(String runId) {
        if (config.mode() == AppConfig.Mode.HOSTED) requireTranscriptEvidenceComplete(runId);
        else reconcileTranscriptEvidenceNow(runId);
        return artifacts.findResult(runId)
                .orElseThrow(() -> new IllegalArgumentException(
                        results == null
                                ? "Result generation requires SAMLSCOPE_IMAGE_DIGEST"
                                : "Result artifact has not been generated"));
    }

    byte[] requireReport(String runId) {
        if (results == null) throw new IllegalArgumentException("Report generation requires SAMLSCOPE_IMAGE_DIGEST");
        if (config.mode() == AppConfig.Mode.HOSTED) requireTranscriptEvidenceComplete(runId);
        else reconcileTranscriptEvidenceNow(runId);
        return results.requireReport(runId);
    }

    PublicationRoutes.Published publish(String runId) {
        if (config.mode() != AppConfig.Mode.HOSTED || !config.publishEnabled()) {
            throw new IllegalArgumentException("Hosted publication is disabled; export report.html locally instead");
        }
        requireRun(runId);
        if (results == null) throw new IllegalArgumentException("Publication requires SAMLSCOPE_IMAGE_DIGEST");
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            results.generate(runId);
            if (!publications.publish(runId, clock.instant())) {
                throw new IllegalArgumentException(
                        "This Run cannot be published because Transcript evidence was rejected at its capacity limit");
            }
            return new PublicationRoutes.Published(
                    runId, config.publicBaseUrl().resolve("/reports/" + runId));
        });
    }

    private <T> T withManualEvidenceWork(String runId, java.util.function.Supplier<T> operation) {
        requireTranscriptEvidenceComplete(runId);
        if (config.mode() != AppConfig.Mode.HOSTED) return operation.get();
        return evidenceWorkGate.executeManual(() -> {
            requireManualReconciliationAllowed(runId);
            return operation.get();
        });
    }

    private void requireManualReconciliationAllowed(String runId) {
        reconciliationLimiter.requireAllowedTogether(
                new HostedRateLimiter.Rule(
                        "transcript-reconciliation-owner",
                        hostedRunProvisioner.ownerForRun(runId), 6,
                        java.time.Duration.ofMinutes(1)),
                new HostedRateLimiter.Rule(
                        "transcript-reconciliation-run", runId, 4,
                        java.time.Duration.ofMinutes(1)),
                new HostedRateLimiter.Rule(
                        "transcript-reconciliation-global", "service", 30,
                        java.time.Duration.ofMinutes(1)));
    }

    private void requireTranscriptEvidenceComplete(String runId) {
        requireRun(runId);
        if (config.mode() == AppConfig.Mode.HOSTED
                && !publications.isTranscriptEvidenceComplete(runId)) {
            throw new IllegalArgumentException(
                    "Transcript evidence was rejected; this Run is incomplete and cannot produce an artifact");
        }
    }

    boolean isPublished(String runId) {
        return config.mode() == AppConfig.Mode.HOSTED && publications.isPublished(runId);
    }

    RunAccessService.ManagementSession exchange(String runId, String token) {
        if (!config.managementProtected()) {
            throw new IllegalArgumentException("Management sessions require Hosted mode or OIDC");
        }
        return access.exchange(runId, token);
    }

    void authorize(String runId, String sessionToken) {
        if (config.managementProtected()) access.authorize(runId, sessionToken);
    }

    RunAccessService.ManagementSession resumeManagementSession(String runId, String sessionToken) {
        if (!config.managementProtected()) throw new SecurityException("Management sessions are disabled");
        return access.resume(runId, sessionToken);
    }

    void authorizeMutation(String runId, String sessionToken, String csrfToken) {
        if (config.managementProtected()) access.authorizeMutation(runId, sessionToken, csrfToken);
    }

    java.util.List<com.samlscope.core.plan.TestPlan> authorizedPlans(String sessionToken) {
        if (!config.managementProtected()) return plans.list();
        var run = requireRun(access.authorizeSession(sessionToken));
        return java.util.List.of(requirePlan(run));
    }

    void authorizePlan(String planId, String sessionToken) {
        if (!config.managementProtected()) return;
        var run = requireRun(access.authorizeSession(sessionToken));
        if (!run.planId().equals(planId)) throw new SecurityException("Access denied");
    }

    void authorizePlanMutation(String planId, String sessionToken, String csrfToken) {
        if (!config.managementProtected()) return;
        var runId = access.authorizeSession(sessionToken);
        var run = requireRun(runId);
        if (!run.planId().equals(planId)) throw new SecurityException("Access denied");
        access.authorizeMutation(runId, sessionToken, csrfToken);
    }

    com.samlscope.runner.access.RunAccessService.PreparedAccess prepareManagementAccess(TestRun run) {
        if (!config.managementProtected()) {
            throw new IllegalStateException("Prepared management access requires Hosted mode or OIDC");
        }
        return access.prepareIssue(run.id());
    }

    private TestRun requireRun(String runId) {
        return runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
    }

    private com.samlscope.core.plan.TestPlan requirePlan(TestRun run) {
        return plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
    }

    private com.samlscope.core.caseexec.CaseContext caseContext(String runId) {
        var run = requireRun(runId);
        return caseContext(run, requirePlan(run));
    }

    private java.util.List<com.samlscope.core.caseexec.CaseExecution> startInteractive(
            TestRun run,
            com.samlscope.core.plan.TestPlan plan,
            com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone milestone) {
        if (run.status() != com.samlscope.core.run.RunStatus.COMPLETED) {
            throw new IllegalArgumentException("Milestone execution requires a completed baseline SSO round trip");
        }
        var context = caseContext(run, plan);
        var started = new java.util.ArrayList<com.samlscope.core.caseexec.CaseExecution>();
        starters.getOrDefault(milestone, List.of()).forEach(starter ->
                started.addAll(starter.startApplicable(run, plan, context)));
        return List.copyOf(started);
    }

    private com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone parseMilestone(String value) {
        try {
            return com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.valueOf(
                    value.toUpperCase(Locale.ROOT));
        } catch (RuntimeException invalid) {
            throw new IllegalArgumentException("Unknown implementation milestone: " + value, invalid);
        }
    }

    private com.samlscope.core.caseexec.CaseContext caseContext(
            TestRun run, com.samlscope.core.plan.TestPlan plan) {
        return new DefaultCaseContext(
                run.id(), plan.profile().role(), clock, plan.parameters(), plan.interaction(),
                run.targetToSuiteReachability(), transcript,
                run.status() == com.samlscope.core.run.RunStatus.COMPLETED);
    }

    private static com.samlscope.core.caseexec.CaseContext caseContext(
            String runId,
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            Clock clock) {
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        return new DefaultCaseContext(
                run.id(), plan.profile().role(), clock, plan.parameters(), plan.interaction(),
                run.targetToSuiteReachability(), transcript,
                run.status() == com.samlscope.core.run.RunStatus.COMPLETED);
    }
}
