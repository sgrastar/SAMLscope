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
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
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
import com.samlscope.runner.result.ReportHtmlWriter;
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
    private final com.samlscope.runner.TargetInitiatedIntents targetInitiated;
    private final com.samlscope.runner.SupplementalDecryptionKeyService supplementalKeys;
    private final java.util.function.Function<String, com.samlscope.runner.SupplementalDecryptionKeyService.Scope> supplementalKeyScopes;
    private final com.samlscope.runner.cases.ScopedSharedDecryptionKeys runDecryptionKeys;
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
    private final com.samlscope.runner.MetadataFetchAutomationService metadataFetches;
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
    private final com.samlscope.runner.FunctionalReleaseRegistry profileDefinitions;
    private final com.samlscope.core.evaluation.CoverageCatalog coverage;
    private final com.samlscope.runner.HistoricalRunReadPolicy historicalReads;
    private final com.samlscope.runner.ApplicabilityProvider applicability;

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
            com.samlscope.runner.MetadataFetchAutomationService metadataFetches,
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
            com.samlscope.runner.CampaignActionCompletionService campaignActions,
            com.samlscope.runner.FunctionalReleaseRegistry profileDefinitions,
            com.samlscope.core.evaluation.CoverageCatalog coverage,
            com.samlscope.runner.ApplicabilityProvider applicability,
            com.samlscope.runner.SupplementalDecryptionKeyService supplementalKeys,
            java.util.function.Function<String, com.samlscope.runner.SupplementalDecryptionKeyService.Scope> supplementalKeyScopes,
            com.samlscope.runner.TargetInitiatedIntents targetInitiated,
            com.samlscope.runner.cases.ScopedSharedDecryptionKeys runDecryptionKeys) {
        this.runDecryptionKeys = runDecryptionKeys;
        this.targetInitiated = targetInitiated;
        this.supplementalKeys = supplementalKeys;
        this.supplementalKeyScopes = supplementalKeyScopes;
        this.coverage = coverage;
        this.applicability = applicability;
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
        this.metadataFetches = metadataFetches;
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
        this.profileDefinitions = profileDefinitions;
        this.historicalReads = new com.samlscope.runner.HistoricalRunReadPolicy(profileDefinitions);
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
        return create(config, database, json, plans, runs, transcript, transcriptContent,
                metadataCache, metadataParser, keys, caseExecutions, metadataLab,
                outboundDispatcher, reconciliationLimiter, hostedRunProvisioner, clock,
                Map.of(), Map.of(), new com.samlscope.runner.TargetInitiatedIntents());
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
            Clock clock,
            Map<com.samlscope.core.profile.FunctionalProfile,byte[]> profileArtifacts,
            Map<com.samlscope.core.profile.FunctionalProfile,String> approvedProfileDigests) {
        return create(config, database, json, plans, runs, transcript, transcriptContent,
                metadataCache, metadataParser, keys, caseExecutions, metadataLab,
                outboundDispatcher, reconciliationLimiter, hostedRunProvisioner, clock,
                profileArtifacts, approvedProfileDigests, new com.samlscope.runner.TargetInitiatedIntents());
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
            Clock clock,
            Map<com.samlscope.core.profile.FunctionalProfile,byte[]> profileArtifacts,
            Map<com.samlscope.core.profile.FunctionalProfile,String> approvedProfileDigests,
            com.samlscope.runner.TargetInitiatedIntents targetInitiated) {
        var documents = CatalogDocuments.load();
        var coverage = CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
        var predicates = PredicateCatalogMapper.fromDocument(documents.parsed("tests/predicates.yaml"));
        var definitions = CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));
        // The protected composition binds the closed manifest to the retained signed C/A bytes.
        if (!"sha256:1e9c8bfb902ffaced1720b60d0b4e6590df04cc1838b467a1ba395d810e1f2f3"
                .equals(HistoricalFunctionalProfileDocuments.MANIFEST_SHA)) {
            throw new IllegalStateException("Historical release authority changed");
        }
        var currentProfileBundle = new FunctionalProfileDocuments.Bundle(profileArtifacts, approvedProfileDigests);
        // Reverify all retained originals before constructing any registry; typed catalogs are immutable.
        var retainedDefinitions = HistoricalFunctionalProfileDocuments.load(
                currentProfileBundle, documents, definitions, coverage, predicates);
        var profileDefinitions = new com.samlscope.runner.FunctionalReleaseRegistry(
                HistoricalFunctionalProfileDocuments.current(
                        currentProfileBundle, documents, definitions, coverage, predicates), retainedDefinitions);
        java.util.function.Function<com.samlscope.core.plan.TestPlan,
                com.samlscope.runner.FunctionalReleaseContext> releaseForPlan = plan ->
                profileDefinitions.require(plan.definitionIdentity());
        java.util.function.Function<com.samlscope.core.plan.TestPlan,
                com.samlscope.core.profile.FunctionalCaseDefinition> definitionForPlan = plan ->
                releaseForPlan.apply(plan).definition();
        java.util.function.Function<String, byte[]> runMetadata = runId -> {
            var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            return metadataCache.getRunSnapshot(run.id(), run.planId());
        };
        java.util.function.Function<String, com.samlscope.runner.SupplementalDecryptionKeyService.Scope> supplementalKeyScopes = runId -> {
            var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
            if (plan.profile() != com.samlscope.core.profile.FunctionalProfile.SINGLE_LOGOUT_IDP) {
                throw new IllegalArgumentException("Supplemental decryption keys require the IdP logout profile");
            }
            var metadata = runMetadata.apply(runId);
            String digest;
            try {
                digest = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(metadata));
            } catch (java.security.NoSuchAlgorithmException impossible) {
                throw new IllegalStateException("SHA-256 is unavailable");
            }
            return new com.samlscope.runner.SupplementalDecryptionKeyService.Scope(
                    plan.target().entityId(), digest, !caseExecutions.list(runId).isEmpty(),
                    new com.samlscope.saml.metadata.TargetEncryptionKeys().rsaKeys(metadata, plan.target().entityId(), plan.profile().role()));
        };
        var supplementalKeys = new com.samlscope.runner.SupplementalDecryptionKeyService(
                new com.samlscope.store.SqliteSupplementalDecryptionKeys(database, json), supplementalKeyScopes, clock);
        var targetCertificates = new CachedTargetSigningCertificateProvider(metadataCache, metadataParser);
        java.util.function.BiFunction<com.samlscope.core.plan.TestPlan, String, IdpErrorProbeConfiguration> probeConfigurations = (plan, runId) -> {
            var inactive = config.peerBaseUrl().resolve("/p/" + plan.id() + "/inactive-idp-probe");
            var endpoint = inactive;
            var responseLocationKnown = false;
            java.util.List<java.security.PublicKey> encryptionKeys = java.util.List.of();
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
            try {
                encryptionKeys = new com.samlscope.saml.metadata.TargetEncryptionKeys().rsaKeys(
                        runMetadata.apply(runId), plan.target().entityId(), com.samlscope.core.plan.TargetRole.IDP);
            } catch (RuntimeException unavailable) {
                // Missing or ambiguous encryption material must not disable ordinary controls.
                encryptionKeys = java.util.List.of();
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
                    true, encryptionKeys);
        };
        var quickCheck = new QuickCheckService(
                plans, runs, transcript, transcriptContent, caseExecutions, keys, targetCertificates,
                config.peerBaseUrl(), clock, definitions, probeConfigurations, definitionForPlan);
        var applicability = new CatalogApplicabilityProvider(
                coverage, predicates,
                new PersistedApplicabilityInputProvider(new SqliteApplicabilityInputRepository(database, json)),
                definitionForPlan, releaseForPlan);
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
        var runDecryptionKeys = new com.samlscope.runner.cases.ScopedSharedDecryptionKeys(runId -> {
            var run = runs.find(runId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            return java.util.Optional.of(keys.getOrCreate(run.planId()).privateKey());
        }, new com.samlscope.store.SqliteRunSharedKeyCommitments(database)::bind);
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
        m1Browser = ApprovedBrowserCaseRegistry.withSignatureModes(m1Browser, transcriptContent, runMetadata, runDecryptionKeys);
        m1Browser = ApprovedBrowserCaseRegistry.withNativeEcSignature(m1Browser, transcriptContent, runMetadata,
                config.dataDirectory().resolve("ec-signature-preparations"));
        m1Browser = ApprovedBrowserCaseRegistry.withNativeSignedRequests(m1Browser,transcriptContent,runMetadata,
                config.dataDirectory().resolve("signed-request-preparations"));
        var m2Attested = ApprovedAttestedCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,
                null, null, null, null, null, runMetadata);
        var pollingMetadata = MetadataUiAssetConfiguration.create(config.peerBaseUrl(), keys,
                new com.samlscope.saml.crypto.XmlSigner(), clock);
        m1Config = ApprovedConfigCaseRegistry.withAttributePolicyPreparation(m1Config, transcriptContent, runMetadata,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForPollingVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))),
                config.dataDirectory().resolve("attribute-policy-preparations"));
        m1Config = ApprovedConfigCaseRegistry.withRelyingPartyAttributePreparation(m1Config, transcriptContent, runMetadata,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))),
                config.dataDirectory().resolve("relying-party-attribute-preparations"));
        m1Config = ApprovedConfigCaseRegistry.withAuthnContextPreparation(m1Config, transcriptContent, runMetadata,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))),
                config.dataDirectory().resolve("authn-context-preparations"));
        m1Config = ApprovedConfigCaseRegistry.withNameIdOmissionPreparation(m1Config, transcriptContent, runMetadata,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))),
                config.dataDirectory().resolve("nameid-omission-preparations"));
        m1Browser = ApprovedBrowserCaseRegistry.withMetadataEncryption(m1Browser,transcriptContent,runMetadata,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForPollingVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))));
        var m2Config = ApprovedConfigCaseRegistry.create(
                definitions, com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2,
                runMetadata, transcriptContent, runDecryptionKeys,
                (runId, variant) -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> pollingMetadata.credentialsForPollingVariant(plan,
                                com.samlscope.saml.metadata.MetadataService.Variant.parse(variant))));
        m2Config = ApprovedConfigCaseRegistry.withMetadataKeySelection(m2Config, transcriptContent, runMetadata,
                config.dataDirectory().resolve("metadata-key-evidence"));
        m2Config = ApprovedConfigCaseRegistry.withMetadataRejection(m2Config, transcriptContent, runMetadata,
                config.dataDirectory().resolve("metadata-rejection-evidence"));
        m2Config = ApprovedConfigCaseRegistry.withAdditionalMetadataLocations(
                m2Config, definitions, transcriptContent, runMetadata, caseExecutions,
                runId -> {
                    var scopedRun = runs.find(runId).orElseThrow();
                    var scopedPlan = plans.find(scopedRun.planId()).orElseThrow();
                    return new com.samlscope.runner.cases.AdditionalMetadataLocationEvidence.Scope(
                            runId, scopedPlan.profile().name(), scopedPlan.target().entityId());
                });
        m2Config = ApprovedConfigCaseRegistry.withNativeCertificates(m2Config, transcriptContent, runMetadata,
                config.dataDirectory().resolve("certificate-evidence"));
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
        m2Browser = ApprovedBrowserCaseRegistry.withPublishedMetadata(m2Browser, runMetadata,
                runId -> runs.find(runId).flatMap(run -> plans.find(run.planId()))
                        .map(plan -> plan.target().entityId()));
        m2Browser = ApprovedBrowserCaseRegistry.withNativeUiLogo(m2Browser, transcriptContent, runMetadata,
                config.dataDirectory().resolve("ui-logo-evidence"));
        m2Browser = ApprovedBrowserCaseRegistry.withNativeUiDisplay(m2Browser, transcriptContent, runMetadata,
                config.dataDirectory().resolve("ui-display-evidence"));
        m2Browser = ApprovedBrowserCaseRegistry.withNativeUiUrls(m2Browser, transcriptContent, runMetadata,
                config.dataDirectory().resolve("ui-url-evidence"));
        var m2Automated = M2AutomatedCaseRegistry.create(runId -> {
            try {
                return runMetadata.apply(runId);
            } catch (com.samlscope.store.StoreException unavailable) {
                return null;
            }
        }, transcriptContent, runMetadata, config.dataDirectory().resolve("metadata-rejection-evidence"));
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
        m3Config = ApprovedConfigCaseRegistry.withMultipleDecryptionKeys(m3Config, supplementalKeys::keySet,
                caseExecutions::find);
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
        m3Browser = ApprovedBrowserCaseRegistry.withLogoutScenarios(m3Browser, (caseId, runId) -> {
            var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
            var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
            java.net.URI endpoint = null;
            var binding = com.samlscope.runner.BrowserFrontChannelScenario.Binding.HTTP_POST;
            java.security.PublicKey encryptionKey = null;
            java.util.List<java.security.PublicKey> encryptionKeys = java.util.List.of();
            java.util.List<java.security.PublicKey> publishedEncryptionKeys = java.util.List.of();
            java.util.List<java.security.cert.X509Certificate> certificates = java.util.List.of();
            try {
                var endpoints = metadataParser.parse(runMetadata.apply(runId), plan.target().entityId()).singleLogoutServices();
                if (!java.util.List.of(com.samlscope.runner.cases.IdpBasicLogoutScenarioTestCase.REDIRECT_ID,
                        com.samlscope.runner.cases.IdpBasicLogoutScenarioTestCase.REDIRECT_RESPONSE_ID).contains(caseId))
                    endpoint = endpoints.stream().filter(value -> com.samlscope.saml.metadata.MetadataService.POST.equals(value.binding()))
                            .map(com.samlscope.saml.metadata.TargetMetadata.Endpoint::location).findFirst().orElse(null);
                if (endpoint == null) {
                    endpoint = endpoints.stream().filter(value -> com.samlscope.saml.metadata.MetadataService.REDIRECT.equals(value.binding()))
                            .map(com.samlscope.saml.metadata.TargetMetadata.Endpoint::location).findFirst().orElse(null);
                    binding = com.samlscope.runner.BrowserFrontChannelScenario.Binding.SIGNED_REDIRECT;
                }
                certificates = targetCertificates.certificatesFor(plan, runId);
                if (com.samlscope.runner.cases.IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID.equals(caseId)
                        || com.samlscope.runner.cases.IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID.equals(caseId)) {
                    publishedEncryptionKeys = new com.samlscope.saml.metadata.TargetEncryptionKeys().rsaKeys(
                            runMetadata.apply(runId),plan.target().entityId(),plan.profile().role());
                    // Published metadata is merged with the Run's fixed supplemental input; metadata is never rewritten.
                    encryptionKeys = supplementalKeys.effectiveKeys(runId);
                    var suitePublicKey = keys.getOrCreate(plan.id()).certificate().getPublicKey().getEncoded();
                    encryptionKey = encryptionKeys.stream()
                            .filter(k -> !java.util.Arrays.equals(k.getEncoded(),suitePublicKey)).findFirst().orElse(null);
                }
            } catch (RuntimeException unavailable) {
                // Missing transport or signing metadata is an unmet Suite test precondition.
            }
            return new com.samlscope.runner.cases.IdpBasicLogoutScenarioTestCase.Configuration(
                    probeConfigurations.apply(plan, runId), endpoint,
                    config.peerBaseUrl().resolve("/p/" + plan.id() + "/sp/slo"), plan.target().entityId(),
                    keys.getOrCreate(plan.id()), certificates, binding, encryptionKey, encryptionKeys,
                    publishedEncryptionKeys);
        }, transcriptContent);
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
                transcript, caseContexts, probeConfigurations, interactiveRegistry, clock, executionService,
                runId -> keys.getOrCreate(runs.find(runId).orElseThrow().planId()));
        var starters = Map.of(
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M1, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m1Attested, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m1Config, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m1Browser, executionService, applicability, definitionForPlan, releaseForPlan)),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M2, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m2Automated, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m2Attested, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m2Config, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m2Browser, executionService, applicability, definitionForPlan, releaseForPlan)),
                com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3, List.of(
                        new ApprovedCaseStarter(coverage, definitions, m3Automated, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m3Attested, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m3Config, executionService, applicability, definitionForPlan, releaseForPlan),
                        new ApprovedCaseStarter(coverage, definitions, m3Browser, executionService, applicability, definitionForPlan, releaseForPlan)));
        var pendingInteractions = new PendingInteractionService(caseExecutions, interactiveRegistry);
        var bootstrapContracts = new BootstrapContractService(
                definitions, caseExecutions, plans, runs, transcript, metadataLab);
        var protocolEvidence = new ProtocolEvidenceAutomationService(
                caseExecutions, interactiveRegistry, executionService, caseContexts);
        var metadataFetches = new com.samlscope.runner.MetadataFetchAutomationService(
                caseExecutions, interactiveRegistry, outboundDispatcher, caseContexts);
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
                new com.samlscope.runner.ReleaseBoundCaseRunProjection(caseExecutions, runId -> {
                    var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
                    var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
                    return releaseForPlan.apply(plan);
                }), applicability,
                new OutboxIncidentProjection(caseExecutions), definitionForPlan, releaseForPlan);
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
            var historicalContexts = new DefaultResultContextProvider(
                    new ResultDocumentContext.Suite("SAMLscope", "0.1.0", config.suiteImageDigest(),
                            config.mode().name().toLowerCase(Locale.ROOT)), components,
                    URI.create("https://github.com/sgrastar/samlscope/blob/main/docs/04-requirement-coverage.md"),
                    URI.create("https://github.com/sgrastar/samlscope/blob/main/tests/cases.yaml"),
                    run -> metadataCache.getRunSnapshot(run.id(), run.planId()));
            results = new ResultPublicationService(
                    coverage, evaluator, new com.samlscope.runner.result.ReleaseBoundResultContextProvider(contexts, historicalContexts, profileDefinitions), new ResultJsonWriter(), artifacts,
                    new ReportHtmlWriter(
                            resource("/META-INF/samlscope/LICENSE"),
                            resource("/META-INF/samlscope/LICENSING.md"),
                            resource("/META-INF/samlscope/LICENSES/source-notices.json")));
        }
        var access = new RunAccessService(
                config.publicBaseUrl(), runs, new SqliteRunAccessGrantRepository(database), clock);
        var publications = new SqlitePublicationRepository(database);
        return new M1Runtime(
                config, quickCheck, results, artifacts, access, plans, runs, transcript, clock,
                starters, pendingInteractions, bootstrapContracts, protocolEvidence, metadataFetches, attestations,
                configurations, browserCompletions, caseExecutions, publications,
                reconciliationLimiter, hostedRunProvisioner, activeProbes, timeouts,
                campaigns, campaignActions, profileDefinitions, coverage, applicability, supplementalKeys,
                supplementalKeyScopes, targetInitiated, runDecryptionKeys);
    }

    java.util.Set<com.samlscope.core.profile.FunctionalProfile> installedProfiles() {
        return profileDefinitions.profiles();
    }

    com.samlscope.core.profile.FunctionalDefinitionIdentity definitionIdentity(
            com.samlscope.core.profile.FunctionalProfile profile) {
        return profileDefinitions.identity(profile);
    }

    record TargetInitiatedView(String runId, String kind, String expiresAt) {}

    TargetInitiatedView targetInitiated(String runId) {
        requireRun(runId);
        return targetInitiated.find(runId, clock)
                .map(value -> new TargetInitiatedView(runId, value.kind().name(), value.expiresAt().toString()))
                .orElse(null);
    }

    TargetInitiatedView prepareTargetInitiated(String runId, String kindText) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var run = requireRun(runId);
            var plan = requirePlan(run);
            com.samlscope.runner.TargetInitiatedIntents.Kind kind;
            try {
                kind = com.samlscope.runner.TargetInitiatedIntents.Kind.valueOf(
                        kindText == null ? "" : kindText.trim().toUpperCase(Locale.ROOT));
            } catch (RuntimeException invalid) {
                throw new IllegalArgumentException("Unknown target-initiated check kind");
            }
            // An unsolicited SSO check applies to browser SSO, and to single logout where the
            // propagation harness establishes extra Suite participants through the target's
            // unsolicited SSO profile before the target-initiated logout.
            var supported = kind == com.samlscope.runner.TargetInitiatedIntents.Kind.UNSOLICITED_SSO
                    ? plan.profile() == com.samlscope.core.profile.FunctionalProfile.BROWSER_SSO_IDP
                            || plan.profile() == com.samlscope.core.profile.FunctionalProfile.SINGLE_LOGOUT_IDP
                    : plan.profile() == com.samlscope.core.profile.FunctionalProfile.SINGLE_LOGOUT_IDP;
            if (!supported) throw new IllegalArgumentException(
                    "The target-initiated check does not apply to this profile");
            var intent = targetInitiated.prepare(run.id(), plan.id(), kind, java.time.Duration.ofMinutes(30), clock);
            return new TargetInitiatedView(run.id(), intent.kind().name(), intent.expiresAt().toString());
        });
    }

    record SupplementalKeyView(String targetEntityId, String metadataSha256, boolean testsStarted,
            com.samlscope.core.caseexec.SupplementalDecryptionKeys input) {}

    SupplementalKeyView supplementalKeys(String runId) {
        var scope = supplementalKeyScopes.apply(runId);
        return new SupplementalKeyView(scope.targetEntityId(), scope.metadataSha256(), scope.testsStarted(),
                supplementalKeys.inspect(runId).orElse(null));
    }

    com.samlscope.core.caseexec.SupplementalDecryptionKeys submitSupplementalKeys(String runId,
            com.samlscope.runner.SupplementalDecryptionKeyService.Submission submission) {
        return withManualEvidenceWork(runId, () -> supplementalKeys.submit(runId, submission));
    }

    private void freezeSupplementalKeys(TestRun run, com.samlscope.core.plan.TestPlan plan) {
        if (plan.profile() == com.samlscope.core.profile.FunctionalProfile.SINGLE_LOGOUT_IDP) {
            supplementalKeys.freeze(run.id());
        }
    }

    record TestStartResult(boolean ecpProbesRequired) {}

    TestStartResult startTests(String runId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var run = requireRun(runId);
            var plan = requirePlan(run);
            if (run.status() != com.samlscope.core.run.RunStatus.COMPLETED) {
                throw new IllegalArgumentException("Complete the initial login before starting the profile tests");
            }
            freezeSupplementalKeys(run, plan);
            quickCheck.executeApplicable(runId, profileDefinitions.require(plan.definitionIdentity()).coverage(), applicability);
            boolean ecpProbesRequired = plan.profile() == com.samlscope.core.profile.FunctionalProfile.ECP_IDP
                    && !com.samlscope.runner.outbox.EcpProbeService.allRequiredFixturesSent(caseExecutions, runId);
            for (var milestone : com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.values()) {
                if (ecpProbesRequired
                        && milestone == com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3) continue;
                startInteractive(run, plan, milestone);
            }
            reconcileTranscriptEvidenceNow(runId);
            if (results != null) results.generate(runId);
            return new TestStartResult(ecpProbesRequired);
        });
    }

    QuickCheckService.QuickCheckResult quickCheck(String runId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var run = requireRun(runId);
            var plan = requirePlan(run);
            freezeSupplementalKeys(run, plan);
            var value = quickCheck.executeApplicable(runId, profileDefinitions.require(plan.definitionIdentity()).coverage(), applicability);
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
        var run = requireRun(runId);
        if (!usesActiveDefinition(runId)) return;
        var expiredProbe = activeProbes.expireReady(runId);
        var expired = timeouts.expireReady(runId, caseContext(runId));
        metadataFetches.collect(runId);
        var evaluation = protocolEvidence.evaluateReady(runId);
        if ((expiredProbe.isPresent() || !expired.isEmpty() || !evaluation.completed().isEmpty())
                && results != null) {
            results.generate(runId);
        }
    }

    ActiveProbeCoordinator.Status activeProbeStatus(String runId) {
        if (!usesActiveDefinition(runId)) {
            requireTranscriptEvidenceComplete(runId);
            return storedView(runId).activeStatus(requireRun(runId).planId(), "Stored historical state; use an available definition for new automatic checks.");
        }
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return activeProbes.status(runId);
        });
    }

    /** Public probe routes need only the coordinator state; Transcript automation runs separately. */
    ActiveProbeCoordinator.Status activeProbeRouteStatus(String runId) {
        requireRun(runId);
        if (!usesActiveDefinition(runId)) return storedView(runId).activeStatus(requireRun(runId).planId(), "Stored historical state; use an available definition for new automatic checks.");
        var expired = activeProbes.expireReady(runId);
        if (expired.isPresent() && results != null) results.generate(runId);
        return activeProbes.status(runId);
    }

    ActiveProbeCoordinator.PreparedProbe prepareActiveProbe(
            String runId, String actionId, boolean freshSessionConfirmed) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return activeProbes.prepare(runId, actionId, freshSessionConfirmed);
    }

    ActiveProbeCoordinator.Status acceptActiveProbe(
            String runId,
            String actionId,
            byte[] decodedSaml,
            com.samlscope.core.evaluation.EvidenceRef evidence) {
        requireRunDefinition(runId);
        var status = activeProbes.accept(runId, actionId, decodedSaml, evidence);
        return publishActiveProbeResponse(runId, actionId, status);
    }

    ActiveProbeCoordinator.Status acceptActiveSloProbe(String runId, String actionId, byte[] decodedSaml,
            com.samlscope.core.evaluation.EvidenceRef evidence) {
        requireRunDefinition(runId);
        return publishActiveProbeResponse(runId, actionId, activeProbes.acceptLogout(runId, actionId, decodedSaml, evidence));
    }

    private ActiveProbeCoordinator.Status publishActiveProbeResponse(String runId, String actionId,
            ActiveProbeCoordinator.Status status) {
        if (results != null && profileDefinitions.find(requirePlan(requireRun(runId)).definitionIdentity()).isPresent()) {
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
        requireRunDefinition(runId);
        requireRun(runId);
        var status = activeProbes.abort(runId);
        if (results != null) results.generate(runId);
        return status;
    }

    com.samlscope.core.transcript.TranscriptEntry recordBrowserObservation(
            String runId, com.samlscope.api.ApiModels.BrowserObservation observation) {
        requireRun(runId);
        return activeProbes.recordBrowserObservation(
                runId, null, observation.status(), observation.url(), observation.body(), null);
    }

    int concludeTargetInitiated(String runId) {
        requireRun(runId);
        var concluded = activeProbes.concludeTargetInitiatedCampaign(runId);
        if (concluded > 0 && results != null) results.generate(runId);
        return concluded;
    }

    ActiveProbeCoordinator.Status reportActiveProbeBrowserResponse(
            String runId, com.samlscope.api.ApiModels.BrowserResponse response) {
        requireRunDefinition(runId);
        requireRun(runId);
        var status = activeProbes.reportBrowserResponse(
                runId, response.actionId(), response.status(), response.url(), response.body());
        return publishActiveProbeResponse(runId, response.actionId(), status);
    }

    ActiveProbeCoordinator.Status retryActiveProbe(String runId) {
        requireRunDefinition(runId);
        requireRun(runId);
        return activeProbes.retry(runId);
    }

    record WorkspaceEvidence(
            java.util.List<com.samlscope.runner.InteractionQuery.PendingInteraction> interactions,
            java.util.List<com.samlscope.runner.BootstrapContractQuery.BootstrapContract> bootstrapContracts,
            com.samlscope.runner.ProtocolEvidenceAutomationService.Status protocolEvidence,
            ActiveProbeCoordinator.Status activeProbe,
            com.samlscope.runner.RunCampaignQuery.CampaignReport campaigns,
            com.samlscope.runner.HistoricalRunReadPolicy.Availability definitionAvailability,
            com.samlscope.runner.HistoricalStoredRunView storedHistoricalState) {}

    WorkspaceEvidence workspaceEvidence(String runId) {
        if (!usesActiveDefinition(runId)) {
            requireTranscriptEvidenceComplete(runId);
            var stored = storedView(runId);
            return new WorkspaceEvidence(List.of(), List.of(),
                    new com.samlscope.runner.ProtocolEvidenceAutomationService.Status(0,0,List.of()),
                    stored.activeStatus(requireRun(runId).planId(), "Stored historical state; no automatic dispatch from this view."),
                    null, definitionAvailability(runId), stored);
        }
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return new WorkspaceEvidence(pendingInteractions.pending(runId),
                    bootstrapContracts.contracts(runId), protocolEvidence.status(runId),
                    activeProbes.status(runId), campaigns.report(runId), definitionAvailability(runId), null);
        });
    }

    java.util.List<com.samlscope.runner.InteractionQuery.PendingInteraction> pending(String runId) {
        if (!usesActiveDefinition(runId)) { requireTranscriptEvidenceComplete(runId); return List.of(); }
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return pendingInteractions.pending(runId);
        });
    }

    com.samlscope.runner.RunCampaignQuery.CampaignReport campaigns(String runId) {
        if (!usesActiveDefinition(runId)) { requireTranscriptEvidenceComplete(runId); requireRunDefinition(runId); return null; }
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return campaigns.report(runId);
        });
    }

    java.util.List<com.samlscope.runner.BootstrapContractQuery.BootstrapContract> bootstrapContracts(String runId) {
        if (!usesActiveDefinition(runId)) { requireTranscriptEvidenceComplete(runId); return List.of(); }
        return withManualEvidenceWork(runId, () -> bootstrapContracts.contracts(runId));
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Status protocolEvidence(String runId) {
        if (!usesActiveDefinition(runId)) { requireTranscriptEvidenceComplete(runId); return new com.samlscope.runner.ProtocolEvidenceAutomationService.Status(0,0,List.of()); }
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            return protocolEvidence.status(runId);
        });
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Evaluation evaluateProtocolEvidence(String runId, byte[] sharedKey) {
        try {
            historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
            return withManualEvidenceWork(runId, () -> {
                requireRun(runId);
                return runDecryptionKeys.evaluate(runId, sharedKey, () -> {
                    metadataFetches.collect(runId);
                    var value = protocolEvidence.evaluateReady(runId);
                    if (results != null) results.generate(runId);
                    return value;
                });
            });
        } finally { if (sharedKey != null) java.util.Arrays.fill(sharedKey, (byte) 0); }
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Evaluation evaluateProtocolEvidence(String runId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            metadataFetches.collect(runId);
            var value = protocolEvidence.evaluateReady(runId);
            if (results != null) results.generate(runId);
            return value;
        });
    }

    com.samlscope.runner.ProtocolEvidenceAutomationService.Evaluation confirmProtocolEvidenceAttempts(
            String runId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var value = protocolEvidence.evaluateAttempted(runId);
            if (results != null) results.generate(runId);
            return value;
        });
    }

    com.samlscope.runner.AttestationExecutor.Result attest(
            String runId, String caseId, String value, String note) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var result = attestations.attest(runId, caseId, value, note);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.ConfigurationExecutor.Result configure(
            String runId, String caseId, String value, String note) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var result = configurations.answer(runId, caseId, value, note);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.BrowserCompletionExecutor.Result completeBrowser(String runId, String caseId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var result = browserCompletions.complete(runId, caseId);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    com.samlscope.runner.CampaignActionCompletionService.Result completeCampaignAction(
            String runId, String campaignId, String actionId) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var result = campaignActions.complete(runId, campaignId, actionId);
            if (results != null) results.generate(runId);
            return result;
        });
    }

    java.util.List<com.samlscope.core.caseexec.CaseExecution> startMilestone(
            String runId, String milestoneName) {
        historicalReads.requireExecution(requirePlan(requireRun(runId)).definitionIdentity());
        return withManualEvidenceWork(runId, () -> {
            var milestone = parseMilestone(milestoneName);
            var run = requireRun(runId);
            var plan = requirePlan(run);
            if (milestone == com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone.M3
                    && plan.profile() == com.samlscope.core.profile.FunctionalProfile.ECP_IDP
                    && !com.samlscope.runner.outbox.EcpProbeService.allRequiredFixturesSent(
                            caseExecutions, run.id())) {
                throw new IllegalArgumentException(
                        "Run the ECP probes before continuing the ECP tests");
            }
            var started = startInteractive(run, plan, milestone);
            reconcileTranscriptEvidenceNow(runId);
            if (results != null) results.generate(runId);
            return started;
        });
    }

    byte[] requireResult(String runId) {
        var run = requireRun(runId);
        if (config.mode() == AppConfig.Mode.HOSTED) requireTranscriptEvidenceComplete(runId);
        return historicalReads.readForRuntime(requirePlan(run).definitionIdentity(), () -> artifacts.findResult(runId),
                () -> currentResult(runId), () -> historicalResult(runId));
    }

    private byte[] historicalResult(String runId) {
        if (results == null) throw new IllegalArgumentException("Result generation requires SAMLSCOPE_IMAGE_DIGEST");
        historicalReads.requireEvaluation(requirePlan(requireRun(runId)).definitionIdentity());
        return results.requireHistoricalResult(runId); // Existing partner is preserved; pure owning publication only if both absent.
    }

    private byte[] historicalReport(String runId) {
        if (results == null) throw new IllegalArgumentException("Report generation requires SAMLSCOPE_IMAGE_DIGEST");
        historicalReads.requireEvaluation(requirePlan(requireRun(runId)).definitionIdentity());
        return results.requireHistoricalReport(runId); // Wrap exact cached JSON without store or re-evaluation.
    }

    private byte[] currentResult(String runId) {
        if (config.mode() != AppConfig.Mode.HOSTED) reconcileTranscriptEvidenceNow(runId);
        return artifacts.findResult(runId).orElseThrow(() -> new IllegalArgumentException(
                results == null ? "Result generation requires SAMLSCOPE_IMAGE_DIGEST" : "Result artifact has not been generated"));
    }

    byte[] requireReport(String runId) {
        var run = requireRun(runId);
        if (config.mode() == AppConfig.Mode.HOSTED) requireTranscriptEvidenceComplete(runId);
        return historicalReads.readForRuntime(requirePlan(run).definitionIdentity(), () -> artifacts.findReport(runId),
                () -> currentReport(runId), () -> historicalReport(runId));
    }

    private byte[] currentReport(String runId) {
        if (results == null) throw new IllegalArgumentException("Report generation requires SAMLSCOPE_IMAGE_DIGEST");
        if (config.mode() != AppConfig.Mode.HOSTED) reconcileTranscriptEvidenceNow(runId);
        return results.requireReport(runId);
    }

    com.samlscope.runner.HistoricalRunReadPolicy.Availability definitionAvailability(String runId) {
        return historicalReads.availability(requirePlan(requireRun(runId)).definitionIdentity());
    }

    void requirePlanDefinition(com.samlscope.core.plan.TestPlan plan) { historicalReads.requireExecution(plan.definitionIdentity()); }
    void requireRunDefinition(String runId) { requirePlanDefinition(requirePlan(requireRun(runId))); }
    private boolean usesActiveDefinition(String runId) {
        return profileDefinitions.find(requirePlan(requireRun(runId)).definitionIdentity())
                .map(release -> release.kind() == com.samlscope.runner.FunctionalReleaseContext.Kind.CURRENT).orElse(false);
    }
    private com.samlscope.runner.HistoricalStoredRunView storedView(String runId) {
        return com.samlscope.runner.HistoricalStoredRunView.from(runId,caseExecutions.list(runId));
    }

    PublicationRoutes.Published publish(String runId) {
        historicalReads.requireEvaluation(requirePlan(requireRun(runId)).definitionIdentity());
        if (config.mode() != AppConfig.Mode.HOSTED || !config.publishEnabled()) {
            throw new IllegalArgumentException("Hosted publication is disabled; export report.html locally instead");
        }
        requireRun(runId);
        if (results == null) throw new IllegalArgumentException("Publication requires SAMLSCOPE_IMAGE_DIGEST");
        return withManualEvidenceWork(runId, () -> {
            reconcileTranscriptEvidenceNow(runId);
            if (usesActiveDefinition(runId)) results.generate(runId);
            else historicalResult(runId);
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

    private static byte[] resource(String path) {
        try (var stream = M1Runtime.class.getResourceAsStream(path)) {
            if (stream == null) throw new IllegalStateException("Missing distribution notice: " + path);
            return stream.readAllBytes();
        } catch (java.io.IOException error) {
            throw new IllegalStateException("Could not read distribution notice: " + path, error);
        }
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

    URI workspaceUrl(String runId) {
        return config.publicBaseUrl().resolve("/manage/" + requireRun(runId).id());
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
            throw new IllegalArgumentException("Complete the initial login before starting the profile tests");
        }
        freezeSupplementalKeys(run, plan);
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
