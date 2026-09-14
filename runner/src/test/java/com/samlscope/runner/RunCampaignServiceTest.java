package com.samlscope.runner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.ConfigurationFailureSemantics;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.RunCampaignQuery.EvidenceClass;
import com.samlscope.runner.RunCampaignQuery.Plan;
import com.samlscope.runner.cases.AttestationOption;
import com.samlscope.runner.cases.AttestedOutcomeTestCase;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

class RunCampaignServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-31T00:00:00Z");

    @Test
    void supplementalMetadataActionsShareWorkWithoutDuplicatingConformanceCases() {
        var extension = definition("IIP-EXT01-c-idp-01", "IIP-EXT01.c", ExecutionMode.BROWSER, "none");
        var metadata = definition("metadata-case", "IIP-MD05.a3", ExecutionMode.CONFIG, "none");
        var implementation = new com.samlscope.runner.cases.IdpExecutableBrowserFixtureScenarioTestCase(
                extension.id(), ignored -> null);
        var report = service(List.of(extension, metadata), List.of(implementation,
                new CampaignProtocolCase(metadata.id(), List.of("control"))),
                List.of(execution(extension.id(), false), execution(metadata.id(), false))).report("run");
        assertEquals(2, report.cases());
        assertEquals(2, report.classifications().size());
        assertTrue(report.classifications().stream().allMatch(value -> value.plan() == Plan.STANDARD),
                "A required metadata operation must not disappear from a QUICK plan budget");
        assertEquals(2, report.campaigns().size());
        var campaign = report.campaigns().stream()
                .filter(value -> value.actionKind() == RunCampaignQuery.ActionKind.METADATA_REFRESH).findFirst().orElseThrow();
        assertEquals(14, campaign.deliberateUserActions(), "one shared control plus the schema-derived metadata matrix");
        assertEquals(2, campaign.caseIds().size());
        assertEquals(2, report.casesByEvidenceClass().values().stream().mapToInt(Integer::intValue).sum());
    }

    @Test
    void sharesOneMetadataRefreshActionAcrossMultipleCases() {
        var first = definition("IIP-MD04-a-idp-01", "IIP-MD04.a", ExecutionMode.CONFIG, "none");
        var second = definition("IIP-MD05-a-idp-01", "IIP-MD05.a", ExecutionMode.CONFIG, "none");
        var firstCase = new ProtocolCase(first.id());
        var secondCase = new ProtocolCase(second.id());
        var report = service(
                List.of(first, second), List.of(firstCase, secondCase),
                List.of(execution(first.id(), false), execution(second.id(), false))).report("run");

        var campaign = report.campaigns().get(0);
        assertEquals("operator_assisted-metadata_refresh-shared-metadata-refresh", campaign.id());
        assertEquals(2, campaign.caseIds().size());
        assertEquals(1, campaign.deliberateUserActions());
        assertEquals(1, campaign.remainingUserActions());
        assertEquals(2, report.casesByEvidenceClass().get(EvidenceClass.OPERATOR_ASSISTED));
    }

    @Test
    void countsTheUnionOfMetadataFixtureOperationsRatherThanCases() {
        var first = definition("first", "IIP-MD03.a", ExecutionMode.CONFIG, "none");
        var second = definition("second", "IIP-MD03.b", ExecutionMode.CONFIG, "none");
        var report = service(
                List.of(first, second),
                List.of(
                        new CampaignProtocolCase(first.id(), List.of("control", "unsigned", "bad-signature")),
                        new CampaignProtocolCase(second.id(), List.of("control", "bad-signature", "other-key"))),
                List.of(execution(first.id(), false), execution(second.id(), false))).report("run");

        var campaign = report.campaigns().get(0);
        assertEquals(4, campaign.deliberateUserActions());
        assertEquals(4, campaign.remainingUserActions());
    }

    @Test
    void preloadedAggregateCountsOneImportAndOneBrowserStartInsteadOfPerFixtureActions() {
        var first = definition("first", "IIP-MD05.a3", ExecutionMode.CONFIG, "none");
        var second = definition("second", "IIP-MD12.d", ExecutionMode.CONFIG, "none");
        var service = new RunCampaignService(
                new MemoryExecutions(List.of(execution(first.id(), false), execution(second.id(), false))),
                new CaseDefinitionCatalog(List.of(first, second)),
                new TestCaseRegistry(List.of(
                        new CampaignProtocolCase(first.id(), List.of(
                                "control", "unknown-extension", "unknown-role-extension")),
                        new CampaignProtocolCase(second.id(), List.of(
                                "control", "certificate-expired", "certificate-sha1")))),
                ignored -> context(), ignored -> preloadedLabState());

        var campaign = service.report("run").campaigns().getFirst();
        assertEquals(3, campaign.deliberateUserActions(),
                "control stays separate; four compatible fixtures become one import plus one start");
    }

    @Test
    void automaticPollingCountsOneCampaignStartInsteadOfPerFixtureRefreshes() {
        var first = definition("first", "IIP-MD05.a3", ExecutionMode.CONFIG, "none");
        var second = definition("second", "IIP-MD12.d", ExecutionMode.CONFIG, "none");
        var variants = List.of("control", "unknown-extension", "certificate-expired", "certificate-sha1");
        var service = new RunCampaignService(
                new MemoryExecutions(List.of(execution(first.id(), false), execution(second.id(), false))),
                new CaseDefinitionCatalog(List.of(first, second)),
                new TestCaseRegistry(List.of(
                        new CampaignProtocolCase(first.id(), variants.subList(0, 2)),
                        new CampaignProtocolCase(second.id(), variants.subList(2, 4)))),
                ignored -> context(), ignored -> automaticLabState(variants));

        assertEquals(1, service.report("run").campaigns().getFirst().deliberateUserActions());
    }

    @Test
    void automaticPollingAddsOnlyTheContinuationsActuallyRequiredByTheTarget() {
        var definition = definition("first", "IIP-MD05.a3", ExecutionMode.CONFIG, "none");
        var variants = List.of("control", "unknown-extension", "bad-signature");
        var service = new RunCampaignService(
                new MemoryExecutions(List.of(execution(definition.id(), false))),
                new CaseDefinitionCatalog(List.of(definition)),
                new TestCaseRegistry(List.of(new CampaignProtocolCase(definition.id(), variants))),
                ignored -> context(), ignored -> automaticLabState(variants, 2));

        assertEquals(3, service.report("run").campaigns().getFirst().deliberateUserActions(),
                "one start plus two observed Target-result continuations");
    }

    @Test
    void keepsFreshSessionBoundaryAndDoesNotTurnMissingEvidenceIntoAnOutcome() {
        var definition = definition(
                "IIP-IDP05-a-idp-01", "IIP-IDP05.a", ExecutionMode.BROWSER, "required");
        var testCase = new ProtocolCase(definition.id());
        var execution = execution(definition.id(), false);
        var report = service(List.of(definition), List.of(testCase), List.of(execution)).report("run");

        assertTrue(report.campaigns().get(0).freshSessionRequired());
        assertEquals(List.of("correlated-saml-response"),
                report.campaigns().get(0).expectedTranscriptEvidence());
        assertEquals(1, report.notVerifiedCases());
        assertEquals(CaseExecutionStatus.RUNNING, execution.status());
        assertEquals(null, execution.outcome());
    }

    @Test
    void reportsSelfAttestationSeparatelyAndKeepsAllPlanBudgetsBounded() {
        var automatic = definition("IIP-G03-a-idp-01", "IIP-G03.a", ExecutionMode.AUTOMATED, "none");
        var browser = definition("IIP-IDP04-a-idp-01", "IIP-IDP04.a", ExecutionMode.BROWSER, "none");
        var attested = definition("IIP-G02-c-idp-01", "IIP-G02.c", ExecutionMode.ATTESTED, "none");
        var report = service(
                List.of(automatic, browser, attested),
                List.of(
                        passive(automatic.id()), passive(browser.id()),
                        new AttestedOutcomeTestCase(
                                attested.id(), TargetRole.IDP, "attestation", "Review evidence.",
                                java.time.Duration.ofHours(1),
                                List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "ok")))),
                List.of(execution(automatic.id(), true), execution(browser.id(), false), execution(attested.id(), true)))
                .report("run");

        assertEquals(1, report.externallyVerifiedCases());
        assertEquals(1, report.selfAttestedCases());
        assertEquals(1, report.notVerifiedCases());
        assertEquals(List.of(Plan.QUICK, Plan.STANDARD, Plan.FULL),
                report.plans().stream().map(RunCampaignQuery.PlanSummary::plan).toList());
        assertTrue(report.plans().stream().allMatch(RunCampaignQuery.PlanSummary::budgetMet));
        assertEquals(1, report.plans().get(2).selfAttestationSections());
        assertFalse(report.campaigns().stream()
                .filter(value -> value.evidenceClass() == EvidenceClass.SELF_ATTESTED)
                .findFirst().orElseThrow().caseIds().isEmpty());
    }

    @Test
    void classifiesFinishedAutomatedExecutionsWithoutAnInteractiveRegistryEntry() {
        var automatic = definition("IIP-G03-a-idp-01", "IIP-G03.a", ExecutionMode.AUTOMATED, "none");
        var report = service(
                List.of(automatic), List.of(), List.of(execution(automatic.id(), true))).report("run");

        assertEquals(1, report.externallyVerifiedCases());
        assertEquals(EvidenceClass.PROTOCOL_OBSERVED, report.classifications().get(0).evidenceClass());
        assertEquals("SATISFIED", report.classifications().get(0).outcome());
        assertEquals(0, report.plans().get(0).deliberateUserActions());
    }

    @Test
    void groupsTheAutomaticallyChainedActiveProbeAndKeepsFreshSessionBoundary() {
        var first = definition("IIP-IDP05-a-idp-01", "IIP-IDP05.a", ExecutionMode.BROWSER, "required");
        var second = definition("IIP-IDP07-a-idp-01", "IIP-IDP07.a", ExecutionMode.BROWSER, "required");
        var report = service(
                List.of(first, second),
                List.of(new BrowserScenarioCase(first.id()), new BrowserScenarioCase(second.id())),
                List.of(execution(first.id(), false), execution(second.id(), false))).report("run");

        var campaign = report.campaigns().get(0);
        assertEquals(EvidenceClass.PROTOCOL_OBSERVED, campaign.evidenceClass());
        assertEquals("protocol_observed-login-shared-active-probe-chain", campaign.id());
        assertEquals(2, campaign.deliberateUserActions(),
                "one shared probe start plus one shared recovery after a fresh-session boundary");
        assertEquals(2, campaign.remainingUserActions());
        assertTrue(campaign.freshSessionRequired());
    }

    @Test
    void sharesLoginCheckpointsAcrossScenariosAndCountsOneFreshSessionRecovery() {
        var first = definition("first", "IIP-IDP05.a", ExecutionMode.BROWSER, "none");
        var second = definition("second", "IIP-IDP06.a", ExecutionMode.BROWSER, "none");
        var third = definition("third", "IIP-IDP07.a", ExecutionMode.BROWSER, "none");
        var report = service(
                List.of(first, second, third),
                List.of(
                        new BrowserScenarioCase(first.id(), 1, true),
                        new BrowserScenarioCase(second.id(), 2, false),
                        new BrowserScenarioCase(third.id(), 1, true)),
                List.of(execution(first.id(), false), execution(second.id(), false),
                        execution(third.id(), false))).report("run");

        var campaign = report.campaigns().getFirst();
        assertEquals(3, campaign.deliberateUserActions(),
                "shared session, forced reauthentication, and one shared post-fresh recovery");
        assertEquals(List.of(
                        "active-probe-login-1", "active-probe-login-after-fresh-session",
                        "active-probe-login-2"),
                campaign.actions().stream().map(RunCampaignQuery.CampaignAction::id).toList());
        assertEquals(3, campaign.actions().get(0).caseIds().size());
        assertEquals(2, campaign.actions().get(1).caseIds().size());
    }

    @Test
    void countsSharedCryptographicPolicyFamiliesInsteadOfCases() {
        var block128 = definition("block128", "IIP-ALG04.a", ExecutionMode.BROWSER, "none");
        var block256 = definition("block256", "IIP-ALG04.b", ExecutionMode.BROWSER, "none");
        var transport = definition("transport", "IIP-ALG06.a", ExecutionMode.BROWSER, "none");
        var report = service(
                List.of(block128, block256, transport),
                List.of(
                        new PolicyCampaignCase(block128.id(), "content-encryption-policy"),
                        new PolicyCampaignCase(block256.id(), "content-encryption-policy"),
                        new PolicyCampaignCase(transport.id(), "key-transport-policy")),
                List.of(execution(block128.id(), false), execution(block256.id(), false),
                        execution(transport.id(), false))).report("run");

        var campaign = report.campaigns().getFirst();
        assertEquals(EvidenceClass.OPERATOR_ASSISTED, campaign.evidenceClass());
        assertEquals(2, campaign.deliberateUserActions());
        assertEquals(2, report.plans().get(1).configurationActions());
        assertEquals(List.of("content-encryption-policy", "key-transport-policy"),
                campaign.actions().stream().map(RunCampaignQuery.CampaignAction::id).toList());
        assertEquals(List.of("block128", "block256"), campaign.actions().getFirst().caseIds());
    }

    @Test
    void classifiesAutomaticFastPathOnlyWhenExternalEvidenceActuallyResolvedFallbackCase() {
        var definition = definition(
                "IIP-MD09-a-idp-01", "IIP-MD09.a", ExecutionMode.ATTESTED, "none");
        var fallbackCase = new ConditionalCampaignCase(definition.id());

        var pending = service(
                List.of(definition), List.of(fallbackCase), List.of(execution(definition.id(), false)))
                .report("run");
        assertEquals(EvidenceClass.SELF_ATTESTED, pending.classifications().getFirst().evidenceClass());

        var externalExecution = finishedExecution(
                definition.id(), new EvidenceRef("target-metadata", "sha256:" + "1".repeat(64)));
        var external = service(
                List.of(definition), List.of(fallbackCase), List.of(externalExecution)).report("run");
        assertEquals(EvidenceClass.PROTOCOL_OBSERVED, external.classifications().getFirst().evidenceClass());
        assertEquals(1, external.externallyVerifiedCases());
        assertEquals(0, external.selfAttestedCases());

        var attestedExecution = finishedExecution(
                definition.id(), new EvidenceRef("attestation", "attestation:run:" + definition.id()));
        var attested = service(
                List.of(definition), List.of(fallbackCase), List.of(attestedExecution)).report("run");
        assertEquals(EvidenceClass.SELF_ATTESTED, attested.classifications().getFirst().evidenceClass());
        assertEquals(1, attested.selfAttestedCases());
    }

    private RunCampaignService service(
            List<CaseDefinition> definitions, List<TestCase> cases, List<CaseExecution> executions) {
        return new RunCampaignService(
                new MemoryExecutions(executions), new CaseDefinitionCatalog(definitions),
                new TestCaseRegistry(cases), ignored -> context());
    }

    private CaseDefinition definition(String id, String obligation, ExecutionMode mode, String session) {
        return new CaseDefinition(
                id, obligation, TargetRole.IDP, mode, Milestone.M1,
                List.of(), Map.of(), List.of(), List.of(), List.of(), "counterexample",
                List.of(), new CaseDefinitionCatalog.Requirements(List.of(), session), false,
                mode == ExecutionMode.CONFIG ? ConfigurationFailureSemantics.TEST_PRECONDITION : null,
                "sha256:" + "0".repeat(64));
    }

    private CaseExecution execution(String id, boolean finished) {
        return new CaseExecution(
                "run", id, 0, finished ? CaseExecutionStatus.FINISHED : CaseExecutionStatus.RUNNING,
                CaseState.initial(), null,
                finished ? CaseOutcome.of(Outcome.SATISFIED, "observed", List.of()) : null, NOW);
    }

    private CaseExecution finishedExecution(String id, EvidenceRef evidence) {
        return new CaseExecution(
                "run", id, 0, CaseExecutionStatus.FINISHED, CaseState.initial(), null,
                CaseOutcome.of(Outcome.SATISFIED, "observed", List.of(evidence)), NOW);
    }

    private TestCase passive(String id) {
        return new TestCase() {
            @Override public String id() { return id; }
            @Override public TargetRole role() { return TargetRole.IDP; }
            @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
            @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
                throw new UnsupportedOperationException();
            }
        };
    }

    private CaseContext context() {
        return new CaseContext() {
            @Override public String runId() { return "run"; }
            @Override public TargetRole targetRole() { return TargetRole.IDP; }
            @Override public Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
            @Override public com.samlscope.core.plan.TestPlan.Parameters parameters() {
                return com.samlscope.core.plan.TestPlan.Parameters.defaults();
            }
            @Override public com.samlscope.core.plan.TestPlan.Interaction interaction() {
                return com.samlscope.core.plan.TestPlan.Interaction.defaults();
            }
            @Override public com.samlscope.core.run.Reachability reachability() {
                return com.samlscope.core.run.Reachability.CONFIRMED;
            }
            @Override public com.samlscope.core.transcript.TranscriptRecorder transcript() {
                return new com.samlscope.core.transcript.TranscriptRecorder() {
                    public com.samlscope.core.transcript.TranscriptEntry record(com.samlscope.core.transcript.TranscriptInput input) { throw new UnsupportedOperationException(); }
                    public com.samlscope.core.transcript.TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) { throw new UnsupportedOperationException(); }
                    public List<com.samlscope.core.transcript.TranscriptEntry> list(String runId) { return List.of(); }
                };
            }
            @Override public boolean transcriptComplete() { return true; }
        };
    }

    private static final class ProtocolCase implements TestCase, ProtocolEvidenceCase {
        private final String id;
        private ProtocolCase(String id) { this.id = id; }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(
                    false, List.of("correlated-saml-response"), List.of(), Map.of());
        }
    }

    private static final class BrowserScenarioCase
            implements TestCase, BrowserFrontChannelScenario, com.samlscope.runner.cases.BrowserPrompt {
        private final String id;
        private final int actions;
        private final boolean fresh;
        private BrowserScenarioCase(String id) { this(id, 0, true); }
        private BrowserScenarioCase(String id, int actions, boolean fresh) {
            this.id = id;
            this.actions = actions;
            this.fresh = fresh;
        }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String browserInstructionsEn() { return "Complete the scenario."; }
        @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }
        @Override public boolean requiresFreshSession(CaseState state) { return fresh; }
        @Override public boolean plansFreshSessionBoundary() { return fresh; }
        @Override public int plannedDeliberateActions() { return actions; }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class PolicyCampaignCase
            implements TestCase, EvidenceCampaignCase, OperatorAssistedCase {
        private final String id;
        private final String actionKey;
        private PolicyCampaignCase(String id, String actionKey) {
            this.id = id;
            this.actionKey = actionKey;
        }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String evidenceCampaignId() { return "crypto-policy"; }
        @Override public String evidenceCampaignTitle() { return "Cryptographic algorithm policy"; }
        @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
            return RunCampaignQuery.ActionKind.CONFIGURATION;
        }
        @Override public List<String> evidenceActionKeys() { return List.of(actionKey); }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
    }

    private static final class CampaignProtocolCase
            implements TestCase, ProtocolEvidenceCase, EvidenceCampaignCase {
        private final String id;
        private final List<String> actionKeys;
        private CampaignProtocolCase(String id, List<String> actionKeys) {
            this.id = id;
            this.actionKeys = actionKeys;
        }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
        @Override public String evidenceCampaignTitle() { return "Refresh metadata fixtures"; }
        @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
            return RunCampaignQuery.ActionKind.METADATA_REFRESH;
        }
        @Override public List<String> evidenceActionKeys() { return actionKeys; }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
        @Override public EvidenceStatus evidenceStatus(CaseContext context) {
            return new EvidenceStatus(false,
                    actionKeys.stream().map(value -> "fetched:" + value).toList(),
                    List.of(), Map.of());
        }
    }

    private MetadataLabService.State preloadedLabState() {
        var variants = com.samlscope.saml.metadata.MetadataService.preloadedCampaignVariants().stream()
                .map(com.samlscope.saml.metadata.MetadataService.Variant::id).toList();
        return new MetadataLabService.State(
                "run", "plan", "control", java.net.URI.create("https://suite.example/live"),
                List.of("control"), MetadataLabService.IngestionMode.PRELOADED_AGGREGATE,
                variants, 0, false, 15, 0, null, null, java.net.URI.create("https://suite.example/preloaded"),
                java.net.URI.create("https://suite.example/preloaded/download"),
                java.net.URI.create("https://suite.example/start"), variants, false);
    }

    private MetadataLabService.State automaticLabState(List<String> variants) {
        return automaticLabState(variants, 0);
    }

    private MetadataLabService.State automaticLabState(List<String> variants, int continuations) {
        return new MetadataLabService.State(
                "run", "plan", variants.getFirst(), java.net.URI.create("https://suite.example/live"),
                variants, MetadataLabService.IngestionMode.AUTOMATIC_POLLING,
                variants, 0, false, 15, continuations,
                java.net.URI.create("https://suite.example/polling-start"),
                null, null, null, null, List.of(), false);
    }

    private static final class ConditionalCampaignCase
            implements TestCase, EvidenceCampaignCase, FallbackEvidenceCase,
            com.samlscope.runner.cases.AttestationPrompt {
        private final String id;
        private ConditionalCampaignCase(String id) { this.id = id; }
        @Override public String id() { return id; }
        @Override public TargetRole role() { return TargetRole.IDP; }
        @Override public String evidenceCampaignId() { return "target-metadata-inspection"; }
        @Override public String evidenceCampaignTitle() { return "Passive target metadata inspection"; }
        @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
            return RunCampaignQuery.ActionKind.NONE;
        }
        @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
            return execution.outcome() != null && execution.outcome().evidence().stream()
                    .anyMatch(value -> "target-metadata".equals(value.kind()));
        }
        @Override public String promptEn() { return "Review evidence."; }
        @Override public List<AttestationOption> options() {
            return List.of(AttestationOption.of("satisfied", Outcome.SATISFIED, "ok"));
        }
        @Override public CaseStep start(CaseContext context) { throw new UnsupportedOperationException(); }
        @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
            throw new UnsupportedOperationException();
        }
    }

    private record MemoryExecutions(List<CaseExecution> values) implements CaseExecutionRepository {
        @Override public Optional<CaseExecution> find(String runId, String caseId) { return Optional.empty(); }
        @Override public List<CaseExecution> list(String runId) { return values; }
        @Override public boolean apply(long expectedRevision, CaseExecution execution, List<OutboundAction> actions) {
            throw new UnsupportedOperationException();
        }
        @Override public List<OutboxEntry> listOutbox(String runId) { return List.of(); }
        @Override public Optional<OutboxEntry> findOutbox(String actionId) { return Optional.empty(); }
        @Override public boolean transitionOutbox(
                String actionId, OutboxStatus expected, OutboxStatus next, Map<String, Object> sendResult,
                String transcriptEntryId, Instant updatedAt) {
            throw new UnsupportedOperationException();
        }
        @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
    }
}
