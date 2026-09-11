package com.samlscope.runner;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.casedef.CaseDefinitionCatalog.CaseDefinition;
import com.samlscope.core.casedef.CaseDefinitionCatalog.ExecutionMode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseExecutionStatus;
import com.samlscope.runner.RunCampaignQuery.ActionKind;
import com.samlscope.runner.RunCampaignQuery.Campaign;
import com.samlscope.runner.RunCampaignQuery.CampaignAction;
import com.samlscope.runner.RunCampaignQuery.CampaignReport;
import com.samlscope.runner.RunCampaignQuery.EvidenceClass;
import com.samlscope.runner.RunCampaignQuery.Plan;
import com.samlscope.runner.RunCampaignQuery.PlanSummary;
import com.samlscope.runner.cases.AttestationPrompt;
import com.samlscope.runner.cases.ProtocolEvidenceCase;

/**
 * Groups approved cases by reusable evidence campaign. This service never completes a case and never
 * turns an operator action into a target outcome; it only describes the work needed to obtain evidence.
 */
public final class RunCampaignService implements RunCampaignQuery {
    private static final Map<Plan, Integer> ACTION_BUDGETS = Map.of(
            Plan.QUICK, 15,
            Plan.STANDARD, 35,
            Plan.FULL, 50);

    private final CaseExecutionRepository executions;
    private final CaseDefinitionCatalog definitions;
    private final TestCaseRegistry registry;
    private final CaseContextProvider contexts;
    private final java.util.function.Function<String, MetadataLabService.State> metadataLabState;

    public RunCampaignService(
            CaseExecutionRepository executions,
            CaseDefinitionCatalog definitions,
            TestCaseRegistry registry,
            CaseContextProvider contexts) {
        this(executions, definitions, registry, contexts, ignored -> null);
    }

    public RunCampaignService(
            CaseExecutionRepository executions,
            CaseDefinitionCatalog definitions,
            TestCaseRegistry registry,
            CaseContextProvider contexts,
            java.util.function.Function<String, MetadataLabService.State> metadataLabState) {
        this.executions = Objects.requireNonNull(executions, "executions");
        this.definitions = Objects.requireNonNull(definitions, "definitions");
        this.registry = Objects.requireNonNull(registry, "registry");
        this.contexts = Objects.requireNonNull(contexts, "contexts");
        this.metadataLabState = Objects.requireNonNull(metadataLabState, "metadataLabState");
    }

    @Override
    public CampaignReport report(String runId) {
        if (runId == null || runId.isBlank()) throw new IllegalArgumentException("runId must not be blank");
        var context = contexts.contextFor(runId);
        var classified = executions.list(runId).stream()
                // ECP send fixtures carry evidence, but are not approved evaluative cases.
                .filter(execution -> !com.samlscope.runner.outbox.EcpProbeService.requiredFixtureIds()
                        .contains(execution.caseId()))
                .map(execution -> classify(execution, context))
                .toList();

        var grouped = new LinkedHashMap<String, MutableCampaign>();
        for (var value : classified) {
            grouped.computeIfAbsent(value.campaignId(), ignored -> new MutableCampaign(value))
                    .add(value);
        }
        var campaigns = grouped.values().stream().map(MutableCampaign::freeze).toList();
        campaigns = optimizeMetadataActions(runId, campaigns);

        var evidenceCounts = new EnumMap<EvidenceClass, Integer>(EvidenceClass.class);
        for (var evidence : EvidenceClass.values()) evidenceCounts.put(evidence, 0);
        classified.forEach(value -> evidenceCounts.compute(
                value.evidenceClass(), (ignored, count) -> count == null ? 1 : count + 1));

        var summaries = new ArrayList<PlanSummary>();
        for (var plan : Plan.values()) summaries.add(summarize(plan, classified, campaigns));
        int externallyVerified = (int) classified.stream()
                .filter(value -> value.resolved() && value.evidenceClass() != EvidenceClass.SELF_ATTESTED)
                .count();
        int selfAttested = (int) classified.stream()
                .filter(value -> value.resolved() && value.evidenceClass() == EvidenceClass.SELF_ATTESTED)
                .count();
        int notVerified = classified.size() - externallyVerified - selfAttested;
        return new CampaignReport(
                runId, classified.size(), evidenceCounts, summaries, campaigns,
                classified.stream().map(value -> new RunCampaignQuery.CaseClassification(
                        value.caseId(), value.plan(), value.evidenceClass(), value.campaignId(),
                        value.actionKind(), value.freshSessionRequired(), value.resolved(),
                        value.outcome(), value.expectedEvidence())).toList(),
                externallyVerified, selfAttested, notVerified);
    }

    private List<Campaign> optimizeMetadataActions(String runId, List<Campaign> campaigns) {
        MetadataLabService.State lab;
        try { lab = metadataLabState.apply(runId); }
        catch (RuntimeException ignored) { return campaigns; }
        if (lab == null || (lab.ingestionMode() != MetadataLabService.IngestionMode.PRELOADED_AGGREGATE
                && lab.ingestionMode() != MetadataLabService.IngestionMode.AUTOMATIC_POLLING)) {
            return campaigns;
        }
        var batched = new LinkedHashSet<>(lab.ingestionMode()
                == MetadataLabService.IngestionMode.AUTOMATIC_POLLING
                ? lab.campaignVariants() : lab.preloadedVariants());
        return campaigns.stream().map(campaign -> {
            if (campaign.actionKind() != ActionKind.METADATA_REFRESH
                    || !campaign.id().contains("metadata-fixture-refresh")) return campaign;
            long covered = campaign.expectedTranscriptEvidence().stream()
                    .filter(value -> value.startsWith("fetched:"))
                    .map(value -> value.substring("fetched:".length()))
                    .filter(batched::contains).distinct().count();
            if (covered == 0) return campaign;
            // Automatic polling needs one explicit campaign start plus any continuations actually
            // required by Target-owned result pages. A static aggregate needs one import plus one
            // browser-sequence start. Neither path can increase the manual budget.
            var replacement = lab.ingestionMode() == MetadataLabService.IngestionMode.AUTOMATIC_POLLING
                    ? 1 + lab.operatorContinuationActions() : 2;
            var optimized = Math.min(
                    campaign.deliberateUserActions(),
                    Math.max(0, campaign.deliberateUserActions() - (int) covered + replacement));
            var remaining = Math.min(campaign.remainingUserActions(), optimized);
            return new Campaign(
                    campaign.id(), campaign.title(), campaign.plan(), campaign.evidenceClass(),
                    campaign.actionKind(), optimized, remaining, campaign.freshSessionRequired(),
                    campaign.caseIds(), campaign.remainingCaseIds(), campaign.expectedTranscriptEvidence(),
                    campaign.actions());
        }).toList();
    }

    private ClassifiedCase classify(CaseExecution execution, CaseContext context) {
        var definition = definitions.require(execution.caseId());
        var testCase = registry.find(execution.caseId()).orElse(null);
        if (testCase == null && definition.mode() != ExecutionMode.AUTOMATED) {
            throw new IllegalArgumentException("Unknown interactive case ID: " + execution.caseId());
        }
        var evidenceClass = evidenceClass(definition, testCase, execution);
        var plan = switch (evidenceClass) {
            case PROTOCOL_OBSERVED -> Plan.QUICK;
            case OPERATOR_ASSISTED -> Plan.STANDARD;
            case SELF_ATTESTED -> Plan.FULL;
        };
        var campaign = campaign(definition, testCase, evidenceClass);
        var shareableAction = evidenceClass == EvidenceClass.SELF_ATTESTED
                || testCase instanceof EvidenceCampaignCase source && source.sharesDeliberateAction()
                || testCase instanceof ProtocolEvidenceCase
                && !(testCase instanceof BrowserFrontChannelScenario);
        var actionUnits = campaign.actionKind() == ActionKind.NONE ? 0
                : testCase instanceof BrowserFrontChannelScenario scenario
                        ? scenario.plannedDeliberateActions() : 1;
        var actionKeys = new ArrayList<>(campaign.actionKind() == ActionKind.NONE ? List.<String>of()
                : testCase instanceof EvidenceCampaignCase source
                        ? source.evidenceActionKeys() : List.of(campaign.id()));
        var freshSessionRequired = testCase instanceof BrowserFrontChannelScenario browser
                ? browser.requiresFreshSession(execution.state()) || browser.plansFreshSessionBoundary()
                : "required".equals(definition.requires().session());
        if (campaign.actionKind() == ActionKind.LOGIN
                && testCase instanceof BrowserFrontChannelScenario && freshSessionRequired) {
            actionKeys.add("active-probe-login-after-fresh-session");
        }
        var campaignId = evidenceClass.name().toLowerCase(java.util.Locale.ROOT) + "-"
                + campaign.actionKind().name().toLowerCase(java.util.Locale.ROOT) + "-"
                + (shareableAction ? "shared-" : "") + campaign.id();
        var expectedEvidence = new LinkedHashSet<String>();
        if (testCase instanceof ProtocolEvidenceCase protocol) {
            expectedEvidence.addAll(protocol.evidenceStatus(context).requiredObservations());
        }
        return new ClassifiedCase(
                execution.caseId(), evidenceClass, plan, campaignId, campaign.title(),
                campaign.actionKind(),
                freshSessionRequired, shareableAction, actionUnits, List.copyOf(actionKeys),
                execution.status() == CaseExecutionStatus.FINISHED,
                execution.outcome() != null && switch (execution.outcome().outcome()) {
                    case SATISFIED, SATISFIED_WITH_NOTE, VIOLATED -> true;
                    case INDETERMINATE, INCONSISTENT, NOT_VERIFIED -> false;
                },
                execution.outcome() == null ? null : execution.outcome().outcome().name(),
                List.copyOf(expectedEvidence));
    }

    private EvidenceClass evidenceClass(
            CaseDefinition definition,
            com.samlscope.core.caseexec.TestCase testCase,
            CaseExecution execution) {
        if (definition.mode() == ExecutionMode.AUTOMATED) return EvidenceClass.PROTOCOL_OBSERVED;
        if (testCase instanceof FallbackEvidenceCase fallback) {
            return fallback.resolvedFromExternalEvidence(execution)
                    ? EvidenceClass.PROTOCOL_OBSERVED : EvidenceClass.SELF_ATTESTED;
        }
        if (testCase instanceof OperatorAssistedCase) return EvidenceClass.OPERATOR_ASSISTED;
        if (definition.mode() == ExecutionMode.CONFIG && testCase instanceof ProtocolEvidenceCase) {
            return EvidenceClass.OPERATOR_ASSISTED;
        }
        if (testCase instanceof ExternallyObservedCase) {
            return EvidenceClass.PROTOCOL_OBSERVED;
        }
        if (testCase instanceof ProtocolEvidenceCase) {
            return definition.mode() == ExecutionMode.CONFIG
                    ? EvidenceClass.OPERATOR_ASSISTED : EvidenceClass.PROTOCOL_OBSERVED;
        }
        if (definition.mode() == ExecutionMode.CONFIG
                && !(testCase instanceof com.samlscope.runner.cases.ConfigurationPrompt)) {
            return EvidenceClass.PROTOCOL_OBSERVED;
        }
        if (definition.mode() == ExecutionMode.ATTESTED && !(testCase instanceof AttestationPrompt)) {
            return EvidenceClass.PROTOCOL_OBSERVED;
        }
        if (definition.mode() == ExecutionMode.BROWSER) return EvidenceClass.OPERATOR_ASSISTED;
        if (definition.mode() == ExecutionMode.CONFIG) return EvidenceClass.SELF_ATTESTED;
        return EvidenceClass.SELF_ATTESTED;
    }

    private CampaignSeed campaign(
            CaseDefinition definition,
            com.samlscope.core.caseexec.TestCase testCase,
            EvidenceClass evidenceClass) {
        if (definition.mode() == ExecutionMode.AUTOMATED) {
            return new CampaignSeed("automatic-evaluation", "Automatic protocol and metadata evaluation", ActionKind.NONE);
        }
        if (testCase instanceof EvidenceCampaignCase source) {
            return new CampaignSeed(
                    source.evidenceCampaignId(), source.evidenceCampaignTitle(), source.evidenceActionKind());
        }
        if (evidenceClass == EvidenceClass.PROTOCOL_OBSERVED
                && !(testCase instanceof com.samlscope.runner.cases.BrowserPrompt)
                && !(testCase instanceof com.samlscope.runner.cases.ConfigurationPrompt)) {
            return new CampaignSeed("automatic-evaluation", "Automatic protocol and metadata evaluation", ActionKind.NONE);
        }
        var obligation = definition.obligation();
        if (evidenceClass == EvidenceClass.SELF_ATTESTED) return selfCheckCampaign(obligation);
        if (definition.mode() == ExecutionMode.CONFIG && evidenceClass == EvidenceClass.OPERATOR_ASSISTED) {
            return new CampaignSeed("metadata-refresh", "Refresh or re-import Suite metadata", ActionKind.METADATA_REFRESH);
        }
        if (obligation.startsWith("IIP-MD")) {
            return new CampaignSeed("metadata-observation", "Metadata publication and consumption", ActionKind.METADATA_REFRESH);
        }
        if (obligation.startsWith("IIP-ALG")) {
            return new CampaignSeed("crypto-policy", "Cryptographic algorithm policy", ActionKind.CONFIGURATION);
        }
        if (obligation.startsWith("IIP-IDP10") || obligation.startsWith("IIP-IDP11")) {
            return new CampaignSeed("nameid-policy", "Name identifier policy scenarios", ActionKind.LOGIN);
        }
        if (obligation.startsWith("IIP-IDP17") || obligation.startsWith("IIP-IDP18")
                || obligation.startsWith("IIP-SP14")) {
            return new CampaignSeed("logout", "Logout scenarios", ActionKind.LOGIN);
        }
        if (definition.requires().session().equals("required") || definition.mode() == ExecutionMode.BROWSER) {
            return new CampaignSeed("browser-sso", "Browser SSO scenarios", ActionKind.LOGIN);
        }
        return new CampaignSeed("protocol-controls", "Protocol controls", ActionKind.CONTINUE);
    }

    private CampaignSeed selfCheckCampaign(String obligation) {
        if (obligation.startsWith("IIP-ALG")) {
            return new CampaignSeed("self-crypto", "Cryptographic capabilities and policy", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-MD01") || obligation.startsWith("IIP-MD02")
                || obligation.startsWith("IIP-MD03") || obligation.startsWith("IIP-MD04")) {
            return new CampaignSeed(
                    "self-metadata-acquisition", "Metadata acquisition, refresh, and trust", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-MD05")) {
            return new CampaignSeed(
                    "self-metadata-format", "Metadata format and interoperability", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-MD06") || obligation.startsWith("IIP-MD07")) {
            return new CampaignSeed(
                    "self-metadata-runtime", "Metadata runtime use and key rollover", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-MD")) {
            return new CampaignSeed(
                    "self-metadata-publication", "Metadata publication and certificate policy", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-IDP10") || obligation.startsWith("IIP-IDP11")
                || obligation.startsWith("IIP-SP10") || obligation.startsWith("IIP-SP11")) {
            return new CampaignSeed("self-identifiers", "Identifier generation and privacy", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-IDP17") || obligation.startsWith("IIP-IDP18")
                || obligation.startsWith("IIP-SP14")) {
            return new CampaignSeed("self-logout", "Logout behavior", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-IDP") || obligation.startsWith("IIP-SP")) {
            return new CampaignSeed("self-authentication", "Authentication and assertion policy", ActionKind.SELF_CHECK);
        }
        if (obligation.startsWith("IIP-G") || obligation.startsWith("IIP-EXT")) {
            return new CampaignSeed("self-processing", "XML and implementation processing", ActionKind.SELF_CHECK);
        }
        return new CampaignSeed("self-other", "Other internal implementation evidence", ActionKind.SELF_CHECK);
    }

    private PlanSummary summarize(
            Plan requestedPlan, List<ClassifiedCase> classified, List<Campaign> campaigns) {
        var includedCases = classified.stream().filter(value -> value.plan().ordinal() <= requestedPlan.ordinal()).toList();
        var includedCampaigns = campaigns.stream().filter(value -> value.plan().ordinal() <= requestedPlan.ordinal()).toList();
        int actions = includedCampaigns.stream().mapToInt(Campaign::deliberateUserActions).sum();
        int remaining = includedCampaigns.stream().mapToInt(Campaign::remainingUserActions).sum();
        int logins = actions(includedCampaigns, ActionKind.LOGIN);
        int configuration = actions(includedCampaigns, ActionKind.CONFIGURATION);
        int metadata = actions(includedCampaigns, ActionKind.METADATA_REFRESH);
        int selfSections = (int) includedCampaigns.stream()
                .filter(value -> value.actionKind() == ActionKind.SELF_CHECK).count();
        int min = durationMin(requestedPlan, actions);
        int max = durationMax(requestedPlan, actions);
        int budget = ACTION_BUDGETS.get(requestedPlan);
        return new PlanSummary(
                requestedPlan, includedCases.size(), actions, remaining, logins, configuration,
                metadata, selfSections, min, max, budget, actions <= budget && selfSections <= 15);
    }

    private int actions(List<Campaign> campaigns, ActionKind kind) {
        return campaigns.stream().filter(value -> value.actionKind() == kind)
                .mapToInt(Campaign::deliberateUserActions).sum();
    }

    private int durationMin(Plan plan, int actions) {
        return switch (plan) {
            case QUICK -> Math.max(10, actions);
            case STANDARD -> Math.max(30, actions);
            case FULL -> Math.max(60, actions);
        };
    }

    private int durationMax(Plan plan, int actions) {
        return switch (plan) {
            case QUICK -> Math.max(20, actions * 2);
            case STANDARD -> Math.max(60, actions * 2);
            case FULL -> Math.max(90, actions * 2);
        };
    }

    private record CampaignSeed(String id, String title, ActionKind actionKind) {}
    private record ClassifiedCase(
            String caseId,
            EvidenceClass evidenceClass,
            Plan plan,
            String campaignId,
            String campaignTitle,
            ActionKind actionKind,
            boolean freshSessionRequired,
            boolean shareableAction,
            int actionUnits,
            List<String> actionKeys,
            boolean finished,
            boolean resolved,
            String outcome,
            List<String> expectedEvidence) {}

    private static final class MutableCampaign {
        private final String id;
        private final String title;
        private final Plan plan;
        private final EvidenceClass evidenceClass;
        private final ActionKind actionKind;
        private boolean freshSessionRequired;
        private final boolean shareableAction;
        private int totalActionUnits;
        private int remainingActionUnits;
        private final LinkedHashSet<String> actionKeys = new LinkedHashSet<>();
        private final LinkedHashSet<String> remainingActionKeys = new LinkedHashSet<>();
        private final List<String> caseIds = new ArrayList<>();
        private final List<String> remainingCaseIds = new ArrayList<>();
        private final LinkedHashSet<String> expectedEvidence = new LinkedHashSet<>();
        private final LinkedHashMap<String, LinkedHashSet<String>> actionCases = new LinkedHashMap<>();
        private final LinkedHashMap<String, LinkedHashSet<String>> remainingActionCases = new LinkedHashMap<>();

        private MutableCampaign(ClassifiedCase first) {
            id = first.campaignId();
            title = first.campaignTitle();
            plan = first.plan();
            evidenceClass = first.evidenceClass();
            actionKind = first.actionKind();
            shareableAction = first.shareableAction();
        }

        private void add(ClassifiedCase value) {
            if (plan != value.plan() || evidenceClass != value.evidenceClass()
                    || actionKind != value.actionKind() || shareableAction != value.shareableAction()) {
                throw new IllegalStateException("Campaign mixes incompatible evidence: " + id);
            }
            caseIds.add(value.caseId());
            if (!value.finished()) remainingCaseIds.add(value.caseId());
            if (actionKind != ActionKind.NONE) {
                totalActionUnits += value.actionUnits();
                if (!value.finished()) remainingActionUnits += value.actionUnits();
                actionKeys.addAll(value.actionKeys());
                if (!value.finished()) remainingActionKeys.addAll(value.actionKeys());
                value.actionKeys().forEach(key -> {
                    actionCases.computeIfAbsent(key, ignored -> new LinkedHashSet<>()).add(value.caseId());
                    if (!value.finished()) {
                        remainingActionCases.computeIfAbsent(key, ignored -> new LinkedHashSet<>())
                                .add(value.caseId());
                    }
                });
            }
            freshSessionRequired |= value.freshSessionRequired();
            expectedEvidence.addAll(value.expectedEvidence());
        }

        private Campaign freeze() {
            int action = shareableAction ? actionKeys.size() : totalActionUnits;
            int remaining = shareableAction ? remainingActionKeys.size() : remainingActionUnits;
            var actions = actionCases.entrySet().stream().map(entry -> new CampaignAction(
                    entry.getKey(), List.copyOf(entry.getValue()),
                    List.copyOf(remainingActionCases.getOrDefault(entry.getKey(), new LinkedHashSet<>()))))
                    .toList();
            return new Campaign(
                    id, title, plan, evidenceClass, actionKind, action, remaining,
                    freshSessionRequired, caseIds, remainingCaseIds, List.copyOf(expectedEvidence), actions);
        }
    }
}
