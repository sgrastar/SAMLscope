package com.samlscope.runner;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import javax.xml.namespace.QName;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.casedef.CaseDefinitionCatalog;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptRecorder;
import com.samlscope.runner.cases.AutomatedCaseDependencies;
import com.samlscope.runner.cases.AutomatedCaseRegistry;
import com.samlscope.runner.cases.IdpErrorProbeConfiguration;
import com.samlscope.runner.cases.PrincipalIdentityResolver;
import com.samlscope.runner.cases.SamlAttributeReleaseFixture;
import com.samlscope.runner.cases.SamlOptionalFieldObservationCase;
import com.samlscope.runner.cases.TargetSigningCertificateProvider;
import com.samlscope.saml.crypto.FilePlanKeyStore;
import com.samlscope.core.profile.FunctionalCaseDefinition;

/** Executes the approved M1 automated subset as an operational check over a completed Transcript. */
public final class QuickCheckService implements QuickCheckExecutor {
    public static final String DISCLAIMER = "This is an operational check, not a conformance determination.";
    private final PlanRepository plans;
    private final RunRepository runs;
    private final TranscriptRecorder transcript;
    private final TranscriptContentReader transcriptContent;
    private final CaseExecutionRepository caseExecutions;
    private final FilePlanKeyStore keys;
    private final TargetSigningCertificateProvider targetSigningCertificates;
    private final URI peerBase;
    private final Clock clock;
    private final CaseDefinitionCatalog approvedDefinitions;
    private final BiFunction<com.samlscope.core.plan.TestPlan, String, IdpErrorProbeConfiguration> probeConfigurations;
    private final java.util.function.Function<com.samlscope.core.plan.TestPlan,FunctionalCaseDefinition> profileDefinitions;

    public QuickCheckService(
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            TranscriptContentReader transcriptContent,
            CaseExecutionRepository caseExecutions,
            FilePlanKeyStore keys,
            TargetSigningCertificateProvider targetSigningCertificates,
            URI peerBase,
            Clock clock) {
        this(plans, runs, transcript, transcriptContent, caseExecutions, keys,
                targetSigningCertificates, peerBase, clock, null, null, null);
    }

    public QuickCheckService(
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            TranscriptContentReader transcriptContent,
            CaseExecutionRepository caseExecutions,
            FilePlanKeyStore keys,
            TargetSigningCertificateProvider targetSigningCertificates,
            URI peerBase,
            Clock clock,
            CaseDefinitionCatalog approvedDefinitions) {
        this(plans, runs, transcript, transcriptContent, caseExecutions, keys,
                targetSigningCertificates, peerBase, clock, approvedDefinitions, null, null);
    }

    public QuickCheckService(
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            TranscriptContentReader transcriptContent,
            CaseExecutionRepository caseExecutions,
            FilePlanKeyStore keys,
            TargetSigningCertificateProvider targetSigningCertificates,
            URI peerBase,
            Clock clock,
            CaseDefinitionCatalog approvedDefinitions,
            BiFunction<com.samlscope.core.plan.TestPlan, String, IdpErrorProbeConfiguration> probeConfigurations) {
        this(plans, runs, transcript, transcriptContent, caseExecutions, keys,
                targetSigningCertificates, peerBase, clock, approvedDefinitions, probeConfigurations, null);
    }

    public QuickCheckService(
            PlanRepository plans,
            RunRepository runs,
            TranscriptRecorder transcript,
            TranscriptContentReader transcriptContent,
            CaseExecutionRepository caseExecutions,
            FilePlanKeyStore keys,
            TargetSigningCertificateProvider targetSigningCertificates,
            URI peerBase,
            Clock clock,
            CaseDefinitionCatalog approvedDefinitions,
            BiFunction<com.samlscope.core.plan.TestPlan, String, IdpErrorProbeConfiguration> probeConfigurations,
            java.util.function.Function<com.samlscope.core.plan.TestPlan,FunctionalCaseDefinition> profileDefinitions) {
        this.plans = Objects.requireNonNull(plans, "plans");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.transcript = Objects.requireNonNull(transcript, "transcript");
        this.transcriptContent = Objects.requireNonNull(transcriptContent, "transcriptContent");
        this.caseExecutions = Objects.requireNonNull(caseExecutions, "caseExecutions");
        this.keys = Objects.requireNonNull(keys, "keys");
        this.targetSigningCertificates = Objects.requireNonNull(
                targetSigningCertificates, "targetSigningCertificates");
        this.peerBase = Objects.requireNonNull(peerBase, "peerBase");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.approvedDefinitions = approvedDefinitions;
        this.probeConfigurations = probeConfigurations == null
                ? (plan, runId) -> inactiveProbe(plan.id())
                : probeConfigurations;
        this.profileDefinitions = profileDefinitions;
    }

    @Override
    public QuickCheckResult execute(String runId) {
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        if (run.status() != RunStatus.COMPLETED) {
            throw new IllegalArgumentException("Quick check requires a completed SSO round trip");
        }
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        var credentials = keys.getOrCreate(plan.id());
        var registry = AutomatedCaseRegistry.create(new AutomatedCaseDependencies(
                transcriptContent,
                attributeFixtures(),
                optionalSelectors(),
                targetSigningCertificates.certificatesFor(plan, run.id()),
                peerBase.resolve("/p/" + plan.id()).toString(),
                ignored -> Optional.of(credentials.privateKey()),
                (ignored, identifier) -> PrincipalIdentityResolver.Resolution.unknown(),
                caseExecutions,
                probeConfigurations.apply(plan, run.id())));
        if (approvedDefinitions != null) {
            CaseImplementationAudit.requireExact(
                    approvedDefinitions, registry,
                    CaseDefinitionCatalog.Milestone.M1,
                    CaseDefinitionCatalog.ExecutionMode.AUTOMATED);
        }
        var context = new DefaultCaseContext(
                run.id(), plan.profile().role(), clock, plan.parameters(),
                plan.interaction(),
                run.targetToSuiteReachability(), transcript, true);
        var snapshot = new AutomatedCaseRunner(registry, new CaseExecutionService(caseExecutions, new PlanRequestSigning(plans, runs, keys)))
                .startReady(run.id(), requireProfileDefinition(plan), context);
        return new QuickCheckResult(run.id(), DISCLAIMER, snapshot);
    }

    private FunctionalCaseDefinition requireProfileDefinition(com.samlscope.core.plan.TestPlan plan) {
        if (profileDefinitions == null) throw new IllegalStateException("Functional case definition is unavailable");
        return profileDefinitions.apply(plan);
    }

    private IdpErrorProbeConfiguration inactiveProbe(String planId) {
        var issuer = peerBase.resolve("/p/" + planId);
        return new IdpErrorProbeConfiguration(
                peerBase.resolve("/p/" + planId + "/inactive-idp-probe"),
                issuer.toString(),
                peerBase.resolve("/p/" + planId + "/sp/acs/0"),
                Duration.ofMinutes(2), false, false, false);
    }

    private Map<String, SamlAttributeReleaseFixture> attributeFixtures() {
        return Map.of(
                "IIP-SSO01-dj-idp-01", new SamlAttributeReleaseFixture("no-values", null, List.of()),
                "IIP-SSO01-dk-idp-01", new SamlAttributeReleaseFixture(
                        "empty", null, List.of(SamlAttributeReleaseFixture.EmptyValue.INSTANCE)),
                "IIP-SSO01-dl-idp-01", new SamlAttributeReleaseFixture(
                        "null", null, List.of(SamlAttributeReleaseFixture.NullValue.INSTANCE)),
                "IIP-SSO01-du-idp-01", new SamlAttributeReleaseFixture(
                        "discrete", null, List.of(
                                new SamlAttributeReleaseFixture.TextValue("one"),
                                new SamlAttributeReleaseFixture.TextValue("two"))));
    }

    private Map<String, SamlOptionalFieldObservationCase.Selector> optionalSelectors() {
        var selector = SamlOptionalFieldObservationCase.Selector.element(new QName(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions"));
        return Map.of("IIP-SSO07-a-idp-01", selector, "IIP-SSO07-a-sp-01", selector);
    }

    public record QuickCheckResult(String runId, String disclaimer, List<CaseExecution> cases) {
        public QuickCheckResult { cases = List.copyOf(cases); }
    }
}
