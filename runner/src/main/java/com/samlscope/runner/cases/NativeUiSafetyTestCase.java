package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

/** Adds complete native UI evidence without removing the approved browser scenario contract. */
final class NativeUiSafetyTestCase implements TestCase, BrowserFrontChannelScenario, BrowserPrompt,
        QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    static final String CASE = "IIP-MD05-fg-idp-01";
    private final IdpExecutableBrowserFixtureScenarioTestCase delegate;
    private final ShibbolethUiConsumerEvidence evidence;
    private final SimpleSamlPhpConsentSafetyEvidence simpleSamlPhp;
    private final KeycloakUiSafetyEvidence keycloak;
    private final Function<String, byte[]> metadata;

    NativeUiSafetyTestCase(IdpExecutableBrowserFixtureScenarioTestCase delegate,
            ShibbolethUiConsumerEvidence evidence, Function<String, byte[]> metadata) {
        this(delegate, evidence, null, metadata);
    }

    NativeUiSafetyTestCase(IdpExecutableBrowserFixtureScenarioTestCase delegate,
            ShibbolethUiConsumerEvidence evidence, SimpleSamlPhpConsentSafetyEvidence simpleSamlPhp,
            Function<String, byte[]> metadata) {
        this(delegate, evidence, simpleSamlPhp, null, metadata);
    }

    NativeUiSafetyTestCase(IdpExecutableBrowserFixtureScenarioTestCase delegate,
            ShibbolethUiConsumerEvidence evidence, SimpleSamlPhpConsentSafetyEvidence simpleSamlPhp,
            KeycloakUiSafetyEvidence keycloak, Function<String, byte[]> metadata) {
        this.delegate = Objects.requireNonNull(delegate);
        this.evidence = Objects.requireNonNull(evidence);
        this.simpleSamlPhp = simpleSamlPhp;
        this.keycloak = keycloak;
        this.metadata = Objects.requireNonNull(metadata);
        if (!CASE.equals(delegate.id())) throw new IllegalArgumentException("Native UI safety is only for MD05.fg");
    }

    @Override public String id() { return delegate.id(); }
    @Override public TargetRole role() { return delegate.role(); }
    @Override public CaseStep start(CaseContext context) {
        return owned(context) ? new CaseStep.Finish(observe(context)) : delegate.start(context);
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return owned(context) ? new CaseStep.Finish(observe(context)) : delegate.resume(context, state, event);
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) { return observe(context); }
    private boolean owned(CaseContext context) {
        return evidence.exists(context.runId())
                || simpleSamlPhp != null && simpleSamlPhp.exists(context.runId())
                || keycloak != null && keycloak.exists(context.runId());
    }
    private CaseOutcome observe(CaseContext context) {
        try {
            boolean shibbolethOwned = evidence.exists(context.runId());
            boolean simpleSamlPhpOwned = simpleSamlPhp != null && simpleSamlPhp.exists(context.runId());
            boolean keycloakOwned = keycloak != null && keycloak.exists(context.runId());
            if ((shibbolethOwned ? 1 : 0) + (simpleSamlPhpOwned ? 1 : 0) + (keycloakOwned ? 1 : 0) > 1)
                return unproven();
            if (keycloakOwned) {
                return keycloak.evaluate(context, metadata.apply(context.runId()))
                        .orElseGet(NativeUiSafetyTestCase::unproven);
            }
            if (simpleSamlPhpOwned) {
                return simpleSamlPhp.evaluate(context, metadata.apply(context.runId()))
                        .orElseGet(NativeUiSafetyTestCase::unproven);
            }
            return evidence.read(context, metadata.apply(context.runId()), id()).orElseGet(NativeUiSafetyTestCase::unproven);
        } catch (Exception unavailable) {
            return unproven();
        }
    }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_ui_safety_originals_unproven", "browser.ui-safety.evidence-incomplete");
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (!owned(context)) return delegate.evidenceStatus(context);
        var observed = observe(context);
        var keys = List.of("ui-safety-logo-data", "ui-safety-information-javascript", "ui-safety-privacy-javascript");
        boolean ready = observed.outcome() != Outcome.NOT_VERIFIED;
        return new EvidenceStatus(ready, keys, ready ? keys : List.of(), observed.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
    @Override public String browserInstructionsEn() { return delegate.browserInstructionsEn(); }
    @Override public String instructionsEn(CaseState state) { return delegate.instructionsEn(state); }
    @Override public Binding outboundBinding(CaseState state) { return delegate.outboundBinding(state); }
    @Override public boolean requiresFreshSession(CaseState state) { return delegate.requiresFreshSession(state); }
    @Override public boolean plansFreshSessionBoundary() { return delegate.plansFreshSessionBoundary(); }
    @Override public int plannedDeliberateActions() { return delegate.plannedDeliberateActions(); }
    @Override public String evidenceCampaignId() { return delegate.evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return delegate.evidenceCampaignTitle(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return delegate.evidenceActionKind(); }
    @Override public List<String> evidenceActionKeys() { return delegate.evidenceActionKeys(); }
}
