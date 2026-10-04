package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import java.util.*;

/** Reuse authenticated known-subject originals without dispatching another browser request. */
public final class RequestedSubjectMatchTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE = "IIP-SSO07-b-idp-01";
    private static final List<String> REQUIRED = List.of("authenticated-known-subject", "signed-correlated-assertion",
            "identifier-content-and-attributes", "nameid-policy-exemption-check", "native-configuration-restoration");
    private final IdpExecutableBrowserFixtureScenarioTestCase fallback;
    private final ShibbolethRequestedSubjectMatchEvidence evidence;

    RequestedSubjectMatchTestCase(IdpExecutableBrowserFixtureScenarioTestCase fallback,
            ShibbolethRequestedSubjectMatchEvidence evidence) {
        this.fallback = Objects.requireNonNull(fallback);
        this.evidence = Objects.requireNonNull(evidence);
        if (!CASE.equals(fallback.id())) throw new IllegalArgumentException("Approved requested-subject case required");
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    private static CaseOutcome unproven() {
        return CaseOutcome.notVerified("native_requested_subject_originals_unproven", "idp.subject.native-match-unproven");
    }
    private Optional<CaseOutcome> observe(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try { return Optional.of(evidence.read(context).orElseGet(RequestedSubjectMatchTestCase::unproven)); }
        catch (RuntimeException unavailable) { return Optional.of(unproven()); }
    }
    @Override public CaseStep start(CaseContext context) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) {
        return observe(context).orElseGet(RequestedSubjectMatchTestCase::unproven);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var proof = observe(context);
        if (proof.isEmpty()) return fallback.evidenceStatus(context);
        boolean ready = proof.get().outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, REQUIRED, ready ? REQUIRED : List.of(), proof.get().details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var proof = observe(context);
        return proof.isPresent() ? RecordedEvidenceReevaluation.conclusiveUpdate(previous, proof.get())
                : fallback.reevaluateRecordedEvidence(context, previous);
    }
    @Override public String browserInstructionsEn() { return fallback.browserInstructionsEn(); }
    @Override public String instructionsEn(CaseState state) { return fallback.instructionsEn(state); }
    @Override public Binding outboundBinding(CaseState state) { return fallback.outboundBinding(state); }
    @Override public boolean requiresFreshSession(CaseState state) { return fallback.requiresFreshSession(state); }
    @Override public boolean plansFreshSessionBoundary() { return fallback.plansFreshSessionBoundary(); }
    @Override public int plannedDeliberateActions() { return fallback.plannedDeliberateActions(); }
}
