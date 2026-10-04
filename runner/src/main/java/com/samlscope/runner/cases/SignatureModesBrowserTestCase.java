package com.samlscope.runner.cases;

import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;

/** Keeps the existing outbox scenario while accepting independently verified multi-configuration evidence. */
public final class SignatureModesBrowserTestCase implements TestCase, BrowserPrompt, BrowserFrontChannelScenario,
        QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final SamlDecryptionKeyProvider keys;
    public SignatureModesBrowserTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, SamlDecryptionKeyProvider keys) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.keys = Objects.requireNonNull(keys);
        if (!SignatureModesObservation.ID.equals(fallback.id()) || !(fallback instanceof BrowserFrontChannelScenario))
            throw new IllegalArgumentException("Signature mode scenario required");
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String browserInstructionsEn() {
        return "For this Run and the same SP, exercise native configurations signing both Response and Assertion, "
                + "only Assertion, and only Response. Restore product settings afterward. The Suite verifies each "
                + "signature and the signed request correlation; configuration labels alone cannot complete the case.";
    }
    @Override public String instructionsEn(CaseState state) { return browserInstructionsEn(); }
    @Override public List<EvidenceCampaignCase> supplementalEvidenceCampaigns() {
        return List.of(new EvidenceCampaignCase() {
            @Override public String evidenceCampaignId() { return "signature-mode-configurations"; }
            @Override public String evidenceCampaignTitle() { return "Native Response and Assertion signing configurations"; }
            @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.CONFIGURATION; }
            @Override public List<String> evidenceActionKeys() { return SignatureModesObservation.REQUIRED; }
        });
    }
    @Override public CaseStep start(CaseContext context) {
        var observed = observe(context);
        return observed.outcome() == Outcome.SATISFIED ? new CaseStep.Finish(observed) : fallback.start(context);
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.TranscriptReady) return new CaseStep.Finish(observe(context));
        var step = fallback.resume(context, state, event);
        if (step instanceof CaseStep.Finish finish && finish.outcome().outcome() == Outcome.NOT_VERIFIED) {
            var observed = observe(context);
            if (observed.outcome() == Outcome.SATISFIED) return new CaseStep.Finish(observed);
            var details = new LinkedHashMap<String,Object>(finish.outcome().details());
            details.putAll(observed.details());
            return new CaseStep.Finish(new CaseOutcome(observed.outcome(), observed.notVerifiedReason(),
                    observed.reasonCode(), observed.reasonMessageKey(), observed.evidence(), details));
        }
        return step;
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) { return observe(context); }
    CaseOutcome observe(CaseContext context) {
        try { return SignatureModesObservation.observe(context, content, metadata.apply(context.runId()), keys); }
        catch (Exception unavailable) { return SignatureModesObservation.evaluate(List.of(), List.of("metadata_unavailable")); }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var observed = outcome.details().get("observed_modes");
        var completed = observed instanceof List<?> list ? list.stream().filter(String.class::isInstance).map(String.class::cast).toList() : List.<String>of();
        return new EvidenceStatus(outcome.outcome() == Outcome.SATISFIED, SignatureModesObservation.REQUIRED, completed, outcome.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("browser_fixture_partial", "browser.signature-modes.incomplete", "browser.oracle-unavailable")
                    .contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return supportsRecordedEvidenceReevaluation(previous)
                ? RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context)) : Optional.empty();
    }
}
