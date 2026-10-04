package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

/** Reads pre-collected native browser evidence; no completion click can supply a missing observation. */
public final class UiDisplayBrowserEvidenceTestCase implements TestCase, QueuedProtocolEvidenceCase,
        com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.RecordedEvidenceReevaluation {
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final UiDisplayEvidenceFile evidence;
    private final SimpleSamlPhpConsentUiEvidence nativeConsent;
    private final ShibbolethUiConsumerEvidence nativeShibboleth;
    public UiDisplayBrowserEvidenceTestCase(TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        this.content = Objects.requireNonNull(content); this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new UiDisplayEvidenceFile(directory);
        this.nativeConsent = new SimpleSamlPhpConsentUiEvidence(directory, content);
        this.nativeShibboleth = new ShibbolethUiConsumerEvidence(
                directory.toAbsolutePath().resolveSibling("ui-url-evidence"), content);
    }
    @Override public String id() { return UiDisplayComparison.CASE_ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public String evidenceCampaignId() { return "metadata-ui-display-comparison"; }
    @Override public String evidenceCampaignTitle() { return "Native browser display-name precedence"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() { return List.of("ui-consumer-display-all", "ui-consumer-display-service", "ui-consumer-display-entity"); }
    @Override public CaseStep start(CaseContext context) { return new CaseStep.Finish(observe(context)); }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) { return observe(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!(event instanceof CaseEvent.TranscriptReady)) throw new IllegalArgumentException("Browser originals required");
        return new CaseStep.Finish(observe(context));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("browser.ui-display.evidence-incomplete", "browser.oracle-unavailable",
                        "attestation.interaction-disallowed").contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return Optional.empty();
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
    CaseOutcome observe(CaseContext context) {
        try {
            if (nativeShibboleth.exists(context.runId())) {
                if (nativeConsent.exists(context.runId())) throw new IllegalArgumentException("Ambiguous native UI originals");
                return nativeShibboleth.read(context, metadata.apply(context.runId()), id()).orElseThrow();
            }
            if (nativeConsent.exists(context.runId())) {
                return nativeConsent.evaluate(context, metadata.apply(context.runId())).orElseThrow();
            }
            return UiDisplayComparison.evaluate(evidence.read(context, metadata.apply(context.runId()), content), List.of());
        } catch (Exception unproven) {
            return UiDisplayComparison.evaluate(List.of(), List.of("native_browser_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        boolean ready = outcome.outcome() == Outcome.SATISFIED || outcome.outcome() == Outcome.SATISFIED_WITH_NOTE
                || outcome.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), outcome.details());
    }
}
