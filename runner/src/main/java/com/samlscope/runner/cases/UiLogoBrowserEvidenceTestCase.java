package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

/** Reads pre-collected native browser evidence; no completion click can supply a missing observation. */
public final class UiLogoBrowserEvidenceTestCase implements TestCase, QueuedProtocolEvidenceCase,
        com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.RecordedEvidenceReevaluation {
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final UiLogoEvidenceFile evidence;
    private final SimpleSamlPhpConsentLogoEvidence nativeConsent;
    private final KeycloakNativeUiConsumerEvidence nativeKeycloak;
    public UiLogoBrowserEvidenceTestCase(TranscriptContentReader content, Function<String, byte[]> metadata, Path directory) {
        this.content = Objects.requireNonNull(content); this.metadata = Objects.requireNonNull(metadata);
        this.evidence = new UiLogoEvidenceFile(directory);
        this.nativeConsent = new SimpleSamlPhpConsentLogoEvidence(directory, content);
        this.nativeKeycloak = new KeycloakNativeUiConsumerEvidence(
                directory.resolveSibling("ui-native-feature-absence"), content);
    }
    @Override public String id() { return UiLogoComparison.CASE_ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public String evidenceCampaignId() { return "metadata-ui-logo-comparison"; }
    @Override public String evidenceCampaignTitle() { return "Native browser logo language comparison"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() { return List.of("ui-consumer-logo-localized", "ui-consumer-logo-fallback"); }
    @Override public CaseStep start(CaseContext context) { return new CaseStep.Finish(observe(context)); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!(event instanceof CaseEvent.TranscriptReady)) throw new IllegalArgumentException("Browser originals required");
        return new CaseStep.Finish(observe(context));
    }
    CaseOutcome observe(CaseContext context) {
        try {
            boolean keycloakOwned = nativeKeycloak.exists(context.runId());
            boolean consentOwned = nativeConsent.exists(context.runId());
            if (keycloakOwned && consentOwned) throw new IllegalArgumentException("Ambiguous native logo product");
            if (keycloakOwned) return nativeKeycloak.read(context, metadata.apply(context.runId()), id()).orElseThrow();
            if (consentOwned)
                return nativeConsent.evaluate(context, metadata.apply(context.runId())).orElseThrow();
            return UiLogoComparison.evaluate(evidence.read(context, metadata.apply(context.runId()), content), List.of());
        } catch (Exception unproven) {
            return UiLogoComparison.evaluate(List.of(), List.of("native_browser_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        boolean ready = outcome.outcome() == Outcome.SATISFIED || outcome.outcome() == Outcome.SATISFIED_WITH_NOTE
                || outcome.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), outcome.details());
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context) { return observe(context); }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("browser.ui-logo.evidence-incomplete", "browser.oracle-unavailable",
                        "attestation.interaction-disallowed").contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!context.transcriptComplete() || !supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
}
