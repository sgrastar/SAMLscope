package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Native request-bound evidence augments the approved metadata fixture campaign. */
public final class NativeCertificateConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase, RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final NativeCertificateEvidenceFile evidence;
    public NativeCertificateConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.evidence = new NativeCertificateEvidenceFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported native certificate case");
    }
    public static boolean supports(String id) {
        return NativeCertificateComparison.CASES.contains(id);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() {
        return ((com.samlscope.runner.EvidenceCampaignCase) fallback).evidenceActionKeys();
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && evidence.exists(context.runId())) {
            return new CaseStep.Finish(observe(context));
        }
        return fallback.resume(context, state, event);
    }
    CaseOutcome observe(CaseContext context) {
        try {
            var before = evidence.receiptSha256(context.runId());
            var result = NativeCertificateComparison.evaluate(id(), evidence.read(context, metadata.apply(context.runId()), content), List.of());
            if (!before.equals(evidence.receiptSha256(context.runId()))) throw new IllegalArgumentException("Receipt changed during evaluation");
            var details = new LinkedHashMap<String, Object>(result.details());
            details.put("native_receipt_sha256", before);
            details.put("original_signatures_verified", true);
            return new CaseOutcome(result.outcome(), result.notVerifiedReason(), result.reasonCode(),
                    result.reasonMessageKey(), result.evidence(), details);
        } catch (Exception unproven) {
            return NativeCertificateComparison.evaluate(id(), List.of(), List.of("native_certificate_originals_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (!evidence.exists(context.runId())) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        var result = observe(context);
        boolean ready = result.outcome() == Outcome.SATISFIED || result.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("metadata.fixture-probe.incomplete", "metadata.certificate.native-evidence-incomplete")
                    .contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        if (evidence.exists(context.runId())) return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
        return ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
    }
}
