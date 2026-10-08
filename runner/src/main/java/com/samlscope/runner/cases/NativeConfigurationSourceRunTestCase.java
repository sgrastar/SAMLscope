package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;

/** Preserves the approved CONFIG fallback unless this recipient owns a source binding. */
public final class NativeConfigurationSourceRunTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, FallbackEvidenceCase, RecordedEvidenceReevaluation, EvidenceCampaignCase {
    interface ProofAccess {
        boolean exists(String run);
        Optional<CaseOutcome> read(CaseContext context);
    }
    private final TestCase fallback;
    private final ProofAccess evidence;
    public NativeConfigurationSourceRunTestCase(TestCase fallback, NativeConfigurationSourceRunEvidence evidence) {
        this(fallback, new ProofAccess() {
            public boolean exists(String run) { return evidence.exists(run); }
            public Optional<CaseOutcome> read(CaseContext context) { return evidence.read(context); }
        });
        Objects.requireNonNull(evidence);
    }
    NativeConfigurationSourceRunTestCase(TestCase fallback, ProofAccess evidence) {
        this.fallback = Objects.requireNonNull(fallback); this.evidence = Objects.requireNonNull(evidence);
        if (!SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE.equals(fallback.id()) || fallback.role() != TargetRole.IDP
                || !(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt)
                || !(fallback instanceof ProtocolEvidenceCase) || !(fallback instanceof FallbackEvidenceCase)
                || !(fallback instanceof RecordedEvidenceReevaluation) || !(fallback instanceof EvidenceCampaignCase)) {
            throw new IllegalArgumentException("Approved multiple-decryption-key CONFIG fallback required");
        }
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt)fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt)fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt)fallback).options(); }
    private CaseOutcome observed(CaseContext context) {
        var outcome = evidence.read(context).orElseGet(NativeConfigurationSourceRunTestCase::pending);
        return outcome.outcome() == Outcome.SATISFIED && !nativeResult(context.runId(),outcome) ? pending() : outcome;
    }
    private static CaseOutcome pending() { return CaseOutcome.notVerified(
            "native_configuration_source_binding_unproven", "configuration.source-run.native-unproven"); }
    @Override public CaseStep start(CaseContext context) {
        return evidence.exists(context.runId()) ? new CaseStep.Finish(observed(context)) : fallback.start(context);
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return evidence.exists(context.runId()) ? new CaseStep.Finish(observed(context)) : fallback.resume(context,state,event);
    }
    @Override public boolean requiresPreparationConfirmation() {
        return ((ProtocolEvidenceCase)fallback).requiresPreparationConfirmation();
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        if (!evidence.exists(context.runId())) return ((ProtocolEvidenceCase)fallback).evidenceStatus(context);
        var outcome = observed(context); boolean ready = outcome.outcome() == Outcome.SATISFIED;
        var required = List.of("approved-source-and-recipient-membership", "whole-source-history-fence",
                "completed-recipient-history-fence", "original-independent-config-proof",
                "native-capability-removal-controls", "original-restoration", "signed-current-native-readback");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), outcome.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!evidence.exists(context.runId())) return ((RecordedEvidenceReevaluation)fallback).reevaluateRecordedEvidence(context,previous);
        return supportsRecordedEvidenceReevaluation(previous) && context.transcriptComplete()
                ? RecordedEvidenceReevaluation.conclusiveUpdate(previous,observed(context)) : Optional.empty();
    }
    private boolean nativeResult(CaseExecution execution) {
        return execution != null && id().equals(execution.caseId()) && nativeResult(execution.runId(),execution.outcome());
    }
    private static boolean nativeResult(String recipient, CaseOutcome outcome) {
        if (outcome == null || outcome.outcome() != Outcome.SATISFIED) return false;
        var d = outcome.details(); Object source = d.get("source_run_id"), hash = d.get("binding_sha256");
        return NativeConfigurationSourceRunEvidence.REASON.equals(outcome.reasonCode())
                && recipient.equals(d.get("adoption_run_id"))
                && source instanceof String run && run.matches("run_[0-9A-HJKMNP-TV-Z]{26}") && !recipient.equals(run)
                && source.equals(d.get("run_id"))
                && SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST.equals(d.get("case_digest"))
                && NativeConfigurationSourceRunEvidence.SCOPE.equals(d.get("binding_scope"))
                && hash instanceof String digest && digest.matches("[0-9a-f]{64}")
                && Boolean.FALSE.equals(d.get("source_transcript_complete"))
                && Boolean.TRUE.equals(d.get("independent_configuration_completion"))
                && Boolean.TRUE.equals(d.get("capability_removal_control_verified"))
                && Boolean.TRUE.equals(d.get("configuration_restored"))
                && outcome.evidence().stream().anyMatch(ref -> "native-configuration-source-run".equals(ref.kind())
                        && ref.reference().equals(recipient+"/manifest.json#sha256="+digest));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return nativeResult(execution) || execution != null && !evidence.exists(execution.runId())
                && ((FallbackEvidenceCase)fallback).resolvedFromExternalEvidence(execution);
    }
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        return nativeResult(execution) || execution != null && evidence.exists(execution.runId())
                ? RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED : ((FallbackEvidenceCase)fallback).evidenceClass(execution);
    }
    @Override public String evidenceCampaignId() { return ((EvidenceCampaignCase)fallback).evidenceCampaignId(); }
    @Override public String evidenceCampaignTitle() { return ((EvidenceCampaignCase)fallback).evidenceCampaignTitle(); }
    @Override public List<EvidenceCampaignCase> supplementalEvidenceCampaigns() {
        return ((EvidenceCampaignCase)fallback).supplementalEvidenceCampaigns();
    }
    @Override public boolean sharesDeliberateAction() { return ((EvidenceCampaignCase)fallback).sharesDeliberateAction(); }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
        return ((EvidenceCampaignCase)fallback).evidenceActionKind();
    }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution) {
        return execution != null && evidence.exists(execution.runId()) ? RunCampaignQuery.ActionKind.NONE
                : ((EvidenceCampaignCase)fallback).evidenceActionKind(execution);
    }
    @Override public List<String> evidenceActionKeys() { return ((EvidenceCampaignCase)fallback).evidenceActionKeys(); }
}
