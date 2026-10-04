package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;

/** Native CONFIG capability is independent of the receiver's separate logout decisions. */
public final class NativeMultipleDecryptionKeysConfigurationTestCase implements TestCase,
        ConfigurationPrompt, AttestationPrompt, ProtocolEvidenceCase, FallbackEvidenceCase,
        RecordedEvidenceReevaluation, EvidenceCampaignCase {
    private final TestCase fallback;
    private final SimpleSamlPhpMultipleDecryptionKeysEvidence evidence;

    public NativeMultipleDecryptionKeysConfigurationTestCase(TestCase fallback,
            SimpleSamlPhpMultipleDecryptionKeysEvidence evidence) {
        this.fallback = Objects.requireNonNull(fallback);
        this.evidence = Objects.requireNonNull(evidence);
        if (!SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE.equals(fallback.id())
                || fallback.role() != TargetRole.IDP || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt) || !(fallback instanceof ProtocolEvidenceCase)
                || !(fallback instanceof RecordedEvidenceReevaluation) || !(fallback instanceof FallbackEvidenceCase)) {
            throw new IllegalArgumentException("Approved multiple-decryption-key CONFIG fallback required");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public CaseStep start(CaseContext context) {
        return evidence.read(context).<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return evidence.read(context).<CaseStep>map(CaseStep.Finish::new)
                .orElseGet(() -> fallback.resume(context, state, event));
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var nativeOutcome = evidence.read(context);
        if (nativeOutcome.isEmpty()) return ((ProtocolEvidenceCase) fallback).evidenceStatus(context);
        var outcome = nativeOutcome.orElseThrow();
        boolean ready = outcome.outcome() == Outcome.SATISFIED;
        var required = List.of("approved-config-source-run", "effective-two-private-keys",
                "signed-native-observation", "native-key-uses", "removed-capability-control", "exact-restoration");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), outcome.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!evidence.exists(context.runId())) {
            return ((RecordedEvidenceReevaluation) fallback).reevaluateRecordedEvidence(context, previous);
        }
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return Optional.empty();
        return evidence.read(context).flatMap(next -> RecordedEvidenceReevaluation.conclusiveUpdate(previous, next));
    }
    private boolean nativeResult(CaseExecution execution) {
        return execution != null && id().equals(execution.caseId()) && execution.outcome() != null
                && execution.outcome().outcome() == Outcome.SATISFIED
                && SimpleSamlPhpMultipleDecryptionKeysEvidence.REASON.equals(execution.outcome().reasonCode())
                && SimpleSamlPhpMultipleDecryptionKeysEvidence.SCHEMA.equals(execution.outcome().details().get("evidence_adapter"))
                && execution.runId().equals(execution.outcome().details().get("run_id"))
                && SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST.equals(execution.outcome().details().get("case_digest"))
                && execution.outcome().evidence().stream().anyMatch(ref ->
                        "native-multiple-decryption-keys".equals(ref.kind())
                        && (execution.runId() + SimpleSamlPhpMultipleDecryptionKeysEvidence.SUFFIX + "/manifest.json")
                                .equals(ref.reference()));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return nativeResult(execution) || execution != null && !evidence.exists(execution.runId())
                && ((FallbackEvidenceCase) fallback).resolvedFromExternalEvidence(execution);
    }
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        if (nativeResult(execution) || execution != null && evidence.exists(execution.runId())) {
            return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
        }
        return ((FallbackEvidenceCase) fallback).evidenceClass(execution);
    }
    @Override public String evidenceCampaignId() { return "native-multiple-decryption-keys"; }
    @Override public String evidenceCampaignTitle() { return "Multiple decryption key configuration"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.CONFIGURATION; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution) {
        if (execution != null && (evidence.exists(execution.runId()) || resolvedFromExternalEvidence(execution)
                || execution.status() == CaseExecutionStatus.FINISHED)) return RunCampaignQuery.ActionKind.NONE;
        return execution != null && execution.status() == CaseExecutionStatus.WAITING_ATTESTATION
                ? RunCampaignQuery.ActionKind.SELF_CHECK : RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    @Override public List<String> evidenceActionKeys() { return List.of(id()); }
}
