package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;

/** Automatic a8 originals augment the exact approved manual CONFIG/attestation fallback. */
public final class AdditionalMetadataLocationConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, EvidenceCampaignCase, FallbackEvidenceCase {
    private final TestCase fallback;
    private final AdditionalMetadataLocationEvidence reader;

    public AdditionalMetadataLocationConfigurationTestCase(TestCase fallback, AdditionalMetadataLocationEvidence reader) {
        this.fallback = Objects.requireNonNull(fallback); this.reader = Objects.requireNonNull(reader);
        if (!AdditionalMetadataLocationEvidence.supports(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt)) throw new IllegalArgumentException("Approved a8 CONFIG fallback required");
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public String evidenceCampaignId() { return "additional-metadata-location-originals"; }
    @Override public String evidenceCampaignTitle() { return "Additional metadata namespace inspection"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.CONFIGURATION; }

    @Override public CaseStep start(CaseContext context) {
        var observed = reader.observe(context);
        if (observed.ready()) return new CaseStep.Finish(observed.outcome());
        var step = fallback.start(context);
        if (!(step instanceof CaseStep.AwaitConfig wait) || !AdditionalMetadataLocationEvidence.PHASE.equals(wait.next().phase())
                || !wait.actions().isEmpty()) return step;
        try {
            var requests = reader.requests(context);
            if (requests.isEmpty()) return step;
            var data = new LinkedHashMap<String, Object>(wait.next().data());
            data.put("additional_metadata_snapshot_sha256", requests.getFirst().snapshotHash());
            data.put("additional_metadata_request_urls", requests.stream().map(r -> r.url().toString()).toList());
            return new CaseStep.AwaitConfig(new CaseState(wait.next().phase(), data), reader.actions(context), wait.instructionKey(), wait.ttl());
        } catch (RuntimeException unavailable) { return step; }
    }

    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed) {
            var observed = reader.observe(context);
            if (observed.ready()) return new CaseStep.Finish(observed.outcome());
        }
        // Operator declarations, cancellation, expiry, and configuration failures retain their meaning.
        return fallback.resume(context, state, event);
    }

    public boolean ownsAction(CaseContext context, CaseExecution execution, OutboxEntry action) {
        if (execution == null || execution.status() != CaseExecutionStatus.WAITING_CONFIG
                || !context.runId().equals(execution.runId()) || !id().equals(execution.caseId())
                || !AdditionalMetadataLocationEvidence.PHASE.equals(execution.state().phase())) return false;
        try {
            var requests = reader.requests(context);
            return !requests.isEmpty() && requests.getFirst().snapshotHash().equals(
                    execution.state().data().get("additional_metadata_snapshot_sha256"))
                    && requests.stream().map(r -> r.url().toString()).toList().equals(
                            execution.state().data().get("additional_metadata_request_urls"))
                    && reader.owns(context, action);
        } catch (RuntimeException unavailable) { return false; }
    }
    public void produceControls(CaseContext context) { reader.produceControls(context); }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observation = reader.observe(context);
        var details = new LinkedHashMap<String, Object>(observation.outcome().details());
        if (observation.outcome().notVerifiedReason() != null) details.put("not_verified_reason", observation.outcome().notVerifiedReason());
        return new EvidenceStatus(observation.ready(), observation.required(), observation.completed(), details);
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution != null && id().equals(execution.caseId()) && execution.outcome() != null
                && Set.of(Outcome.SATISFIED, Outcome.VIOLATED).contains(execution.outcome().outcome())
                && execution.outcome().reasonCode().startsWith(AdditionalMetadataLocationEvidence.REASON + ".")
                && execution.runId().equals(execution.outcome().details().get("run_id"))
                && id().equals(execution.outcome().details().get("case_id"))
                && execution.outcome().evidence().stream().anyMatch(e -> "transcript".equals(e.kind()))
                && execution.outcome().evidence().stream().anyMatch(e -> "suite-calibration".equals(e.kind()));
    }
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution) {
        if (resolvedFromExternalEvidence(execution)) return RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED;
        return fallback instanceof FallbackEvidenceCase original ? original.evidenceClass(execution)
                : RunCampaignQuery.EvidenceClass.SELF_ATTESTED;
    }
}
