package com.samlscope.runner.cases;

import java.time.Duration;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.runner.*;

/** Positive proof of ECDSA-SHA256 support, guarded against blanket accept/reject peers. */
public final class EcSignatureSupportTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, EvidenceCampaignCase, RecordedEvidenceReevaluation {
    public static final String ID = "IIP-ALG03-a-idp-01";
    private static final String PHASE = "await-ec-signature-evidence";
    private static final String CONTROL = "control";
    private static final String VALID = "ecdsa-sha256";
    private static final String INVALID = "ecdsa-sha256-invalid-signature";
    private static final String SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    private static final Set<String> ERRORS = Set.of("urn:oasis:names:tc:SAML:2.0:status:Requester",
            "urn:oasis:names:tc:SAML:2.0:status:Responder", "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch");
    private static final List<String> VARIANTS = List.of(CONTROL, VALID, INVALID);
    @Override public String id() { return ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Refresh or re-import Suite metadata fixtures"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.METADATA_REFRESH; }
    @Override public List<String> evidenceActionKeys() { return VARIANTS; }
    @Override public String instructionEn() {
        return "Use the Run metadata campaign to fetch control, ecdsa-sha256, and ecdsa-sha256-invalid-signature "
                + "and attempt each correlated signed request. Keep the same signature-verification policy enabled. "
                + "The Suite requires a working RSA control, successful EC request, and an explicit SAML error "
                + "for the corrupted EC signature. An HTTP error or silence cannot confirm rejection or lack of support.";
    }
    @Override public CaseStep start(CaseContext context) {
        return new CaseStep.AwaitConfig(new CaseState(PHASE, Map.of()), List.of(), "ec-signature-support", Duration.ofDays(7));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (!PHASE.equals(state.phase())) throw new IllegalArgumentException("Unexpected EC evidence phase");
        if (event instanceof CaseEvent.ConfigConfirmed) return new CaseStep.Finish(observe(context));
        if (event instanceof CaseEvent.ConfigUnavailable) return new CaseStep.Finish(CaseOutcome.notVerified(
                "ec_signature_configuration_unavailable", "ec-signature.configuration-unavailable"));
        if (event instanceof CaseEvent.TimedOut) return new CaseStep.Finish(CaseOutcome.notVerified(
                "ec_signature_timeout", "ec-signature.timeout"));
        if (event instanceof CaseEvent.Aborted) return new CaseStep.Finish(CaseOutcome.notVerified(
                "ec_signature_aborted", "ec-signature.aborted"));
        throw new IllegalArgumentException("Expected EC evidence completion");
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var observation = observe(context);
        var complete = observation.details().get("completed_observations") instanceof List<?> list
                ? list.stream().map(String::valueOf).toList() : List.<String>of();
        return new EvidenceStatus(observation.outcome() == Outcome.SATISFIED,
                List.of("fetched:control", "success:control", "fetched:" + VALID, "success:" + VALID,
                        "fetched:" + INVALID, "error:" + INVALID), complete, observation.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && "ec-signature.incomplete".equals(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous, observe(context));
    }
    private CaseOutcome observe(CaseContext context) {
        var fetched = new LinkedHashSet<String>();
        var success = new LinkedHashSet<String>();
        var errors = new LinkedHashSet<String>();
        var evidence = new LinkedHashSet<EvidenceRef>();
        for (var entry : context.transcript().list(context.runId())) {
            if (entry.direction() != Direction.INBOUND || !context.runId().equals(entry.runId())) continue;
            if ("MetadataFetch".equals(entry.samlSummary().get("type"))) {
                var advertised = new ArrayList<String>();
                if (entry.samlSummary().get("variant") instanceof String value) advertised.add(value);
                if (entry.samlSummary().get("variants") instanceof List<?> values)
                    values.stream().filter(String.class::isInstance).map(String.class::cast).forEach(advertised::add);
                if (advertised.stream().anyMatch(VARIANTS::contains)) {
                    advertised.stream().filter(VARIANTS::contains).forEach(fetched::add);
                    evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
                }
            }
            if (entry.decodedSamlBytes() <= 0 || !Boolean.TRUE.equals(entry.samlSummary().get("metadataProbeAccepted"))) continue;
            for (var variant : VARIANTS) {
                if (!fetched.contains(variant) || !MetadataProbeCorrelation.matches(entry.url(), context.runId(), variant)) continue;
                var status = entry.samlSummary().get("statusCode");
                if (SUCCESS.equals(status)) success.add(variant);
                else if (ERRORS.contains(String.valueOf(status))) errors.add(variant);
                else continue;
                evidence.add(new EvidenceRef("transcript", "transcript:" + entry.id()));
            }
        }
        var completed = new ArrayList<String>();
        fetched.forEach(v -> completed.add("fetched:" + v));
        success.forEach(v -> completed.add("success:" + v));
        errors.forEach(v -> completed.add("error:" + v));
        boolean contradictory = VARIANTS.stream().anyMatch(v -> success.contains(v) && errors.contains(v));
        boolean controlFailed = errors.contains(CONTROL) || success.contains(INVALID) || contradictory;
        boolean satisfied = context.transcriptComplete() && !controlFailed && success.contains(CONTROL)
                && success.contains(VALID) && errors.contains(INVALID);
        var details = new LinkedHashMap<String,Object>();
        details.put("completed_observations", List.copyOf(completed));
        details.put("fetched_variants", List.copyOf(fetched));
        details.put("successful_variants", List.copyOf(success));
        details.put("error_variants", List.copyOf(errors));
        details.put("transcript_complete", context.transcriptComplete());
        details.put("control_failed", controlFailed);
        details.put("contradictory_responses", contradictory);
        details.put("rejection_is_not_proof_of_algorithm_absence", errors.contains(VALID));
        return new CaseOutcome(satisfied ? Outcome.SATISFIED : Outcome.NOT_VERIFIED,
                satisfied ? null : controlFailed ? "ec_signature_control_failed" : "ec_signature_evidence_incomplete",
                satisfied ? "ec-signature.support-observed" : controlFailed ? "ec-signature.control-failed" : "ec-signature.incomplete",
                satisfied ? "ec-signature.support-observed" : "ec-signature.incomplete", List.copyOf(evidence), details);
    }
}
