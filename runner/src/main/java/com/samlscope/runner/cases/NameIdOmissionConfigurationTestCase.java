package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.crypto.PlanCredentials;

/** Native preparation enables protocol comparison; manual evidence review remains available. */
public final class NameIdOmissionConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final BiFunction<String, String, Optional<PlanCredentials>> keys;
    private final NameIdOmissionPreparationFile preparations;

    public NameIdOmissionConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, BiFunction<String, String, Optional<PlanCredentials>> keys, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.keys = Objects.requireNonNull(keys);
        preparations = new NameIdOmissionPreparationFile(directory);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported NameID omission case");
    }
    public static boolean supports(String id) {
        return NameIdOmissionComparison.CASE_ID.equals(id);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public String instructionEn() {
        return "Record normal signed SSO, disable NameID generation using the target's native configuration, "
                + "then repeat SSO with the same relying party and fixed login inputs. Restore the native configuration. "
                + "Confirm preparation only after the original exchanges and configuration changes are bound; "
                + "confirmation alone does not establish conformance.";
    }
    @Override public String evidenceCampaignId() { return "nameid-omission-comparison"; }
    @Override public String evidenceCampaignTitle() { return "NameID generation and omission"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.CONFIGURATION;
    }
    @Override public List<String> evidenceActionKeys() {
        return List.of();
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed) {
            var outcome = observe(context);
            if (outcome.outcome() == Outcome.SATISFIED) {
                var details = new LinkedHashMap<String, Object>(outcome.details());
                details.put("configuration_confirmed", true);
                details.put("preparation_source", "local-native-adapter");
                return new CaseStep.Finish(new CaseOutcome(outcome.outcome(), outcome.notVerifiedReason(),
                        outcome.reasonCode(), outcome.reasonMessageKey(), outcome.evidence(), details));
            }
        }
        return fallback.resume(context, state, event);
    }
    CaseOutcome observe(CaseContext context) {
        try {
            var target = metadata.apply(context.runId());
            var preparation = preparations.read(context, target, content);
            if (preparation.isEmpty()) {
                return NameIdOmissionComparison.evaluate(List.of(), List.of("verified_preparation_unavailable"));
            }
            var exchanges = preparation.orElseThrow().exchanges().stream().map(e ->
                    new NameIdOmissionProtocolEvidence.Exchange(e.condition(), e.metadataReference(),
                            e.requestReference(), e.responseReference())).toList();
            var protocol = NameIdOmissionProtocolEvidence.collect(context, content, target, keys, exchanges);
            return NameIdOmissionExperimentBinding.evaluate(protocol, preparation);
        } catch (Exception unproven) {
            return NameIdOmissionComparison.evaluate(List.of(), List.of("native_preparation_or_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var details = new LinkedHashMap<String, Object>(outcome.details());
        details.put("configuration_confirmation_required", true);
        return new EvidenceStatus(outcome.outcome() == Outcome.SATISFIED, evidenceActionKeys(), List.of(), details);
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("attestation.interaction-disallowed", "configuration.nameid-omission.evidence-incomplete")
                    .contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous)) return Optional.empty();
        var next = observe(context);
        var details = new LinkedHashMap<String, Object>(next.details());
        details.put("preparation_source", "local-native-adapter");
        details.put("recorded_evidence_rechecked", true);
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous,
                new CaseOutcome(next.outcome(), next.notVerifiedReason(), next.reasonCode(), next.reasonMessageKey(), next.evidence(), details));
    }

}
