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
public final class AttributePolicyConfigurationTestCase implements TestCase, ConfigurationPrompt,
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final BiFunction<String, String, Optional<PlanCredentials>> keys;
    private final AttributePolicyPreparationFile preparations;
    private final SimpleSamlPhpAttributeServiceIndexEvidence nativeIndex;

    public AttributePolicyConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, BiFunction<String, String, Optional<PlanCredentials>> keys, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.keys = Objects.requireNonNull(keys);
        preparations = new AttributePolicyPreparationFile(directory);
        nativeIndex = new SimpleSamlPhpAttributeServiceIndexEvidence(
                directory.resolveSibling("attribute-service-index-evidence"), content, metadata, keys);
        if (!supports(fallback.id())) throw new IllegalArgumentException("Unsupported attribute policy case");
    }
    public static boolean supports(String id) {
        return Set.of(AttributePolicyComparison.ENTITY, AttributePolicyComparison.REQUESTED, AttributePolicyComparison.INDEX).contains(id);
    }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public String instructionEn() {
        return "Keep the attribute-release policy and login inputs fixed while exercising the metadata conditions. "
                + "Use the target's own metadata import path. Confirm preparation after all conditions are recorded; "
                + "confirmation alone does not establish conformance.";
    }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Fixed-policy attribute release comparisons"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;
    }
    @Override public List<String> evidenceActionKeys() {
        return switch (id()) {
            case AttributePolicyComparison.ENTITY -> List.of("control", "attribute-policy-entity-present", "attribute-policy-entity-absent");
            case AttributePolicyComparison.REQUESTED -> List.of("control", "attribute-policy-requested-required", "attribute-policy-requested-optional", "attribute-policy-requested-absent");
            default -> List.of("control", "attribute-policy-indexed");
        };
    }
    private Optional<CaseOutcome> nativeObservation(CaseContext context) {
        if (!AttributePolicyComparison.INDEX.equals(id()) || !nativeIndex.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete()) return Optional.of(nativeUnproven());
        try {
            return Optional.of(nativeIndex.evaluate(context).orElseGet(AttributePolicyConfigurationTestCase::nativeUnproven));
        } catch (RuntimeException unavailable) {
            return Optional.of(nativeUnproven());
        }
    }
    private static CaseOutcome nativeUnproven() {
        return CaseOutcome.notVerified("native_attribute_index_originals_unproven", "browser.attribute-index.native-unproven");
    }
    @Override public CaseStep start(CaseContext context) {
        return nativeObservation(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var nativeOutcome = nativeObservation(context);
        if (nativeOutcome.isPresent()) return new CaseStep.Finish(nativeOutcome.orElseThrow());
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
        var nativeOutcome = nativeObservation(context);
        if (nativeOutcome.isPresent()) return nativeOutcome.orElseThrow();
        try {
            var target = metadata.apply(context.runId());
            var protocol = AttributePolicyProtocolEvidence.collect(context, content, target, keys);
            return AttributePolicyExperimentBinding.evaluate(id(), protocol, preparations.read(context, target, content, protocol));
        } catch (Exception unproven) {
            return AttributePolicyComparison.evaluate(id(), List.of(), List.of("native_preparation_or_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var details = new LinkedHashMap<String, Object>(outcome.details());
        boolean nativeOwned = AttributePolicyComparison.INDEX.equals(id()) && nativeIndex.exists(context.runId());
        details.put("configuration_confirmation_required", !nativeOwned);
        boolean ready = outcome.outcome() == Outcome.SATISFIED || nativeOwned && outcome.outcome() == Outcome.VIOLATED;
        return new EvidenceStatus(ready, evidenceActionKeys(), ready ? evidenceActionKeys() : List.of(), details);
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous != null && previous.outcome() == Outcome.NOT_VERIFIED
                && Set.of("attestation.interaction-disallowed", "configuration.attribute-policy.evidence-incomplete",
                        "case.pending-interaction", "browser.attribute-index.native-unproven")
                    .contains(String.valueOf(previous.reasonCode()));
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        if (!supportsRecordedEvidenceReevaluation(previous) || !context.transcriptComplete()) return Optional.empty();
        var nativeOutcome = nativeObservation(context);
        if (nativeOutcome.isPresent()) {
            return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous, nativeOutcome.orElseThrow());
        }
        var next = observe(context);
        var details = new LinkedHashMap<String, Object>(next.details());
        details.put("preparation_source", "local-native-adapter");
        details.put("recorded_evidence_rechecked", true);
        return com.samlscope.runner.RecordedEvidenceReevaluation.conclusiveUpdate(previous,
                new CaseOutcome(next.outcome(), next.notVerifiedReason(), next.reasonCode(),
                        next.reasonMessageKey(), next.evidence(), details));
    }
}
