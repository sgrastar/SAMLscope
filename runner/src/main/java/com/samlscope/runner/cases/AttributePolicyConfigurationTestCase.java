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
        ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String, byte[]> metadata;
    private final BiFunction<String, String, Optional<PlanCredentials>> keys;
    private final AttributePolicyPreparationFile preparations;

    public AttributePolicyConfigurationTestCase(TestCase fallback, TranscriptContentReader content,
            Function<String, byte[]> metadata, BiFunction<String, String, Optional<PlanCredentials>> keys, Path directory) {
        this.fallback = Objects.requireNonNull(fallback); this.content = Objects.requireNonNull(content);
        this.metadata = Objects.requireNonNull(metadata); this.keys = Objects.requireNonNull(keys);
        preparations = new AttributePolicyPreparationFile(directory);
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
            var protocol = AttributePolicyProtocolEvidence.collect(context, content, target, keys);
            return AttributePolicyExperimentBinding.evaluate(id(), protocol, preparations.read(context, target, content, protocol));
        } catch (Exception unproven) {
            return AttributePolicyComparison.evaluate(id(), List.of(), List.of("native_preparation_or_evidence_unproven"));
        }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var details = new LinkedHashMap<String, Object>(outcome.details());
        details.put("configuration_confirmation_required", true);
        return new EvidenceStatus(false, evidenceActionKeys(), List.of(), details);
    }
}
