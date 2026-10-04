package com.samlscope.runner.cases;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;

/** Uses target metadata first and falls back to the approved CONFIG interaction when inconclusive. */
public final class AutoConfigurationEvidenceTestCase
        implements TestCase, ConfigurationPrompt, AttestationPrompt,
        com.samlscope.runner.EvidenceCampaignCase, com.samlscope.runner.FallbackEvidenceCase {
    private final TestCase fallback;
    private final Function<String, byte[]> targetMetadata;

    public AutoConfigurationEvidenceTestCase(TestCase fallback, Function<String, byte[]> targetMetadata) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.targetMetadata = Objects.requireNonNull(targetMetadata, "targetMetadata");
        if (!TargetMetadataObservation.supports(fallback.id())) {
            throw new IllegalArgumentException("No target-metadata oracle for " + fallback.id());
        }
        if (!(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("CONFIG fallback must expose both approved prompts");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String evidenceCampaignId() { return "target-metadata-inspection"; }
    @Override public String evidenceCampaignTitle() { return "Passive target metadata inspection"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.NONE;
    }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public java.util.List<AttestationOption> options() {
        return ((AttestationPrompt) fallback).options();
    }

    @Override
    public boolean resolvedFromExternalEvidence(com.samlscope.core.caseexec.CaseExecution execution) {
        return execution.outcome() != null && execution.outcome().evidence().stream()
                .anyMatch(value -> "target-metadata".equals(value.kind()));
    }

    @Override
    public CaseStep start(CaseContext context) {
        byte[] metadata;
        try { metadata = targetMetadata.apply(context.runId()); }
        catch (RuntimeException unavailable) { metadata = null; }
        var outcome = TargetMetadataObservation.evaluate(id(), metadata, context.clock().instant());
        return outcome.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        // A case already waiting before an oracle upgrade can reuse its immutable Run snapshot.
        // Configuration-unavailable and cancellation events keep their existing semantics.
        if (event instanceof CaseEvent.ConfigConfirmed) {
            byte[] metadata;
            try { metadata = targetMetadata.apply(context.runId()); }
            catch (RuntimeException unavailable) { metadata = null; }
            var outcome = TargetMetadataObservation.evaluate(id(), metadata, context.clock().instant());
            if (outcome.isPresent()) return new CaseStep.Finish(outcome.orElseThrow());
        }
        return fallback.resume(context, state, event);
    }
}
