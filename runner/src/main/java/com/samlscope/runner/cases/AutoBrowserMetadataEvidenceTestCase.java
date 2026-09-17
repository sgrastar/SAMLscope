package com.samlscope.runner.cases;

import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.FallbackEvidenceCase;
import com.samlscope.runner.RunCampaignQuery;

/** Uses conclusive target metadata first and preserves the approved browser interaction as fallback. */
public final class AutoBrowserMetadataEvidenceTestCase
        implements TestCase, EvidenceCampaignCase, FallbackEvidenceCase {
    private final TestCase fallback;
    private final Function<String, byte[]> targetMetadata;
    private final Function<String, java.util.Optional<String>> entityIds;

    public AutoBrowserMetadataEvidenceTestCase(
            TestCase fallback, Function<String, byte[]> targetMetadata,
            Function<String, java.util.Optional<String>> entityIds) {
        this.fallback = Objects.requireNonNull(fallback, "fallback");
        this.entityIds = Objects.requireNonNull(entityIds, "entityIds");
        this.targetMetadata = Objects.requireNonNull(targetMetadata, "targetMetadata");
        if (!TargetMetadataObservation.supports(fallback.id())) {
            throw new IllegalArgumentException("No approved target-metadata fallback for " + fallback.id());
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String evidenceCampaignId() { return "target-metadata-inspection"; }
    @Override public String evidenceCampaignTitle() { return "Passive target metadata inspection"; }
    @Override public RunCampaignQuery.ActionKind evidenceActionKind() {
        return RunCampaignQuery.ActionKind.NONE;
    }

    @Override
    public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution.outcome() != null && execution.outcome().evidence().stream()
                .anyMatch(value -> "target-metadata".equals(value.kind()));
    }

    @Override
    public CaseStep start(CaseContext context) {
        byte[] metadata;
        try {
            metadata = targetMetadata.apply(context.runId());
            var entityId = entityIds.apply(context.runId()).orElse(null);
            if (metadata == null || entityId == null || entityId.isBlank()) return fallback.start(context);
            var root = com.samlscope.saml.normal.SecureXml.parse(metadata).getDocumentElement();
            // Aggregate selection needs its own provenance; never grade another entity's role.
            if (!"urn:oasis:names:tc:SAML:2.0:metadata".equals(root.getNamespaceURI())
                    || !"EntityDescriptor".equals(root.getLocalName())
                    || !entityId.equals(root.getAttribute("entityID"))) return fallback.start(context);
        }
        catch (RuntimeException unavailable) { metadata = null; }
        var outcome = TargetMetadataObservation.evaluate(id(), metadata, context.clock().instant());
        return outcome.<CaseStep>map(CaseStep.Finish::new).orElseGet(() -> fallback.start(context));
    }

    @Override
    public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        return fallback.resume(context, state, event);
    }
}
