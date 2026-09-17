package com.samlscope.runner.cases;

import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

/** Requires confirmation of native fixture preparation; never asks the operator to supply a Verdict. */
public final class MetadataAlgorithmConfigurationTestCase implements TestCase,ConfigurationPrompt,ProtocolEvidenceCase,com.samlscope.runner.EvidenceCampaignCase {
    private final TestCase fallback;
    private final TranscriptContentReader content;
    private final Function<String,byte[]> metadata;
    public MetadataAlgorithmConfigurationTestCase(TestCase fallback,TranscriptContentReader content,Function<String,byte[]> metadata) {
        this.fallback=Objects.requireNonNull(fallback);this.content=Objects.requireNonNull(content);this.metadata=Objects.requireNonNull(metadata);
        if(!supports(fallback.id()))throw new IllegalArgumentException("Unsupported metadata algorithm case");
    }
    static boolean supports(String id) { return MetadataAlgorithmSelection.ORDER.equals(id)||MetadataAlgorithmSelection.ROLE.equals(id); }
    @Override public boolean requiresPreparationConfirmation() { return true; }
    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() {
        return "Import the original metadata fixtures through the target's own metadata path and perform the correlated SSO for each fixture. "
            +"Confirm only after this preparation was completed; confirmation does not supply a conformance outcome. Required fixtures: "+String.join(", ",evidenceActionKeys());
    }
    @Override public String evidenceCampaignId() { return "metadata-fixture-refresh"; }
    @Override public String evidenceCampaignTitle() { return "Metadata fixture consumption and signed algorithm selection"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() { return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH; }
    @Override public List<String> evidenceActionKeys() { return MetadataAlgorithmSelection.required(id()); }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event) {
        if(event instanceof CaseEvent.ConfigConfirmed) {
            var outcome=observe(context);var details=new LinkedHashMap<String,Object>(outcome.details());
            details.put("configuration_confirmed",true);
            return new CaseStep.Finish(new CaseOutcome(outcome.outcome(),outcome.notVerifiedReason(),outcome.reasonCode(),outcome.reasonMessageKey(),outcome.evidence(),details));
        }
        return fallback.resume(context,state,event);
    }
    private CaseOutcome observe(CaseContext context) {
        try { return MetadataAlgorithmEvidence.observe(id(),context,content,metadata.apply(context.runId())); }
        catch(RuntimeException unavailable) { return MetadataAlgorithmSelection.evaluate(id(),List.of(),List.of("target_metadata_unavailable")); }
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome=observe(context);var details=new LinkedHashMap<String,Object>(outcome.details());
        details.put("configuration_confirmation_required",true);
        // The caller must confirm real native preparation, not merely that a metadata URL was fetched.
        return new EvidenceStatus(false,evidenceActionKeys(),List.of(),details);
    }
}
