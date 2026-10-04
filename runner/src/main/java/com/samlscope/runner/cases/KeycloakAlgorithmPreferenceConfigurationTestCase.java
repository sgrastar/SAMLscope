package com.samlscope.runner.cases;

import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.RecordedEvidenceReevaluation;

/** Optional native preference campaign; preserves every other product's approved fallback. */
final class KeycloakAlgorithmPreferenceConfigurationTestCase implements TestCase,ConfigurationPrompt,
        ProtocolEvidenceCase,com.samlscope.runner.EvidenceCampaignCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final Function<String,byte[]> metadata;
    private final KeycloakAlgorithmPreferenceEvidenceFile evidence;
    KeycloakAlgorithmPreferenceConfigurationTestCase(TestCase fallback,TranscriptContentReader content,
            Function<String,byte[]> metadata,Path directory) {
        this.fallback=Objects.requireNonNull(fallback);this.metadata=Objects.requireNonNull(metadata);
        this.evidence=new KeycloakAlgorithmPreferenceEvidenceFile(directory,content);
        if(!KeycloakAlgorithmPreferenceEvidenceFile.CASES.contains(fallback.id()))throw new IllegalArgumentException();
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String instructionEn(){return ((ConfigurationPrompt)fallback).instructionEn()
        +". The optional native default-selector campaign uses explicit SHA256/SHA512 ordering fixtures, "
        +"individual digest/signature swaps, same-policy native capability controls and verified restoration.";}
    @Override public boolean requiresPreparationConfirmation(){return true;}
    @Override public String evidenceCampaignId(){return "metadata-fixture-refresh";}
    @Override public String evidenceCampaignTitle(){return "Native metadata algorithm preference";}
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind(){return com.samlscope.runner.RunCampaignQuery.ActionKind.METADATA_REFRESH;}
    @Override public List<String> evidenceActionKeys(){return ((com.samlscope.runner.EvidenceCampaignCase)fallback).evidenceActionKeys();}
    @Override public CaseStep start(CaseContext context){return fallback.start(context);}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(event instanceof CaseEvent.ConfigConfirmed&&evidence.exists(context.runId()))return new CaseStep.Finish(observe(context));
        return fallback.resume(context,state,event);
    }
    private CaseOutcome observe(CaseContext context){
        var result=evidence.evaluate(id(),context,metadata.apply(context.runId()));var details=new LinkedHashMap<String,Object>(result.details());
        details.put("configuration_confirmed",true);
        return new CaseOutcome(result.outcome(),result.notVerifiedReason(),result.reasonCode(),result.reasonMessageKey(),result.evidence(),details);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        if(!evidence.exists(context.runId()))return ((ProtocolEvidenceCase)fallback).evidenceStatus(context);
        var result=observe(context);var details=new LinkedHashMap<String,Object>(result.details());details.put("configuration_confirmation_required",true);
        return new EvidenceStatus(false,KeycloakAlgorithmPreferenceEvidenceFile.REQUIRED,List.of(),details);
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){
        return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED&&Boolean.TRUE.equals(previous.details().get("configuration_confirmed"))
            &&Set.of("metadata.algorithms.local-policy-unverified","metadata.algorithms.evidence-incomplete",
                "metadata.algorithms.native-preference-incomplete").contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        if(supportsRecordedEvidenceReevaluation(previous)&&evidence.exists(context.runId()))return RecordedEvidenceReevaluation.conclusiveUpdate(previous,observe(context));
        return fallback instanceof RecordedEvidenceReevaluation recorded?recorded.reevaluateRecordedEvidence(context,previous):Optional.empty();
    }
}
