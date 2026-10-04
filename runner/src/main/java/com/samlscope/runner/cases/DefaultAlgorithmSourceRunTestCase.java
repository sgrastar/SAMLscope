package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;

/** Preserves the original scenario; an owned invalid source binding remains NOT_VERIFIED. */
public final class DefaultAlgorithmSourceRunTestCase implements TestCase,BrowserFrontChannelScenario,
        ConfigurationPrompt,AttestationPrompt,QueuedProtocolEvidenceCase,RecordedEvidenceReevaluation,FallbackEvidenceCase {
    private final TestCase fallback; private final DefaultAlgorithmSourceRunEvidence evidence;
    public DefaultAlgorithmSourceRunTestCase(TestCase fallback,DefaultAlgorithmSourceRunEvidence evidence) {
        this.fallback=Objects.requireNonNull(fallback);this.evidence=Objects.requireNonNull(evidence);
        if(!DefaultAlgorithmComparison.CASE.equals(fallback.id())||fallback.role()!=TargetRole.IDP
                ||!(fallback instanceof BrowserFrontChannelScenario)||!(fallback instanceof AttestationPrompt)
                ||!(fallback instanceof ConfigurationPrompt)||!(fallback instanceof ProtocolEvidenceCase)||!(fallback instanceof FallbackEvidenceCase))
            throw new IllegalArgumentException("Whole approved default-algorithm scenario required");
    }
    public String id(){return fallback.id();}public TargetRole role(){return fallback.role();}
    private CaseOutcome observed(CaseContext c){return evidence.evaluate(c).orElseGet(()->DefaultAlgorithmComparison.missing("source_run_default_algorithm_binding_unproven",List.of()));}
    public CaseStep start(CaseContext c){return evidence.exists(c.runId())?new CaseStep.Finish(observed(c)):fallback.start(c);}
    public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return evidence.exists(c.runId())?new CaseStep.Finish(observed(c)):fallback.resume(c,s,e);}
    public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    public String instructionEn(){return ((ConfigurationPrompt)fallback).instructionEn();}
    public String instructionsEn(CaseState state){return ((BrowserFrontChannelScenario)fallback).instructionsEn(state);}
    public Binding outboundBinding(CaseState state){return ((BrowserFrontChannelScenario)fallback).outboundBinding(state);}
    public boolean requiresFreshSession(CaseState state){return ((BrowserFrontChannelScenario)fallback).requiresFreshSession(state);}
    public boolean plansFreshSessionBoundary(){return ((BrowserFrontChannelScenario)fallback).plansFreshSessionBoundary();}
    public int plannedDeliberateActions(){return ((BrowserFrontChannelScenario)fallback).plannedDeliberateActions();}
    public String evidenceCampaignId(){return ((BrowserFrontChannelScenario)fallback).evidenceCampaignId();}
    public String evidenceCampaignTitle(){return ((BrowserFrontChannelScenario)fallback).evidenceCampaignTitle();}
    public List<String> evidenceActionKeys(){return ((BrowserFrontChannelScenario)fallback).evidenceActionKeys();}
    public RunCampaignQuery.ActionKind evidenceActionKind(){return ((BrowserFrontChannelScenario)fallback).evidenceActionKind();}
    public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution e){return ((BrowserFrontChannelScenario)fallback).evidenceActionKind(e);}
    public boolean requiresPreparationConfirmation(){return ((ProtocolEvidenceCase)fallback).requiresPreparationConfirmation();}
    public EvidenceStatus evidenceStatus(CaseContext c){
        if(!evidence.exists(c.runId()))return ((ProtocolEvidenceCase)fallback).evidenceStatus(c);
        var outcome=observed(c);boolean ready=Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(outcome.outcome());
        return new EvidenceStatus(ready,DefaultAlgorithmComparison.REQUIRED,ready?DefaultAlgorithmComparison.REQUIRED:List.of(),outcome.details());
    }
    /** Only an explicitly owned, fully verified source binding may finish a never-dispatched queue. */
    public CaseOutcome queuedEvidenceOutcome(CaseContext c){return evidence.exists(c.runId())?observed(c)
            :DefaultAlgorithmComparison.missing("source_run_default_algorithm_binding_unavailable",List.of());}
    public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){
        if(evidence.exists(c.runId()))return supportsRecordedEvidenceReevaluation(previous)&&c.transcriptComplete()
                ?RecordedEvidenceReevaluation.conclusiveUpdate(previous,observed(c)):Optional.empty();
        return fallback instanceof RecordedEvidenceReevaluation reader?reader.reevaluateRecordedEvidence(c,previous):Optional.empty();
    }
    public boolean resolvedFromExternalEvidence(CaseExecution execution){return execution!=null&&id().equals(execution.caseId())&&execution.outcome()!=null
            &&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(execution.outcome().outcome())
            &&Boolean.FALSE.equals(execution.outcome().details().get("ecp_protocol_traffic_verified"))
            &&execution.outcome().evidence().stream().anyMatch(r->"default-algorithm-source-run-evidence".equals(r.kind())&&r.reference().startsWith(execution.runId()+"/manifest.json#sha256="))
            ||fallback instanceof FallbackEvidenceCase reader&&reader.resolvedFromExternalEvidence(execution);}
    public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution){return resolvedFromExternalEvidence(execution)
            ?RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED:((FallbackEvidenceCase)fallback).evidenceClass(execution);}
}
