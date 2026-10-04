package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;
import java.util.function.*;

/** Observed native proof, retaining the original approved attestation fallback. No new sends. */
public final class SelfContainedMetadataTrustEvidenceTestCase implements TestCase,AttestationPrompt,
        EvidenceCampaignCase,FallbackEvidenceCase,ProtocolEvidenceCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;private final Predicate<String> owned;private final Function<CaseContext,CaseOutcome> observer;
    private final String adapter,evidenceKind,evidencePrefix;
    private final boolean offlineCalibrationAllowed;
    public SelfContainedMetadataTrustEvidenceTestCase(TestCase fallback,Predicate<String> owned,
            Function<CaseContext,CaseOutcome> observer,String adapter,String evidenceKind,String evidencePrefix){
        this(fallback,owned,observer,adapter,evidenceKind,evidencePrefix,false);
    }
    /** Developer-only wrapper calibration; registry callers use the public stock-only constructor. */
    SelfContainedMetadataTrustEvidenceTestCase(TestCase fallback,Predicate<String> owned,Function<CaseContext,CaseOutcome> observer,
            String adapter,String evidenceKind,String evidencePrefix,boolean offlineCalibrationAllowed){
        this.offlineCalibrationAllowed=offlineCalibrationAllowed;
        if(!SimpleSamlPhpSelfContainedTrustEvidenceFile.ID.equals(fallback.id())||!(fallback instanceof AttestationPrompt))throw new IllegalArgumentException("Approved metadata trust attestation required");
        this.fallback=Objects.requireNonNull(fallback);this.owned=Objects.requireNonNull(owned);this.observer=Objects.requireNonNull(observer);
        this.adapter=Objects.requireNonNull(adapter);this.evidenceKind=Objects.requireNonNull(evidenceKind);this.evidencePrefix=Objects.requireNonNull(evidencePrefix);
    }
    @Override public String id(){return fallback.id();}@Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}@Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    @Override public String evidenceCampaignId(){return "native-metadata-trust";}@Override public String evidenceCampaignTitle(){return "Native metadata signature and encryption trust observation";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.NONE;}
    @Override public List<String> evidenceActionKeys(){return List.of();}
    private Optional<CaseOutcome> observe(CaseContext context){
        if(!owned.test(context.runId()))return Optional.empty();CaseOutcome result;
        try{result=context.transcriptComplete()?observer.apply(context):null;}catch(RuntimeException invalid){result=null;}
        if(result!=null&&result.outcome()!=Outcome.NOT_VERIFIED&&(!Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(result.outcome())
                ||(!offlineCalibrationAllowed&&!Boolean.FALSE.equals(result.details().get("counterfactual_calibration_only")))
                ||!adapter.equals(result.details().get("evidence_adapter"))||!context.runId().equals(result.details().get("run_id"))
                ||result.evidence().stream().noneMatch(r->evidenceKind.equals(r.kind())&&r.reference().startsWith(context.runId()+evidencePrefix))))result=null;
        if(result==null)result=CaseOutcome.notVerified("native_metadata_trust_unproven","metadata.trust.native-evidence-incomplete");
        return Optional.of(result);
    }
    @Override public CaseStep start(CaseContext c){return observe(c).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(c));}
    @Override public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){return observe(c).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.resume(c,state,event));}
    @Override public EvidenceStatus evidenceStatus(CaseContext c){if(!owned.test(c.runId())&&fallback instanceof ProtocolEvidenceCase protocol)return protocol.evidenceStatus(c);var outcome=observe(c);boolean ready=outcome.map(v->Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(v.outcome())).orElse(false);return new EvidenceStatus(ready,List.of("native-signature-encryption-trust"),ready?List.of("native-signature-encryption-trust"):List.of(),outcome.map(CaseOutcome::details).orElse(Map.of()));}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return (previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED)||(fallback instanceof RecordedEvidenceReevaluation recorded&&recorded.supportsRecordedEvidenceReevaluation(previous));}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){if(!owned.test(c.runId())&&fallback instanceof RecordedEvidenceReevaluation recorded)return recorded.reevaluateRecordedEvidence(c,previous);return supportsRecordedEvidenceReevaluation(previous)?observe(c).flatMap(next->RecordedEvidenceReevaluation.conclusiveUpdate(previous,next)):Optional.empty();}
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution e){if(e!=null&&!owned.test(e.runId())&&fallback instanceof FallbackEvidenceCase observed)return observed.evidenceClass(e);return FallbackEvidenceCase.super.evidenceClass(e);}
    @Override public boolean resolvedFromExternalEvidence(CaseExecution e){if(e!=null&&!owned.test(e.runId())&&fallback instanceof FallbackEvidenceCase observed)return observed.resolvedFromExternalEvidence(e);return e!=null&&id().equals(e.caseId())&&e.outcome()!=null
            &&e.outcome().outcome()==Outcome.SATISFIED&&adapter.equals(e.outcome().details().get("evidence_adapter"))
            &&e.runId().equals(e.outcome().details().get("run_id"))&&!Boolean.TRUE.equals(e.outcome().details().get("counterfactual_calibration_only"))
            &&e.outcome().evidence().stream().anyMatch(r->evidenceKind.equals(r.kind())&&r.reference().startsWith(e.runId()+evidencePrefix));}
}
