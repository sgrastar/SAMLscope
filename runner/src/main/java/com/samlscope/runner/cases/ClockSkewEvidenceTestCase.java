package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;
import java.util.function.Function;

/** Preserve the approved BROWSER case, but do not repeat logins to fill missing clock policies. */
public final class ClockSkewEvidenceTestCase implements InteractionFreeEvidenceCase,
        EvidenceCampaignCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final Function<CaseContext,Optional<CaseOutcome>> observer;
    private final boolean offlineCalibrationAllowed;
    public ClockSkewEvidenceTestCase(TestCase fallback,ClockSkewEvidence evidence) {
        this(fallback,Objects.requireNonNull(evidence)::evaluate,false);
    }
    /** Only developer replay may opt in; production registry uses the public constructor. */
    ClockSkewEvidenceTestCase(TestCase fallback,Function<CaseContext,Optional<CaseOutcome>> observer,
            boolean offlineCalibrationAllowed) {
        this.fallback=Objects.requireNonNull(fallback);this.observer=Objects.requireNonNull(observer);
        this.offlineCalibrationAllowed=offlineCalibrationAllowed;
        if(!ClockSkewEvidence.CASE.equals(fallback.id())||fallback.role()!=TargetRole.IDP)
            throw new IllegalArgumentException("Approved IdP clock case required");
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String evidenceCampaignId(){return ClockSkewEvidence.CAMPAIGN;}
    @Override public String evidenceCampaignTitle(){return "Target clock-tolerance consumer evidence";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.NONE;}
    @Override public List<String> evidenceActionKeys(){return List.of();}
    private CaseOutcome observe(CaseContext context) {
        if(!context.transcriptComplete())return ClockSkewComparison.missing("history_incomplete",List.of());
        try {
            var result=observer.apply(context).orElse(null);
            if(result==null)return ClockSkewComparison.missing("target_clock_originals_unavailable",List.of());
            if(result.outcome()==Outcome.NOT_VERIFIED)return result;
            if(!Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(result.outcome())
                    ||!context.runId().equals(result.details().get("run_id"))
                    ||!(result.details().get("evidence_adapter") instanceof String adapter)||adapter.isBlank()
                    ||(!offlineCalibrationAllowed&&!Boolean.FALSE.equals(result.details().get("counterfactual_calibration_only")))
                    ||result.evidence().stream().noneMatch(r->"clock-skew-native-evidence".equals(r.kind())
                    &&r.reference().startsWith(context.runId()+"/manifest.json#sha256=")))
                return ClockSkewComparison.missing("clock_provenance_unproven",List.of());
            return result;
        } catch(RuntimeException malformed) {
            return ClockSkewComparison.missing("clock_originals_invalid",List.of());
        }
    }
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context){return observe(context);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var result=observe(context);boolean ready=Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(result.outcome());
        var completed=new ArrayList<String>();
        if(result.details().get("completed_observations") instanceof List<?> list)
            for(var value:list)if(value instanceof String s&&ClockSkewComparison.REQUIRED.contains(s))completed.add(s);
        return new EvidenceStatus(ready,ClockSkewComparison.REQUIRED,completed,result.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous) {
        if(!context.transcriptComplete()||!supportsRecordedEvidenceReevaluation(previous))return Optional.empty();
        return RecordedEvidenceReevaluation.conclusiveUpdate(previous,observe(context));
    }
}
