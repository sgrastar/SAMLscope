package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.crypto.PlanCredentials;
import java.nio.file.Path;
import java.util.*;
import java.util.function.*;

/** Native SLO observation for the approved ATTESTED case; its identity and manual fallback are preserved. */
public final class SloRegisteredSignerObservationTestCase implements TestCase,AttestationPrompt,
        BrowserFrontChannelScenario,FallbackEvidenceCase,ProtocolEvidenceCase,RecordedEvidenceReevaluation {
    private static final Set<Outcome> CONCLUSIVE=Set.of(Outcome.SATISFIED,Outcome.SATISFIED_WITH_NOTE,Outcome.VIOLATED);
    private final TestCase fallback;private final SloRegisteredSignerEvidence reader;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    public SloRegisteredSignerObservationTestCase(TestCase fallback,Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys){
        this(fallback,directory,content,metadata,keys,SloRegisteredSignerNativeAdapters.create(content));
    }
    public SloRegisteredSignerObservationTestCase(TestCase fallback,Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,SloRegisteredSignerNativeAdapter... adapters){
        this(fallback,directory,content,metadata,keys,false,adapters);
    }
    SloRegisteredSignerObservationTestCase(TestCase fallback,Path directory,TranscriptContentReader content,
            Function<String,byte[]> metadata,BiFunction<String,String,Optional<PlanCredentials>> keys,
            boolean offlineCalibrationPermission,SloRegisteredSignerNativeAdapter... adapters){
        if(!SloRegisteredSignerEvidence.CASE.equals(fallback.id())||!(fallback instanceof AttestationPrompt))throw new IllegalArgumentException("Approved SLO signer attestation required");
        this.fallback=Objects.requireNonNull(fallback);this.keys=Objects.requireNonNull(keys);
        reader=new SloRegisteredSignerEvidence(directory,content,metadata,keys,offlineCalibrationPermission,adapters);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    @Override public String evidenceCampaignId(){return SloRegisteredSignerEvidence.CAMPAIGN;}
    @Override public String evidenceCampaignTitle(){return "SLO Issuer and registered signer";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.SELF_CHECK;}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution){
        if(execution!=null&&execution.status()==CaseExecutionStatus.FINISHED&&execution.outcome()!=null&&CONCLUSIVE.contains(execution.outcome().outcome()))return RunCampaignQuery.ActionKind.NONE;
        if(execution!=null&&execution.state()!=null&&execution.state().phase().startsWith("await-fixture-"))return RunCampaignQuery.ActionKind.LOGIN;
        return nativeRecorded(execution)?RunCampaignQuery.ActionKind.CONFIGURATION:RunCampaignQuery.ActionKind.SELF_CHECK;
    }
    @Override public String instructionsEn(CaseState state){return state!=null&&state.phase().equals("await-fixture-local-normal")
            ?"Complete the own-signer control with the same authenticated browser. This final control ends the test session; later session tests may need recovery."
            :"Reuse the authenticated test browser for this SLO signature control. The administrator prepares both native peers and restores them. Do not log in again solely to establish signer identity.";}
    @Override public CaseStep start(CaseContext c){
        if(!reader.exists(c.runId()))return fallback.start(c);
        if(reader.hasFinalProof(c.runId()))return finish(c);
        try{return mark(c,scenario(c).start(c));}catch(RuntimeException unprepared){return new CaseStep.Finish(reader.pending(c.runId(),"native-slo-session-or-preparation-unproven"));}
    }
    @Override public CaseStep resume(CaseContext c,CaseState state,CaseEvent event){
        if(!reader.exists(c.runId()))return fallback.resume(c,state,event);
        if(reader.hasFinalProof(c.runId()))return finish(c);
        if(!state.phase().startsWith("await-fixture-"))return new CaseStep.Finish(reader.pending(c.runId(),"native-slo-session-or-preparation-unproven"));
        try{var next=scenario(c).resume(c,state,event);return next instanceof CaseStep.Finish?new CaseStep.Finish(reader.pending(c.runId(),"native-slo-controls-await-originals")):mark(c,next);}
        catch(RuntimeException unproven){return new CaseStep.Finish(reader.pending(c.runId(),"native-slo-controls-unproven"));}
    }
    private CaseStep finish(CaseContext c){return new CaseStep.Finish(reader.evaluate(c).orElseGet(()->reader.pending(c.runId(),"native-slo-originals-unproven")));}
    private CaseStep mark(CaseContext c,CaseStep step){if(step instanceof CaseStep.AwaitInbound value){var state=new HashMap<String,Object>(value.next().data());
        state.put("case_id",id());state.put("native_run_id",c.runId());state.put("native_receipt_owned",true);state.put("normal_control_ends_session",true);
        return new CaseStep.AwaitInbound(new CaseState(value.next().phase(),state),value.actions(),value.matcher(),value.ttl());}return step;}
    private FixtureScenarioTestCase scenario(CaseContext c){
        var input=reader.probeInputs(c).orElseThrow();var own=keys.apply(input.localRunId(),"primary").orElseThrow();var other=keys.apply(input.otherRunId(),"primary").orElseThrow();
        var fixtures=new ArrayList<ScenarioFixture>();for(var id:SloRegisteredSignerComparison.FIXTURES)fixtures.add(new Probe(id,input,own,other));String reason="slo.signer.native-unproven";
        return new FixtureScenarioTestCase(id(),TargetRole.IDP,fixtures,value->value.targetRole()==TargetRole.IDP,
                new FixtureScenarioTestCase.Vocabulary(reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason));
    }
    private record Probe(String id,SloRegisteredSignerProbeInputs input,PlanCredentials own,PlanCredentials other) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context,String action){String requestId="_"+action;
            return new Prepared(new OutboundAction(action,OutboundKind.LOGOUT_REQUEST,SloRegisteredSignerFixtures.build(id,requestId,context.clock().instant(),input,own,other),input.destination(),false),requestId);}
        @Override public FixtureObservation observe(String correlation,byte[] response){return FixtureObservation.NOT_VERIFIED;}
        @Override public String definitionKey(){return "native-slo-registered-signer-v1|"+id+"|"+input.preparationSha256()+"|"+input.localRunId()+"|"+input.otherRunId();}
    }
    private boolean nativeRecorded(CaseExecution e){if(e==null)return false;var data=e.outcome()!=null?e.outcome().details():e.state()!=null?e.state().data():Map.<String,Object>of();
        return id().equals(data.get("case_id"))&&e.runId().equals(data.get("native_run_id"))&&Boolean.TRUE.equals(data.get("native_receipt_owned"));}
    @Override public boolean resolvedFromExternalEvidence(CaseExecution e){return nativeRecorded(e)&&e.outcome()!=null&&CONCLUSIVE.contains(e.outcome().outcome())
            &&e.outcome().evidence().stream().anyMatch(ref->SloRegisteredSignerEvidence.KIND.equals(ref.kind())&&ref.reference().matches(java.util.regex.Pattern.quote(e.runId())+"/manifest\\.json#[0-9a-f]{64}"));}
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution e){return nativeRecorded(e)?RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED:
            fallback instanceof FallbackEvidenceCase legacy?legacy.evidenceClass(e):RunCampaignQuery.EvidenceClass.SELF_ATTESTED;}
    @Override public EvidenceStatus evidenceStatus(CaseContext c){
        if(!reader.exists(c.runId()))return fallback instanceof ProtocolEvidenceCase legacy?legacy.evidenceStatus(c):new EvidenceStatus(false,SloRegisteredSignerComparison.FIXTURES,List.of(),Map.of());
        var o=reader.evaluate(c).orElseThrow();boolean ready=CONCLUSIVE.contains(o.outcome());return new EvidenceStatus(ready,SloRegisteredSignerComparison.FIXTURES,ready?SloRegisteredSignerComparison.FIXTURES:List.of(),o.details());
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){
        if(!reader.exists(c.runId()))return fallback instanceof RecordedEvidenceReevaluation legacy?legacy.reevaluateRecordedEvidence(c,previous):Optional.empty();
        return supportsRecordedEvidenceReevaluation(previous)?reader.evaluate(c).flatMap(o->RecordedEvidenceReevaluation.conclusiveUpdate(previous,o)):Optional.empty();
    }
}
