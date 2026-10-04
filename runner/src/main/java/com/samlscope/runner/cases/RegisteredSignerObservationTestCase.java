package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.runner.*;
import com.samlscope.runner.scenario.*;
import com.samlscope.saml.crypto.PlanCredentials;
import com.samlscope.saml.normal.SamlSignedRequestFactory;
import java.nio.file.Path;
import java.util.*;
import java.util.function.*;

/** A registered peer's valid key is tested separately from mathematical signature validity.
 * Requests leave only through Runner's deterministic outbox. Native missing proof never creates
 * a target failure; the original manual attestation remains available only when this adapter owns no evidence.
 */
public final class RegisteredSignerObservationTestCase implements TestCase, AttestationPrompt,
        BrowserFrontChannelScenario, FallbackEvidenceCase, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    public static final String CASE="IIP-SSO01-al-idp-01";
    static final List<String> FIXTURES=List.of("local-normal","local-invalid-signature","local-other-signer");
    private final TestCase fallback;
    private final List<RegisteredSignerNativeEvidence> readers;
    private final BiFunction<String,String,Optional<PlanCredentials>> keys;
    public RegisteredSignerObservationTestCase(TestCase fallback,Path directory,TranscriptContentReader content,
            Function<String,byte[]> targetMetadata,BiFunction<String,String,Optional<PlanCredentials>> keys,RegisteredSignerNativeEvidence... additional) {
        if(!CASE.equals(fallback.id())||!(fallback instanceof AttestationPrompt))throw new IllegalArgumentException("No approved signer attestation fallback");
        this.fallback=Objects.requireNonNull(fallback);this.keys=Objects.requireNonNull(keys);
        var values=new ArrayList<RegisteredSignerNativeEvidence>();values.add(new KeycloakRegisteredSignerEvidence(directory,content,targetMetadata,keys));if(additional!=null)for(var value:additional)values.add(Objects.requireNonNull(value));readers=List.copyOf(values);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    @Override public String evidenceCampaignId(){return KeycloakRegisteredSignerEvidence.CAMPAIGN;}
    @Override public String evidenceCampaignTitle(){return "Registered signer and Issuer key restriction";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.SELF_CHECK;}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution execution){
        if(execution!=null&&execution.status()==CaseExecutionStatus.FINISHED&&execution.outcome()!=null&&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(execution.outcome().outcome()))return RunCampaignQuery.ActionKind.NONE;
        if(execution!=null&&execution.state()!=null&&execution.state().phase().startsWith("await-fixture-"))return RunCampaignQuery.ActionKind.LOGIN;
        return recordedNative(execution)?RunCampaignQuery.ActionKind.CONFIGURATION:RunCampaignQuery.ActionKind.SELF_CHECK;
    }
    public String instructionEn(){return "Ask the administrator to prepare two native SAML peers. Reuse one authenticated browser for normal, invalid-signature and other-peer-signer controls; additional logins do not establish signer identity.";}
    @Override public String instructionsEn(CaseState state){return "Execute this signed request with the established browser session. The administrator prepares and restores the two peer configurations.";}
    private boolean recordedNative(CaseExecution execution){
        var o=execution==null?null:execution.outcome();
        if(o==null){if(execution==null||execution.state()==null)return false;var saved=execution.state().data();return CASE.equals(saved.get("case_id"))&&execution.runId().equals(saved.get("native_run_id"))&&Boolean.TRUE.equals(saved.get("native_receipt_owned"))&&readers.stream().anyMatch(r->r.adapter().equals(saved.get("evidence_adapter")));}
        if(!CASE.equals(o.details().get("case_id"))||!execution.runId().equals(o.details().get("native_run_id"))||!Boolean.TRUE.equals(o.details().get("native_receipt_owned")))return false;
        boolean known=readers.stream().anyMatch(r->r.adapter().equals(o.details().get("evidence_adapter")))||"ambiguous-native-registered-signer".equals(o.details().get("evidence_adapter"));
        if(!known)return false;if(o.outcome()==Outcome.NOT_VERIFIED)return "signature.signer.native-unproven".equals(o.reasonCode());
        return readers.stream().anyMatch(reader->reader.adapter().equals(o.details().get("evidence_adapter"))&&o.evidence().stream().anyMatch(e->reader.evidenceKind().equals(e.kind())&&e.reference().matches(java.util.regex.Pattern.quote(execution.runId())+"/manifest\\.json#[0-9a-f]{64}")))&&o.evidence().stream().anyMatch(e->"transcript".equals(e.kind()));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution){return execution!=null&&execution.outcome()!=null&&recordedNative(execution)&&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(execution.outcome().outcome());}
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution){
        if(recordedNative(execution))return RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;
        return fallback instanceof FallbackEvidenceCase old?old.evidenceClass(execution):RunCampaignQuery.EvidenceClass.SELF_ATTESTED;
    }
    private List<RegisteredSignerNativeEvidence> owned(CaseContext c){return readers.stream().filter(r->r.exists(c.runId())).toList();}
    private Optional<CaseOutcome> observe(CaseContext context){if(!context.transcriptComplete())return owned(context).isEmpty()?Optional.empty():Optional.of(pending(context));var owners=owned(context);if(owners.isEmpty())return Optional.empty();if(owners.size()!=1)return Optional.of(pending(context));return owners.getFirst().evaluate(context);}
    private CaseOutcome pending(CaseContext context){var owners=owned(context);if(owners.size()==1)return owners.getFirst().pending(context.runId(),"native-registered-signer-campaign-incomplete");return new CaseOutcome(Outcome.NOT_VERIFIED,"ambiguous-native-registered-signer-owner","signature.signer.native-unproven","signature.signer.native-unproven",List.of(),Map.of("native_receipt_owned",true,"case_id",CASE,"native_run_id",context.runId(),"evidence_adapter","ambiguous-native-registered-signer"));}
    @Override public CaseStep start(CaseContext context){
        if(owned(context).isEmpty())return fallback.start(context);
        if(owned(context).size()!=1)return new CaseStep.Finish(pending(context));
        var o=observe(context);if(owned(context).getFirst().hasFinalProof(context.runId()))return new CaseStep.Finish(o.orElseGet(()->pending(context)));if(o.isPresent()&&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(o.orElseThrow().outcome()))return new CaseStep.Finish(o.orElseThrow());
        try{return prepared(context,scenario(context).start(context));}catch(RuntimeException missing){return new CaseStep.Finish(pending(context));}
    }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        if(owned(context).isEmpty())return fallback.resume(context,state,event);
        if(owned(context).size()!=1)return new CaseStep.Finish(pending(context));
        var o=observe(context);if(owned(context).getFirst().hasFinalProof(context.runId()))return new CaseStep.Finish(o.orElseGet(()->pending(context)));if(o.isPresent()&&Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(o.orElseThrow().outcome()))return new CaseStep.Finish(o.orElseThrow());
        if(state.phase().startsWith("await-fixture-")){try{var next=scenario(context).resume(context,state,event);return next instanceof CaseStep.Finish?new CaseStep.Finish(pending(context)):prepared(context,next);}catch(RuntimeException invalid){return new CaseStep.Finish(pending(context));}}
        return new CaseStep.Finish(pending(context));
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){var o=observe(context);boolean ready=o.map(v->Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(v.outcome())).orElse(false);return new EvidenceStatus(ready,FIXTURES,ready?FIXTURES:List.of(),o.map(CaseOutcome::details).orElse(Map.of()));}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome before){return supportsRecordedEvidenceReevaluation(before)?observe(c).flatMap(o->RecordedEvidenceReevaluation.conclusiveUpdate(before,o)):Optional.empty();}
    private CaseStep prepared(CaseContext context,CaseStep step){
        if(step instanceof CaseStep.AwaitInbound value){var owner=owned(context).getFirst();var saved=new HashMap<String,Object>(value.next().data());saved.put("evidence_adapter",owner.adapter());saved.put("native_run_id",context.runId());saved.put("case_id",CASE);saved.put("native_receipt_owned",true);return new CaseStep.AwaitInbound(new CaseState(value.next().phase(),saved),value.actions(),value.matcher(),value.ttl());}
        return step;
    }
    private FixtureScenarioTestCase scenario(CaseContext context){
        var owners=owned(context);if(owners.size()!=1)throw new IllegalArgumentException("Ambiguous native owner");var inputs=owners.getFirst().probeInputs(context).orElseThrow();var local=keys.apply(inputs.localRunId(),"primary").orElseThrow();var other=keys.apply(inputs.otherRunId(),"primary").orElseThrow();
        var fixtures=new ArrayList<ScenarioFixture>();for(String id:FIXTURES)fixtures.add(new Probe(id,inputs,id.equals("local-other-signer")?other:local,id.equals("local-invalid-signature")?SamlSignedRequestFactory.Fixture.BAD_SIGNATURE_VALUE:SamlSignedRequestFactory.Fixture.VALID));
        String reason="signature.signer.native-unproven";
        return new FixtureScenarioTestCase(id(),TargetRole.IDP,fixtures,c->c.targetRole()==TargetRole.IDP,new FixtureScenarioTestCase.Vocabulary(reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason,reason));
    }
    private record Probe(String id,RegisteredSignerProbeInputs input,PlanCredentials key,SamlSignedRequestFactory.Fixture kind) implements ScenarioFixture {
        @Override public Prepared prepare(CaseContext context,String actionId){var requestId="_"+actionId;var raw=new SamlSignedRequestFactory().build(kind,requestId,input.destination(),input.entity(),input.acs(),context.clock().instant(),key);return new Prepared(new OutboundAction(actionId,OutboundKind.AUTHN_REQUEST,raw,input.destination(),false),requestId);}
        @Override public FixtureObservation observe(String correlation,byte[] raw){return FixtureObservation.NOT_VERIFIED;}
        @Override public String definitionKey(){return "registered-signer-probe-v1|"+id+"|"+input.frameSha256()+"|"+input.localRunId()+"|"+input.otherRunId()+"|"+input.entity()+"|"+input.destination()+"|"+input.acs()+"|"+kind;}
    }
}
