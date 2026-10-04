package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.FallbackEvidenceCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery;
import com.samlscope.runner.RunCampaignQuery.ActionKind;
import java.util.*;

/** Native producer evidence never supplies an operator declaration or starts a browser chain. */
public final class NativePersistentIdentifierEvidenceTestCase implements TestCase,AttestationPrompt,QueuedProtocolEvidenceCase,EvidenceCampaignCase,FallbackEvidenceCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;private final KeycloakPersistentIdentifierEvidence evidence;
    public NativePersistentIdentifierEvidenceTestCase(TestCase fallback,KeycloakPersistentIdentifierEvidence evidence) {
        if(fallback==null||!KeycloakPersistentIdentifierEvidence.DIGESTS.containsKey(fallback.id())||fallback.role()!=TargetRole.IDP||!(fallback instanceof AttestationPrompt))throw new IllegalArgumentException("Approved persistent identifier attestation fallback required");
        this.fallback=fallback;this.evidence=Objects.requireNonNull(evidence);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    private CaseOutcome observe(CaseContext context){return evidence.read(context,id()).orElseGet(()->CaseOutcome.notVerified("native_identifier_construction_unproven","idp.persistent-identifier.native-unproven"));}
    @Override public CaseStep start(CaseContext context){return evidence.read(context,id()).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(context));}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){return evidence.read(context,id()).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.resume(context,state,event));}
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context){return observe(context);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        if(!evidence.exists(context.runId())&&fallback instanceof ProtocolEvidenceCase protocol)return protocol.evidenceStatus(context);
        var outcome=observe(context);boolean ready=Set.of(Outcome.SATISFIED,Outcome.VIOLATED).contains(outcome.outcome());
        var required=List.of("approved-source-run","signed-persistent-originals","native-uuid-construction","saved-attribute-response-equality","principal-valued-native-control","exact-native-restoration");
        return new EvidenceStatus(ready,required,ready?required:List.of(),outcome.details());}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        if(!evidence.exists(context.runId())&&fallback instanceof RecordedEvidenceReevaluation recorded)return recorded.reevaluateRecordedEvidence(context,previous);
        return supportsRecordedEvidenceReevaluation(previous)&&context.transcriptComplete()?RecordedEvidenceReevaluation.conclusiveUpdate(previous,observe(context)):Optional.empty();}
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution){return execution!=null&&id().equals(execution.caseId())&&execution.outcome()!=null
        &&KeycloakPersistentIdentifierEvidence.SCHEMA.equals(execution.outcome().details().get("evidence_adapter"))&&execution.runId().equals(execution.outcome().details().get("run_id"))
        &&execution.outcome().evidence().stream().anyMatch(ref->"native-persistent-identifier".equals(ref.kind())&&ref.reference().startsWith(execution.runId()+".keycloak-native-identifier/"));}
    @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution execution){return !resolvedFromExternalEvidence(execution)&&execution!=null
        &&(execution.outcome()!=null&&Boolean.TRUE.equals(execution.outcome().details().get("attested"))||evidenceActionKind(execution)==ActionKind.SELF_CHECK)
        ?RunCampaignQuery.EvidenceClass.SELF_ATTESTED:RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;}
    @Override public String evidenceCampaignId(){return "native-persistent-identifier";}
    @Override public String evidenceCampaignTitle(){return "Persistent identifier construction evidence";}
    @Override public ActionKind evidenceActionKind(){return ActionKind.NONE;}
    @Override public ActionKind evidenceActionKind(CaseExecution execution){return execution!=null&&id().equals(execution.caseId())&&execution.status()==CaseExecutionStatus.WAITING_ATTESTATION
        &&execution.state()!=null&&"await-attestation".equals(execution.state().phase())&&!evidence.exists(execution.runId())?ActionKind.SELF_CHECK:ActionKind.NONE;}
    @Override public List<String> evidenceActionKeys(){return List.of(id());}
}
