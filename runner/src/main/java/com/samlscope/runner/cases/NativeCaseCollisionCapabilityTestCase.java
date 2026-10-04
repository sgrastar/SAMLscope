package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;

/** Provisional native wrapper; the approved manual interface remains usable while controls are unfinished. */
public final class NativeCaseCollisionCapabilityTestCase implements TestCase,AttestationPrompt,QueuedProtocolEvidenceCase,EvidenceCampaignCase,FallbackEvidenceCase,RecordedEvidenceReevaluation {
    private final TestCase fallback;private final KeycloakCaseCollisionCapabilityEvidence evidence;
    public NativeCaseCollisionCapabilityTestCase(TestCase fallback,KeycloakCaseCollisionCapabilityEvidence evidence){
        if(fallback==null||!KeycloakCaseCollisionCapabilityEvidence.CASE.equals(fallback.id())||fallback.role()!=TargetRole.IDP||!(fallback instanceof AttestationPrompt))throw new IllegalArgumentException("Approved identifier case-policy fallback required");this.fallback=fallback;this.evidence=Objects.requireNonNull(evidence);
    }
    public String id(){return fallback.id();}public TargetRole role(){return fallback.role();}public String promptEn(){return((AttestationPrompt)fallback).promptEn();}public List<AttestationOption> options(){return((AttestationPrompt)fallback).options();}
    private CaseOutcome observed(CaseContext c){return evidence.read(c).orElseGet(()->CaseOutcome.notVerified("native_case_policy_unproven","idp.identifier.case-policy-unproven"));}
    public CaseStep start(CaseContext c){return evidence.read(c).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(c));}
    public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return evidence.read(c).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.resume(c,s,e));}
    public CaseOutcome queuedEvidenceOutcome(CaseContext c){return observed(c);}
    public EvidenceStatus evidenceStatus(CaseContext c){if(!evidence.exists(c.runId())&&fallback instanceof ProtocolEvidenceCase original)return original.evidenceStatus(c);var result=observed(c);boolean ready=result.outcome()==Outcome.SATISFIED;var required=List.of("approved-recipient-and-source-membership","actual-native-persistent-selector","signed-source-and-saved-state","unchanged-product-epoch","general-formatter-derivation","native-formatter-sensitivity-diagnostic","same-policy-different-subject-negative-control","recipient-native-transcript");return new EvidenceStatus(ready,required,ready?required:List.of(),result.details());}
    public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome previous){if(!evidence.exists(c.runId())&&fallback instanceof RecordedEvidenceReevaluation original)return original.reevaluateRecordedEvidence(c,previous);return supportsRecordedEvidenceReevaluation(previous)&&c.transcriptComplete()?RecordedEvidenceReevaluation.conclusiveUpdate(previous,observed(c)):Optional.empty();}
    public boolean resolvedFromExternalEvidence(CaseExecution e){return e!=null&&id().equals(e.caseId())&&e.outcome()!=null&&e.outcome().outcome()==Outcome.SATISFIED&&KeycloakCaseCollisionCapabilityEvidence.SCHEMA.equals(e.outcome().details().get("evidence_adapter"))&&e.runId().equals(e.outcome().details().get("run_id"))&&Boolean.FALSE.equals(e.outcome().details().get("slo_protocol_traffic_verified"))&&e.outcome().evidence().stream().anyMatch(ref->"native-case-collision-capability".equals(ref.kind())&&ref.reference().matches(java.util.regex.Pattern.quote(e.runId()+".keycloak-case-policy/manifest.json#sha256=")+"[0-9a-f]{64}"));}
    public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution e){return evidenceActionKind(e)==RunCampaignQuery.ActionKind.SELF_CHECK||e!=null&&e.outcome()!=null&&!resolvedFromExternalEvidence(e)&&Boolean.TRUE.equals(e.outcome().details().get("attested"))?RunCampaignQuery.EvidenceClass.SELF_ATTESTED:RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED;}
    public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution e){return e!=null&&id().equals(e.caseId())&&e.status()==CaseExecutionStatus.WAITING_ATTESTATION&&"await-attestation".equals(e.state().phase())&&!evidence.exists(e.runId())?RunCampaignQuery.ActionKind.SELF_CHECK:RunCampaignQuery.ActionKind.NONE;}
    public String evidenceCampaignId(){return"native-identifier-case-policy";}public String evidenceCampaignTitle(){return"Persistent identifier case policy";}public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.NONE;}public List<String> evidenceActionKeys(){return List.of(id());}
}
