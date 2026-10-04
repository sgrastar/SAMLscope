package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.util.*;
import java.util.function.Function;

/** Original-backed observation first; the approved attestation remains the fallback. */
final class KeycloakSelfContainedTrustAttestedTestCase implements TestCase, AttestationPrompt,
        EvidenceCampaignCase, FallbackEvidenceCase, ProtocolEvidenceCase, RecordedEvidenceReevaluation {
    private final TestCase fallback;
    private final Function<String,byte[]> metadata;
    private final KeycloakSelfContainedTrustEvidenceFile evidence;

    KeycloakSelfContainedTrustAttestedTestCase(TestCase fallback,Function<String,byte[]> metadata,
            KeycloakNativeRunEvidenceBridge bridge) {
        this(fallback,metadata,new KeycloakSelfContainedTrustEvidenceFile(
                bridge.evidenceDirectory(),bridge::content,bridge::key));
    }
    KeycloakSelfContainedTrustAttestedTestCase(TestCase fallback,Function<String,byte[]> metadata,
            KeycloakSelfContainedTrustEvidenceFile evidence) {
        if(!KeycloakSelfContainedTrustEvidenceFile.ID.equals(fallback.id())||!(fallback instanceof AttestationPrompt))
            throw new IllegalArgumentException("No approved native trust attestation fallback");
        this.fallback=Objects.requireNonNull(fallback);this.metadata=Objects.requireNonNull(metadata);
        this.evidence=Objects.requireNonNull(evidence);
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public String promptEn(){return ((AttestationPrompt)fallback).promptEn();}
    @Override public List<AttestationOption> options(){return ((AttestationPrompt)fallback).options();}
    @Override public String evidenceCampaignId(){return "native-metadata-trust";}
    @Override public String evidenceCampaignTitle(){return "Native metadata signature and encryption trust observation";}
    @Override public RunCampaignQuery.ActionKind evidenceActionKind(){return RunCampaignQuery.ActionKind.NONE;}
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution){
        return execution.outcome()!=null&&execution.outcome().outcome()==Outcome.SATISFIED
                &&"metadata.trust.self-contained-native-observed".equals(execution.outcome().reasonCode())
                &&Boolean.TRUE.equals(execution.outcome().details().get("native_originals_verified"))
                &&execution.outcome().evidence().stream().anyMatch(value->"transcript".equals(value.kind()));
    }
    private Optional<CaseOutcome> observe(CaseContext context){
        if(!context.transcriptComplete()||!evidence.exists(context.runId()))return Optional.empty();
        byte[] target;try{target=metadata.apply(context.runId());}catch(RuntimeException missing){target=null;}
        return Optional.of(evidence.evaluate(context,target));
    }
    @Override public CaseStep start(CaseContext context){
        return observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){
        return event instanceof CaseEvent.TranscriptReady
                ?observe(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.resume(context,state,event))
                :fallback.resume(context,state,event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var outcome=observe(context);boolean ready=outcome.map(value->value.outcome()==Outcome.SATISFIED).orElse(false);
        return new EvidenceStatus(ready,List.of("native-signature-encryption-trust"),
                ready?List.of("native-signature-encryption-trust"):List.of(),
                outcome.map(CaseOutcome::details).orElse(Map.of()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){
        return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        return supportsRecordedEvidenceReevaluation(previous)
                ?observe(context).flatMap(next->RecordedEvidenceReevaluation.conclusiveUpdate(previous,next)):Optional.empty();
    }
}
