package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.EvidenceCampaignCase;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import com.samlscope.runner.RunCampaignQuery.ActionKind;
import java.util.*;

/**
 * Original-bound native fixture completion; never supplies an operator attestation.
 * External logins cannot prove that an indicator reaches the authentication mechanism,
 * so missing native evidence must not start or continue a browser probe chain.
 */
public final class ForceAuthnMechanismEvidenceTestCase implements InteractionFreeEvidenceCase,EvidenceCampaignCase,RecordedEvidenceReevaluation {
    private final IdpForceAuthnScenarioTestCase fallback;
    private final List<NativeForceAuthnMechanismEvidence> evidence;
    public ForceAuthnMechanismEvidenceTestCase(IdpForceAuthnScenarioTestCase fallback,NativeForceAuthnMechanismEvidence... evidence){
        this.fallback=Objects.requireNonNull(fallback);this.evidence=List.of(evidence);
        if(this.evidence.isEmpty())throw new IllegalArgumentException("Native evidence adapter required");
        if(!IdpForceAuthnScenarioTestCase.MECHANISM_ACCESS_CASE.equals(fallback.id()))throw new IllegalArgumentException("Approved mechanism case required");
    }
    public ForceAuthnMechanismEvidenceTestCase withDecryptionKeys(SamlDecryptionKeyProvider provider){return new ForceAuthnMechanismEvidenceTestCase(fallback,evidence.stream().map(e->e.withKeys(provider)).toArray(NativeForceAuthnMechanismEvidence[]::new));}
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    private Optional<CaseOutcome> observe(CaseContext context){
        var owned=evidence.stream().filter(e->e.exists(context.runId())).toList();
        if(owned.size()>1)return Optional.of(unproven());
        if(owned.isEmpty())return Optional.empty();
        return owned.getFirst().read(context).map(outcome->{
        if(outcome.outcome()!=Outcome.NOT_VERIFIED)return outcome;
        var details=new LinkedHashMap<String,Object>(outcome.details());
        details.put("required_action","administrator_evidence");details.put("instructions_en",INSTRUCTIONS);
        return new CaseOutcome(outcome.outcome(),outcome.notVerifiedReason(),outcome.reasonCode(),
            outcome.reasonMessageKey(),outcome.evidence(),details);
    });}
    private static final String INSTRUCTIONS = "Ask the target administrator to provide evidence that ForceAuthn reaches the authentication mechanism. Additional logins cannot verify this case.";
    private static CaseOutcome unproven(){return new CaseOutcome(Outcome.NOT_VERIFIED,
        "native_mechanism_reachability_unproven","idp.force-authn.mechanism-reachability.unproven",
        "idp.force-authn.mechanism-reachability.unproven",List.of(),
        Map.of("required_action","administrator_evidence","instructions_en",INSTRUCTIONS));}
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context){return observe(context).orElseGet(ForceAuthnMechanismEvidenceTestCase::unproven);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){var o=observe(context);boolean ready=o.isPresent()&&o.get().outcome()==Outcome.SATISFIED;
        var required=List.of("signed-native-authentication-baseline","native-instrumented-same-context-indicator","drop-and-misbound-negative-controls","native-process-config-originals");
        return new EvidenceStatus(ready,required,ready?required:List.of(),o.map(CaseOutcome::details).orElseGet(()->unproven().details()));}
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED;}
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){if(!supportsRecordedEvidenceReevaluation(previous)||!context.transcriptComplete())return Optional.empty();return observe(context).flatMap(o->RecordedEvidenceReevaluation.conclusiveUpdate(previous,o));}
    @Override public String evidenceCampaignId(){return "native-authentication-mechanism";}
    @Override public String evidenceCampaignTitle(){return "Authentication mechanism evidence";}
    @Override public ActionKind evidenceActionKind(){return ActionKind.NONE;}
    @Override public List<String> evidenceActionKeys(){return List.of();}
}
