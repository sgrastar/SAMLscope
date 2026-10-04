package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.BrowserFrontChannelScenario;
import com.samlscope.runner.RecordedEvidenceReevaluation;
import java.util.*;

/** Native cryptographic originals can establish the approved multi-key counterexample. */
public final class EncryptedLogoutNativeTestCase implements TestCase, BrowserFrontChannelScenario,
        BrowserPrompt, QueuedProtocolEvidenceCase, RecordedEvidenceReevaluation {
    private static final String REASON="slo.encrypted-id.native-unproven";
    private static final List<String> REQUIRED=List.of("native-two-active-decryption-keys",
            "signed-authenticated-logout-operations", "registered-key-normal-control",
            "unknown-key-cryptographic-counterexample", "configuration-restoration");
    private final IdpBasicLogoutScenarioTestCase fallback;
    private final SimpleSamlPhpEncryptedLogoutEvidence evidence;

    EncryptedLogoutNativeTestCase(IdpBasicLogoutScenarioTestCase fallback,SimpleSamlPhpEncryptedLogoutEvidence evidence) {
        this.fallback=Objects.requireNonNull(fallback);this.evidence=Objects.requireNonNull(evidence);
        if (!IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID.equals(fallback.id()))
            throw new IllegalArgumentException("Approved multi-key logout case required");
    }
    private static CaseOutcome unproven(){return CaseOutcome.notVerified("native_encrypted_logout_originals_unproven",REASON);}
    private Optional<CaseOutcome> observed(CaseContext context) {
        if (!evidence.exists(context.runId())) return Optional.empty();
        if (!context.transcriptComplete()) return Optional.of(unproven());
        try {return Optional.of(evidence.evaluate(context).orElseGet(EncryptedLogoutNativeTestCase::unproven));}
        catch (RuntimeException unavailable){return Optional.of(unproven());}
    }
    @Override public String id(){return fallback.id();}
    @Override public TargetRole role(){return fallback.role();}
    @Override public CaseStep start(CaseContext context){return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(context));}
    @Override public CaseStep resume(CaseContext context,CaseState state,CaseEvent event){return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.resume(context,state,event));}
    @Override public CaseOutcome queuedEvidenceOutcome(CaseContext context){return observed(context).orElseGet(EncryptedLogoutNativeTestCase::unproven);}
    @Override public EvidenceStatus evidenceStatus(CaseContext context){
        var proof=observed(context);boolean ready=proof.map(o->o.outcome()==Outcome.VIOLATED).orElse(false);
        return new EvidenceStatus(ready,REQUIRED,ready?REQUIRED:List.of(),proof.map(CaseOutcome::details).orElse(Map.of()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous){
        return previous!=null&&previous.outcome()==Outcome.NOT_VERIFIED&&Set.of(REASON,
                "slo.encrypted-id.multiple-keys.negative-control-failed", "browser.oracle-unavailable",
                "browser_fixture_partial").contains(previous.reasonCode());
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context,CaseOutcome previous){
        if(!context.transcriptComplete()||!supportsRecordedEvidenceReevaluation(previous))return Optional.empty();
        return observed(context).flatMap(next->RecordedEvidenceReevaluation.conclusiveUpdate(previous,next));
    }
    @Override public String browserInstructionsEn(){return fallback.browserInstructionsEn();}
    @Override public String instructionsEn(CaseState state){return fallback.instructionsEn(state);}
    @Override public Binding outboundBinding(CaseState state){return fallback.outboundBinding(state);}
    @Override public boolean requiresFreshSession(CaseState state){return fallback.requiresFreshSession(state);}
    @Override public boolean plansFreshSessionBoundary(){return fallback.plansFreshSessionBoundary();}
    @Override public int plannedDeliberateActions(){return fallback.plannedDeliberateActions();}
}
