package com.samlscope.runner.cases;

import java.security.PublicKey;
import java.util.*;
import java.util.function.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.Direction;
import com.samlscope.runner.*;

/** Positive configuration-capability proof from both controlled decryption scenarios in this Run. */
public final class MultipleDecryptionKeysConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, FallbackEvidenceCase, RecordedEvidenceReevaluation {
    public static final String ID = "IIP-IDP19-b-idp-01";
    private static final Map<String,String> PROOFS = Map.of(
            IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID, "slo.encrypted-id.decryption-observed",
            IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID, "slo.encrypted-id.multiple-keys.decryption-observed");
    private static final String REASON = "configuration.multiple-decryption-keys.observed";
    private final TestCase fallback;
    private final Function<String,SupplementalDecryptionKeyService.KeySet> keys;
    private final BiFunction<String,String,Optional<CaseExecution>> executions;
    public MultipleDecryptionKeysConfigurationTestCase(TestCase fallback,
            Function<String,SupplementalDecryptionKeyService.KeySet> keys,
            BiFunction<String,String,Optional<CaseExecution>> executions) {
        this.fallback=Objects.requireNonNull(fallback); this.keys=Objects.requireNonNull(keys);
        this.executions=Objects.requireNonNull(executions);
        if (!ID.equals(fallback.id()) || fallback.role()!=TargetRole.IDP
                || !(fallback instanceof ConfigurationPrompt) || !(fallback instanceof AttestationPrompt))
            throw new IllegalArgumentException("Expected approved multiple-decryption-key CONFIG fallback");
    }
    /** Metadata-published keys only; used where no supplemental input exists. */
    public static MultipleDecryptionKeysConfigurationTestCase publishedOnly(TestCase fallback,
            Function<String,List<PublicKey>> publishedKeys,
            BiFunction<String,String,Optional<CaseExecution>> executions) {
        return new MultipleDecryptionKeysConfigurationTestCase(fallback,
                runId -> new SupplementalDecryptionKeyService.KeySet(publishedKeys.apply(runId),List.of()), executions);
    }
    @Override public String id() { return ID; }
    @Override public TargetRole role() { return TargetRole.IDP; }
    @Override public String instructionEn() { return ((ConfigurationPrompt)fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt)fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt)fallback).options(); }
    @Override public CaseStep start(CaseContext context) {
        return observed(context).<CaseStep>map(CaseStep.Finish::new).orElseGet(()->fallback.start(context));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        var outcome=observed(context);
        if (outcome.isPresent()) return new CaseStep.Finish(outcome.orElseThrow());
        if (event instanceof CaseEvent.TranscriptReady)
            return new CaseStep.Finish(CaseOutcome.notVerified("decryption_key_capability_unproven","configuration.multiple-decryption-keys.unproven"));
        return fallback.resume(context,state,event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var proof=observed(context); var required=PROOFS.keySet().stream().sorted().toList();
        return new EvidenceStatus(proof.isPresent(),required,proof.isPresent()?required:List.of(),
                Map.of("automatic_observation",true));
    }
    @Override public boolean resolvedFromExternalEvidence(CaseExecution execution) {
        return execution.outcome()!=null && REASON.equals(execution.outcome().reasonCode())
                && execution.outcome().evidence().stream().anyMatch(e->"transcript".equals(e.kind()));
    }
    @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome previous) {
        return previous!=null && previous.outcome()==Outcome.NOT_VERIFIED;
    }
    @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext context, CaseOutcome previous) {
        return observed(context).flatMap(next->RecordedEvidenceReevaluation.conclusiveUpdate(previous,next));
    }
    private Optional<CaseOutcome> observed(CaseContext context) {
        if (!context.transcriptComplete()) return Optional.empty();
        try {
            var keySet=keys.apply(context.runId());
            var effective=keySet.effective();
            // The provider is bound to the selected entity/role and immutable Run metadata.
            if (effective.size()<2 || effective.stream().anyMatch(k->!"RSA".equals(k.getAlgorithm()))
                    || effective.stream().map(k->Base64.getEncoder().encodeToString(k.getEncoded())).distinct().count()!=effective.size())
                return Optional.empty();
            var history=context.transcript().list(context.runId());
            var byId=new HashMap<String,com.samlscope.core.transcript.TranscriptEntry>();
            for(var entry:history) {
                if(!context.runId().equals(entry.runId()) || byId.putIfAbsent(entry.id(),entry)!=null) return Optional.empty();
            }
            var evidence=new ArrayList<EvidenceRef>(); var ids=new HashSet<String>();
            for(var required:PROOFS.entrySet()) {
                var execution=executions.apply(context.runId(),required.getKey()).orElse(null);
                if(execution==null || !context.runId().equals(execution.runId()) || !required.getKey().equals(execution.caseId())
                        || execution.status()!=CaseExecutionStatus.FINISHED || execution.outcome()==null
                        || execution.outcome().outcome()!=Outcome.SATISFIED
                        || !required.getValue().equals(execution.outcome().reasonCode())
                        || execution.outcome().evidence().size()!=4) return Optional.empty();
                for(var ref:execution.outcome().evidence()) {
                    var entry=byId.get(ref.reference());
                    if(!"transcript".equals(ref.kind()) || !ids.add(ref.reference()) || entry==null
                            || entry.direction()!=Direction.INBOUND || entry.decodedSamlRef()==null || entry.decodedSamlBytes()<=0)
                        return Optional.empty();
                    evidence.add(ref);
                }
            }
            return Optional.of(new CaseOutcome(Outcome.SATISFIED,null,REASON,REASON,List.copyOf(evidence),
                    Map.of("decryption_key_source",keySet.sources())));
        } catch(RuntimeException unavailable) { return Optional.empty(); }
    }
}
