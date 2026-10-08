package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.runner.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class NativeConfigurationSourceRunTestCaseTest {
    private final CaseContext context = ClockSkewEvidenceTestCaseTest.context(true);
    private static final String SOURCE = "run_11111111111111111111111111", HASH = "a".repeat(64);
    private static final class Fallback implements TestCase, ConfigurationPrompt, AttestationPrompt,
            ProtocolEvidenceCase, FallbackEvidenceCase, RecordedEvidenceReevaluation, EvidenceCampaignCase {
        int starts, resumes;
        final CaseOutcome legacy = new CaseOutcome(Outcome.SATISFIED,null,"legacy-proof","legacy-proof",List.of(),Map.of());
        public String id() { return SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE; }
        public TargetRole role() { return TargetRole.IDP; }
        public String instructionEn() { return "Approved configuration instructions"; }
        public String promptEn() { return "Approved evidence prompt"; }
        public List<AttestationOption> options() { return List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"manual")); }
        public CaseStep start(CaseContext c) { starts++; return new CaseStep.Finish(legacy); }
        public CaseStep resume(CaseContext c,CaseState s,CaseEvent e) { resumes++; return new CaseStep.Finish(legacy); }
        public EvidenceStatus evidenceStatus(CaseContext c) { return new EvidenceStatus(true,List.of("legacy"),List.of("legacy"),Map.of()); }
        public boolean supportsRecordedEvidenceReevaluation(CaseOutcome p) { return p.outcome()==Outcome.NOT_VERIFIED; }
        public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome p) { return Optional.of(legacy); }
        public boolean resolvedFromExternalEvidence(CaseExecution e) { return e!=null&&legacy.equals(e.outcome()); }
        public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution e) { return RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED; }
        public String evidenceCampaignId() { return "approved-fallback"; }
        public String evidenceCampaignTitle() { return "Approved fallback"; }
        public RunCampaignQuery.ActionKind evidenceActionKind() { return RunCampaignQuery.ActionKind.CONFIGURATION; }
        public RunCampaignQuery.ActionKind evidenceActionKind(CaseExecution e) { return e!=null&&e.status()==CaseExecutionStatus.WAITING_ATTESTATION
                ? RunCampaignQuery.ActionKind.SELF_CHECK : RunCampaignQuery.ActionKind.CONFIGURATION; }
        public List<String> evidenceActionKeys() { return List.of(id()); }
        public boolean sharesDeliberateAction() { return false; }
    }
    private NativeConfigurationSourceRunTestCase wrapper(Fallback fallback,boolean exists,CaseOutcome outcome) {
        return new NativeConfigurationSourceRunTestCase(fallback,new NativeConfigurationSourceRunTestCase.ProofAccess() {
            public boolean exists(String run) { return exists; }
            public Optional<CaseOutcome> read(CaseContext c) { return Optional.ofNullable(outcome); }
        });
    }
    private CaseExecution saved(CaseOutcome outcome) {
        return new CaseExecution(context.runId(),SimpleSamlPhpMultipleDecryptionKeysEvidence.CASE,1,
                CaseExecutionStatus.FINISHED,CaseState.initial(),null,outcome,Instant.EPOCH);
    }
    private CaseOutcome proof() {
        var details=new LinkedHashMap<String,Object>(); details.put("run_id",SOURCE); details.put("source_run_id",SOURCE);
        details.put("adoption_run_id",context.runId()); details.put("case_digest",SimpleSamlPhpMultipleDecryptionKeysEvidence.DIGEST);
        details.put("binding_scope",NativeConfigurationSourceRunEvidence.SCOPE); details.put("binding_sha256",HASH);
        details.put("source_transcript_complete",false); details.put("independent_configuration_completion",true);
        details.put("capability_removal_control_verified",true); details.put("configuration_restored",true);
        return new CaseOutcome(Outcome.SATISFIED,null,NativeConfigurationSourceRunEvidence.REASON,
                NativeConfigurationSourceRunEvidence.REASON,List.of(new EvidenceRef("native-configuration-source-run",
                context.runId()+"/manifest.json#sha256="+HASH)),details);
    }
    @Test void missingBindingPreservesApprovedFallbackAndManualSurface() {
        var f=new Fallback();var t=wrapper(f,false,null);
        assertEquals(f.legacy,assertInstanceOf(CaseStep.Finish.class,t.start(context)).outcome());
        assertEquals(f.options(),t.options());assertEquals(f.promptEn(),t.promptEn());assertEquals(f.instructionEn(),t.instructionEn());
        assertEquals(f.evidenceStatus(context),t.evidenceStatus(context));assertEquals(f.evidenceActionKeys(),t.evidenceActionKeys());
        assertEquals(f.evidenceCampaignId(),t.evidenceCampaignId());assertEquals(f.evidenceCampaignTitle(),t.evidenceCampaignTitle());
        assertEquals(f.supplementalEvidenceCampaigns(),t.supplementalEvidenceCampaigns());
        assertEquals(f.sharesDeliberateAction(),t.sharesDeliberateAction());
        assertEquals(RunCampaignQuery.EvidenceClass.PROTOCOL_OBSERVED,t.evidenceClass(saved(f.legacy)));
        assertFalse(BrowserFrontChannelScenario.class.isInstance(t));
    }
    @Test void ownedInvalidBindingCannotBorrowLegacySuccessOrManualAttestation() {
        var f=new Fallback();var t=wrapper(f,true,null);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.start(context)).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.resume(context,CaseState.initial(),new CaseEvent.Attested("satisfied","manual"))).outcome().outcome());
        assertEquals(0,f.starts);assertEquals(0,f.resumes);assertFalse(t.evidenceStatus(context).ready());
        assertTrue(t.reevaluateRecordedEvidence(context,CaseOutcome.notVerified("pending","pending")).isEmpty());
        assertFalse(t.resolvedFromExternalEvidence(saved(f.legacy)));
        assertEquals(RunCampaignQuery.ActionKind.NONE,t.evidenceActionKind(saved(f.legacy)));
    }
    @Test void qualifiedSourceKeepsItsOriginalRunAndReportsOperatorAssistance() {
        var f=new Fallback();var outcome=proof();var t=wrapper(f,true,outcome);
        assertEquals(outcome,assertInstanceOf(CaseStep.Finish.class,t.start(context)).outcome());assertTrue(t.evidenceStatus(context).ready());
        assertEquals(SOURCE,outcome.details().get("run_id"));assertNotEquals(context.runId(),outcome.details().get("run_id"));
        assertTrue(t.resolvedFromExternalEvidence(saved(outcome)));
        assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,t.evidenceClass(saved(outcome)));
        assertEquals(RunCampaignQuery.ActionKind.NONE,t.evidenceActionKind(saved(outcome)));
    }
    @Test void coherentProvenanceSubstitutionsCannotBecomeSourceProof() {
        var original=proof();
        for(String field:List.of("source_run_id","run_id","adoption_run_id","case_digest","binding_scope","binding_sha256",
                "source_transcript_complete","independent_configuration_completion","capability_removal_control_verified","configuration_restored")) {
            var fields=new LinkedHashMap<>(original.details());fields.put(field,"foreign");
            var altered=new CaseOutcome(original.outcome(),null,original.reasonCode(),original.reasonMessageKey(),original.evidence(),fields);
            var t=wrapper(new Fallback(),true,altered);
            assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.start(context)).outcome().outcome(),field);
            assertFalse(t.resolvedFromExternalEvidence(saved(altered)),field);
        }
        var withoutManifest=new CaseOutcome(original.outcome(),null,original.reasonCode(),original.reasonMessageKey(),List.of(),original.details());
        assertFalse(wrapper(new Fallback(),true,withoutManifest).evidenceStatus(context).ready());
    }
    @Test void existingConclusiveCaseIsNeverRewrittenByReevaluation() {
        var t=wrapper(new Fallback(),true,proof());assertTrue(t.reevaluateRecordedEvidence(context,proof()).isEmpty());
        assertTrue(t.reevaluateRecordedEvidence(ClockSkewEvidenceTestCaseTest.context(false),CaseOutcome.notVerified("pending","pending")).isEmpty());
    }
}
