package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.runner.BrowserFrontChannelScenario;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class SelfContainedMetadataTrustEvidenceTestCaseTest {
    static final String RUN="run_00000000000000000000000000",ADAPTER=SimpleSamlPhpSelfContainedTrustEvidenceFile.ADAPTER,KIND="native-self-contained-trust-evidence",PREFIX=".simplesamlphp-trust.json";
    static DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry> list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No sends/records");}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError();}},complete);}
    static AttestedOutcomeTestCase fallback(){return new AttestedOutcomeTestCase(SimpleSamlPhpSelfContainedTrustEvidenceFile.ID,TargetRole.IDP,"native-trust-fallback","Approved prompt",Duration.ofDays(7),List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied"),AttestationOption.notVerified("unable_to_verify","attestation.unavailable","attestation_unavailable")));}
    static CaseOutcome outcome(Outcome value,boolean diagnostic){return new CaseOutcome(value,null,"native-proof","native-proof",List.of(new EvidenceRef(KIND,RUN+PREFIX),new EvidenceRef("transcript","transcripts/"+RUN+"/tx_00000000000000000000000000.saml.xml")),Map.of("evidence_adapter",ADAPTER,"run_id",RUN,"counterfactual_calibration_only",diagnostic));}
    static SelfContainedMetadataTrustEvidenceTestCase test(boolean owns,CaseOutcome observed){return new SelfContainedMetadataTrustEvidenceTestCase(fallback(),run->owns,c->observed,ADAPTER,KIND,PREFIX);}
    @Test void missingNativeProofKeepsApprovedAttestationAndNeverAddsBrowserActions(){var t=test(false,null);assertEquals(fallback().start(context(true)),t.start(context(true)));assertEquals(fallback().options(),t.options());assertEquals("Approved prompt",t.promptEn());assertEquals(com.samlscope.runner.RunCampaignQuery.ActionKind.NONE,t.evidenceActionKind());assertTrue(t.evidenceActionKeys().isEmpty());assertFalse(BrowserFrontChannelScenario.class.isInstance(t));}
    @Test void ownedInvalidAndIncompleteCannotBecomeDeclarationOrConclusion(){for(boolean complete:List.of(false,true)){var t=test(true,null);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,t.start(context(complete))).outcome().outcome());assertFalse(t.evidenceStatus(context(complete)).ready());assertTrue(t.reevaluateRecordedEvidence(context(complete),CaseOutcome.notVerified("before","before")).isEmpty());}assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test(true,outcome(Outcome.SATISFIED,false)).start(context(false))).outcome().outcome());}
    @Test void completeNativeProofUsesEveryLifecycleAndRetainsConclusiveHistory(){var n=outcome(Outcome.SATISFIED,false);var t=test(true,n);assertEquals(n,assertInstanceOf(CaseStep.Finish.class,t.start(context(true))).outcome());for(var e:List.<CaseEvent>of(new CaseEvent.TranscriptReady(),new CaseEvent.Attested("satisfied",""),new CaseEvent.Aborted("cancel")))assertEquals(n,assertInstanceOf(CaseStep.Finish.class,t.resume(context(true),null,e)).outcome());assertEquals(n,t.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("before","before")).orElseThrow());assertTrue(t.reevaluateRecordedEvidence(context(true),n).isEmpty());assertTrue(t.evidenceStatus(context(true)).ready());}
    @Test void wrongAdapterOrRunReferenceCannotUseNativeProvenance(){for(var n:List.of(new CaseOutcome(Outcome.SATISFIED,null,"x","x",List.of(new EvidenceRef(KIND,"other")),Map.of("evidence_adapter",ADAPTER,"run_id",RUN)),new CaseOutcome(Outcome.SATISFIED,null,"x","x",List.of(new EvidenceRef(KIND,RUN+PREFIX),new EvidenceRef("transcript","transcripts/"+RUN+"/tx_00000000000000000000000000.saml.xml")),Map.of("evidence_adapter","other","run_id",RUN))))assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test(true,n).start(context(true))).outcome().outcome());}
    @Test void counterfactualExtraAnchorIsDetectedBySameProductionWrapper(){var n=outcome(Outcome.VIOLATED,true);assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,test(true,n).start(context(true))).outcome().outcome());assertFalse(test(true,n).evidenceStatus(context(true)).ready());var t=new SelfContainedMetadataTrustEvidenceTestCase(fallback(),run->true,c->n,ADAPTER,KIND,PREFIX,true);assertEquals(n,assertInstanceOf(CaseStep.Finish.class,t.start(context(true))).outcome());assertTrue(t.evidenceStatus(context(true)).ready());assertEquals(n,t.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("before","before")).orElseThrow());}
    @Test void noNewTranscriptKeepsNotVerifiedWithoutRewritingOldHistory(){var next=outcome(Outcome.SATISFIED,false);var previous=new CaseOutcome(Outcome.NOT_VERIFIED,"before","before","before",next.evidence(),Map.of());assertTrue(test(true,next).reevaluateRecordedEvidence(context(true),previous).isEmpty());}
    static final class NativeFallback implements TestCase,AttestationPrompt,ProtocolEvidenceCase,RecordedEvidenceReevaluation,FallbackEvidenceCase {
        final CaseOutcome nativeOutcome=new CaseOutcome(Outcome.SATISFIED,null,"legacy.native","legacy.native",outcome(Outcome.SATISFIED,false).evidence(),Map.of("evidence_adapter","legacy-kc"));
        @Override public String id(){return SimpleSamlPhpSelfContainedTrustEvidenceFile.ID;}@Override public TargetRole role(){return TargetRole.IDP;}
        @Override public String promptEn(){return "Legacy approved prompt";}@Override public List<AttestationOption> options(){return fallback().options();}
        @Override public CaseStep start(CaseContext c){return new CaseStep.Finish(nativeOutcome);}@Override public CaseStep resume(CaseContext c,CaseState s,CaseEvent e){return start(c);}
        @Override public EvidenceStatus evidenceStatus(CaseContext c){return new EvidenceStatus(true,List.of("legacy-native"),List.of("legacy-native"),Map.of("evidence_adapter","legacy-kc"));}
        @Override public boolean supportsRecordedEvidenceReevaluation(CaseOutcome before){return before!=null&&before.outcome()==Outcome.NOT_VERIFIED;}
        @Override public Optional<CaseOutcome> reevaluateRecordedEvidence(CaseContext c,CaseOutcome before){return RecordedEvidenceReevaluation.conclusiveUpdate(before,nativeOutcome);}
        @Override public boolean resolvedFromExternalEvidence(CaseExecution e){return e!=null&&nativeOutcome.equals(e.outcome());}
        @Override public RunCampaignQuery.EvidenceClass evidenceClass(CaseExecution e){return resolvedFromExternalEvidence(e)?RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED:RunCampaignQuery.EvidenceClass.SELF_ATTESTED;}
    }
    @Test void absentOwnProofPreservesNativeFallbackButMalformedOwnedProofNeverBorrowsIt(){
        var fallback=new NativeFallback();var c=context(true);var saved=new CaseExecution(RUN,fallback.id(),1,CaseExecutionStatus.FINISHED,new CaseState("finished",Map.of()),null,fallback.nativeOutcome,Instant.EPOCH);var before=CaseOutcome.notVerified("before","before");
        var absent=new SelfContainedMetadataTrustEvidenceTestCase(fallback,r->false,x->null,ADAPTER,KIND,PREFIX);
        assertEquals(fallback.evidenceStatus(c),absent.evidenceStatus(c));assertEquals(fallback.nativeOutcome,absent.reevaluateRecordedEvidence(c,before).orElseThrow());assertTrue(absent.resolvedFromExternalEvidence(saved));assertEquals(RunCampaignQuery.EvidenceClass.OPERATOR_ASSISTED,absent.evidenceClass(saved));assertEquals(fallback.start(c),absent.start(c));
        var malformed=new SelfContainedMetadataTrustEvidenceTestCase(fallback,r->true,x->null,ADAPTER,KIND,PREFIX);
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,malformed.start(c)).outcome().outcome());assertFalse(malformed.evidenceStatus(c).ready());assertTrue(malformed.reevaluateRecordedEvidence(c,before).isEmpty());assertFalse(malformed.resolvedFromExternalEvidence(saved));assertEquals(RunCampaignQuery.EvidenceClass.SELF_ATTESTED,malformed.evidenceClass(saved));
    }

}

