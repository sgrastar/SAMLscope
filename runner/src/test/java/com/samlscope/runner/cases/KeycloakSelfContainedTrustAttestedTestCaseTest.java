package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class KeycloakSelfContainedTrustAttestedTestCaseTest {
 @TempDir Path data;
 static final String RUN="run_00000000000000000000000000";
 DefaultCaseContext context(){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("No recording");}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object>s){throw new AssertionError();}},true);}
 AttestedOutcomeTestCase fallback(){return new AttestedOutcomeTestCase(KeycloakSelfContainedTrustEvidenceFile.ID,TargetRole.IDP,"native-trust-fallback","Approved prompt",Duration.ofDays(7),List.of(AttestationOption.of("satisfied",Outcome.SATISFIED,"attestation.satisfied"),AttestationOption.notVerified("unable_to_verify","attestation.unavailable","attestation_unavailable")));}
 KeycloakSelfContainedTrustAttestedTestCase wrapper(){return new KeycloakSelfContainedTrustAttestedTestCase(fallback(),run->new byte[0],new KeycloakSelfContainedTrustEvidenceFile(data,entry->{throw new AssertionError("No originals");},(r,v)->Optional.empty()));}
 @Test void absentNativeEvidenceRetainsApprovedAttestationAndCannotReevaluate(){var test=wrapper();assertEquals(fallback().start(context()),test.start(context()));assertEquals("Approved prompt",test.promptEn());assertEquals(fallback().options(),test.options());assertFalse(test.evidenceStatus(context()).ready());assertTrue(test.reevaluateRecordedEvidence(context(),CaseOutcome.notVerified("interaction_disallowed","attestation.interaction-disallowed")).isEmpty());}
 @Test void malformedReceiptCannotBecomeAttestationOrConclusiveResult()throws Exception{Files.writeString(data.resolve(RUN+".native-trust.json"),"{}");var test=wrapper();var finish=assertInstanceOf(CaseStep.Finish.class,test.start(context()));assertEquals(Outcome.NOT_VERIFIED,finish.outcome().outcome());assertFalse(test.evidenceStatus(context()).ready());assertTrue(test.reevaluateRecordedEvidence(context(),CaseOutcome.notVerified("interaction_disallowed","attestation.interaction-disallowed")).isEmpty());}
 @Test void conclusiveExistingResultIsNotReevaluated(){assertFalse(wrapper().supportsRecordedEvidenceReevaluation(CaseOutcome.of(Outcome.SATISFIED,"existing",List.of())));}
}
