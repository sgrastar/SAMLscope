package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import com.samlscope.runner.ExternallyObservedCase;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeycloakPersistentPairwiseWiringTest {
 private static final String RUN="run_00000000000000000000000000",CASE="IIP-SSO05-a3-idp-01";
 @TempDir Path directory;
 private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String run){assertEquals(RUN,run);return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read-only observer");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("No original mutation");}},complete);}
 private IdpExecutableBrowserFixtureScenarioTestCase testCase(){return new IdpExecutableBrowserFixtureScenarioTestCase(CASE,run->{throw new AssertionError("Owned proof must not generate another action");}).withPersistentPairwiseEvidence(directory,e->new byte[0],run->new byte[0]);}
 private Path owned(){return directory.resolve(RUN+".keycloak-pairwise.json");}
 private void noActionAndNoAdoption(){var tc=testCase();assertInstanceOf(com.samlscope.runner.RecordedEvidenceReevaluation.class,tc);var value=tc.recordedPersistentPairwise(context(true)).orElseThrow();assertEquals(Outcome.NOT_VERIFIED,value.outcome());assertEquals("idp.persistent-pairwise.unproven",value.reasonCode());assertEquals(value,((CaseStep.Finish)tc.start(context(true))).outcome());for(CaseEvent event:List.of(new CaseEvent.TranscriptReady(),new CaseEvent.TimedOut(java.time.Duration.ofSeconds(1))))assertEquals(value,((CaseStep.Finish)tc.resume(context(true),null,event)).outcome());assertFalse(tc.evidenceStatus(context(true)).ready());var previous=CaseOutcome.notVerified("not_observed","browser_fixture_partial");assertTrue(tc.supportsRecordedEvidenceReevaluation(previous));assertTrue(tc.reevaluateRecordedEvidence(context(true),previous).isEmpty());assertTrue(tc.reevaluateRecordedEvidence(context(false),previous).isEmpty());assertFalse(tc.supportsRecordedEvidenceReevaluation(CaseOutcome.of(Outcome.SATISFIED,"already",List.of())));}
 @Test void absentOwnershipRetainsNoObservedProof(){assertTrue(testCase().recordedPersistentPairwise(context(true)).isEmpty());assertFalse(testCase().evidenceStatus(context(true)).ready());}
 @Test void malformedOwnedProofCannotLaunchAnotherAction()throws Exception{Files.writeString(owned(),"{}");noActionAndNoAdoption();}
 @Test void directoryOwnedProofCannotFallBack()throws Exception{Files.createDirectory(owned());noActionAndNoAdoption();}
 @Test void symlinkOwnedProofCannotFallBack()throws Exception{var p=directory.resolve("other.json");Files.writeString(p,"{}");Files.createSymbolicLink(owned(),p);noActionAndNoAdoption();}
 @Test void competingNativeProductProofsAreAmbiguous()throws Exception{Files.writeString(owned(),"{}");Files.createDirectory(directory.resolve(RUN));noActionAndNoAdoption();assertEquals("ambiguous_native_pairwise_product",testCase().recordedPersistentPairwise(context(true)).orElseThrow().notVerifiedReason());}
 @Test void unrelatedPriorFailuresCannotBeReclassified()throws Exception{Files.writeString(owned(),"{}");var tc=testCase();assertFalse(tc.supportsRecordedEvidenceReevaluation(CaseOutcome.notVerified("not_observed","outbox.unknown-delivery")));assertTrue(tc.reevaluateRecordedEvidence(context(true),CaseOutcome.notVerified("not_observed","outbox.unknown-delivery")).isEmpty());}
}
