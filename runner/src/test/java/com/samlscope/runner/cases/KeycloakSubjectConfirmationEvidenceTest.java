package com.samlscope.runner.cases;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class KeycloakSubjectConfirmationEvidenceTest {
 @TempDir Path directory;
 static final String RUN="run_00000000000000000000000001";
 CaseContext context(boolean complete){var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String r,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,complete);}
 KeycloakSubjectConfirmationEvidence reader(){return new KeycloakSubjectConfirmationEvidence(directory,e->new byte[0],r->"browser_sso_idp");}
 Path path(){return directory.resolve(RUN+".keycloak-subject-confirmation.json");}
 void nv(boolean complete){for(String id:List.of(KeycloakSubjectConfirmationEvidence.FR,KeycloakSubjectConfirmationEvidence.GD)){var result=reader().evaluate(context(complete),id,new byte[0]).orElseThrow();assertEquals(Outcome.NOT_VERIFIED,result.outcome());assertEquals("browser.subject-confirmation.native-unproven",result.reasonCode());assertTrue(result.evidence().isEmpty());}}
 @Test void noOwnedProofPreservesApprovedFallback(){assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true),KeycloakSubjectConfirmationEvidence.FR,new byte[0]).isEmpty());}
 @Test void foreignCaseCannotAcquireNoteFromOwnedNativeProof()throws Exception{Files.writeString(path(),"{}");assertTrue(reader().evaluate(context(true),"IIP-SSO01-a-idp-01",new byte[0]).isEmpty());}
 @Test void bareNoCapabilityClaimCannotAcquireNote()throws Exception{Files.writeString(path(),"{\"restored\":true,\"multipleAttesters\":false,\"foreignAttester\":false}");nv(true);}
 @Test void malformedOwnedProofCannotEscapeIntoFallback()throws Exception{Files.writeString(path(),"not JSON");assertTrue(reader().exists(RUN));nv(true);}
 @Test void ownedDirectoryCannotEscapeIntoFallback()throws Exception{Files.createDirectory(path());assertTrue(reader().exists(RUN));nv(true);}
 @Test void ownedSymlinkCannotEscapeIntoFallback()throws Exception{Path outside=directory.resolve("outside.json");Files.writeString(outside,"{}");Files.createSymbolicLink(path(),outside);assertTrue(reader().exists(RUN));nv(true);}
 @Test void incompleteHistoryCannotAcquireNote()throws Exception{Files.writeString(path(),"{}");nv(false);}
 @Test void partialOwnedSidecarCannotEscapeIntoFallback()throws Exception{Files.createDirectory(directory.resolve(RUN+".keycloak-subject-confirmation"));assertTrue(reader().exists(RUN));nv(true);}
 @Test void ownedSymlinkSidecarCannotEscapeIntoFallback()throws Exception{Path outside=Files.createDirectory(directory.resolve("outside"));Files.createSymbolicLink(directory.resolve(RUN+".keycloak-subject-confirmation"),outside);assertTrue(reader().exists(RUN));nv(true);}
}
