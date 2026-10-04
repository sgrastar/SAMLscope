package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.DefaultCaseContext;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeycloakPersistentPairwiseEvidenceTest {
 private static final String RUN="run_00000000000000000000000000";
 @TempDir Path root;
 private DefaultCaseContext context(boolean complete){return new DefaultCaseContext(RUN,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,new TranscriptRecorder(){public List<TranscriptEntry>list(String run){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new AssertionError("Read-only native observer");}public TranscriptEntry updateSamlAnalysis(String id,String c,Map<String,Object>s){throw new AssertionError("Unchanged originals");}},complete);}
 private KeycloakPersistentPairwiseEvidence reader(){return new KeycloakPersistentPairwiseEvidence(root,e->new byte[0],run->new byte[0],run->Optional.empty());}
 private Path receipt(){return root.resolve(RUN+".keycloak-pairwise.json");}
 private void unproven(){var value=reader().evaluate(context(true)).orElseThrow();assertEquals(Outcome.NOT_VERIFIED,value.outcome());assertEquals("idp.persistent-pairwise.unproven",value.reasonCode());assertTrue(value.evidence().isEmpty());}
 @Test void absentNativeProofRetainsFallback(){assertFalse(reader().exists(RUN));assertTrue(reader().evaluate(context(true)).isEmpty());}
 @Test void statementsWithoutOriginalsCannotConclude()throws Exception{Files.writeString(receipt(),"{\"schema\":\""+KeycloakPersistentPairwiseEvidence.SCHEMA+"\",\"runId\":\""+RUN+"\",\"samePrincipal\":true,\"restored\":true}");assertTrue(reader().exists(RUN));unproven();}
 @Test void incompleteHistoryNeverConcludes()throws Exception{Files.writeString(receipt(),"{}");assertEquals(Outcome.NOT_VERIFIED,reader().evaluate(context(false)).orElseThrow().outcome());}
 @Test void directoryReceiptIsOwnedButRejected()throws Exception{Files.createDirectory(receipt());assertTrue(reader().exists(RUN));unproven();}
 @Test void symlinkReceiptIsOwnedButRejected()throws Exception{var file=root.resolve("other.json");Files.writeString(file,"{}");Files.createSymbolicLink(receipt(),file);assertTrue(reader().exists(RUN));unproven();}
 @Test void foreignRunCannotOwnAnotherReceipt()throws Exception{Files.writeString(receipt(),"{}");assertFalse(reader().exists("../"+RUN));assertFalse(reader().exists("run_foreign"));}
}
