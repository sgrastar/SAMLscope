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
class KeycloakMetadataSupersessionEvidenceFileTest {
 @TempDir Path data;
 @Test void absentOriginalsCannotClassifyNativeHttpFailure(){
  var run="run_0123456789ABCDEFGHJKMNPQRS";var reader=new KeycloakMetadataSupersessionEvidenceFile(data,e->{throw new AssertionError("Missing receipt must not read content");},(r,v)->Optional.empty());
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry> list(String r){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String i,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  for(var id:List.of(MetadataSupersessionProbeTestCase.APPLICATION,MetadataSupersessionProbeTestCase.SUPERSESSION))assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(id,context,new byte[0]).outcome());
 }
 @Test void supersessionRequiresTheSameFullNativeProofAsApplication()throws Exception{
  var run="run_0123456789ABCDEFGHJKMNPQRS";Files.writeString(data.resolve(run+".keycloak-supersession.json"),"{\"schema\":\"samlscope-keycloak-native-supersession-v1\",\"runId\":\""+run+"\"}");
  var reader=new KeycloakMetadataSupersessionEvidenceFile(data,e->{throw new AssertionError("No correlated originals exist");},(r,v)->Optional.empty());
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){return List.of();}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String r,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,true);
  assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(MetadataSupersessionProbeTestCase.SUPERSESSION,context,"<EntityDescriptor/>".getBytes()).outcome());
 }
 @Test void incompleteSupersessionHistoryRemainsUnverified()throws Exception{
  var run="run_0123456789ABCDEFGHJKMNPQRS";Files.writeString(data.resolve(run+".keycloak-supersession.json"),"{}");var reader=new KeycloakMetadataSupersessionEvidenceFile(data,e->{throw new AssertionError("Incomplete history must not read originals");},(r,v)->Optional.empty());
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String r){throw new AssertionError("Incomplete history must not be listed");}public TranscriptEntry record(TranscriptInput i){throw new UnsupportedOperationException();}public TranscriptEntry updateSamlAnalysis(String r,String c,Map<String,Object>s){throw new UnsupportedOperationException();}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),TestPlan.Parameters.defaults(),TestPlan.Interaction.defaults(),Reachability.CONFIRMED,recorder,false);
  assertEquals(Outcome.NOT_VERIFIED,reader.evaluate(MetadataSupersessionProbeTestCase.SUPERSESSION,context,new byte[0]).outcome());
 }
 @Test void originalPathCannotEscapeRunReceiptDirectory(){var reader=new KeycloakMetadataSupersessionEvidenceFile(data,e->new byte[0],(r,v)->Optional.empty());assertFalse(reader.exists("../another-run"));assertFalse(reader.exists(null));}
}
