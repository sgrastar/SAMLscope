package com.samlscope.runner.cases;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.time.Clock;
import java.util.*;
/** Actual production preparation predicate before any baseline credential/outbox. Read-only only. */
public final class ReadDefaultAlgorithmPreparation {
 public static void main(String[]args)throws Exception{
  if(args.length!=1||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");String run=args[0];var data=Path.of("/data");var json=new JsonCodec();var entries=new ArrayList<TranscriptEntry>();
  try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");var statement=connection.prepareStatement("SELECT document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")){statement.setString(1,run);try(var rows=statement.executeQuery()){while(rows.next())entries.add(json.read(rows.getString(1),TranscriptEntry.class));}}
  var recorder=new TranscriptRecorder(){public List<TranscriptEntry>list(String selected){return selected.equals(run)?entries:List.of();}public TranscriptEntry record(TranscriptInput input){throw new AssertionError("Preparation wrote transcript");}public TranscriptEntry updateSamlAnalysis(String id,String correlation,Map<String,Object> summary){throw new AssertionError("Preparation changed original");}};
  var context=new DefaultCaseContext(run,TargetRole.IDP,Clock.systemUTC(),new TestPlan.Parameters(180,45,"reference"),new TestPlan.Interaction(true,false),Reachability.CONFIRMED,recorder,true);var bridge=new KeycloakNativeRunEvidenceBridge(data);var profiles=new SuiteRunProfileLookup(data);
  var reader=new DefaultAlgorithmPreventionEvidence(data.resolve("default-algorithm-evidence"),bridge::content,bridge::targetMetadata,r->bridge.key(r,"control"),profiles::profile,new ShibbolethDefaultAlgorithmNativeAdapter(bridge::content));var preparation=reader.preparation(context).orElseThrow(()->new IllegalArgumentException("Native/default/prepared metadata originals are not ready; no baseline login permitted"));
  System.out.println(json.mapper().writeValueAsString(Map.of("runId",run,"caseId",DefaultAlgorithmComparison.CASE,"profile",profiles.profile(run),"nativePreparationReady",true,"policyId",preparation.policyId(),"keyTransportConsumerAvailable",preparation.keyTransportConsumerAvailable(),"transcriptReferences",preparation.evidence(),"productSettings",0,"protocolSubmissions",0,"credentialPosts",0)));
 }
}
