package com.samlscope.runner.cases;
import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;

/** Read-only public case conclusion and central RECOMMENDED verdict; no CaseState/keys. */
public final class ReadDefaultAlgorithmStoredConclusion {
 static final JsonCodec J=new JsonCodec();static final String CASE="IIP-ALG08-c-idp-01";
 static Map<String,Object> row(String status,long revision,String updated,CaseOutcome outcome){if(!Set.of("FINISHED","WAITING_CONFIG","WAITING_INBOUND","WAITING_BROWSER").contains(status)||status.equals("FINISHED")!=(outcome!=null))throw new IllegalArgumentException("Invalid execution");var n=new TreeMap<String,Object>();n.put("status",status);n.put("revision",revision);n.put("updatedAt",updated);n.put("outcome",outcome);n.put("verdict",outcome==null?null:Evaluator.toVerdict(Rfc2119Level.RECOMMENDED,outcome));return n;}
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new IllegalArgumentException("capture Run or offline original");J.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);String run;Map<String,Object> selected;
  if(args[0].equals("capture")){run=args[1];if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");try(var c=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");var q=c.prepareStatement("SELECT revision,updated_at,document_json FROM case_executions WHERE run_id=? AND case_id=?")){q.setString(1,run);q.setString(2,CASE);try(var rs=q.executeQuery()){if(!rs.next())throw new IllegalArgumentException("Selected actual case missing");var n=J.mapper().readTree(rs.getString("document_json"));if(!run.equals(n.path("runId").asText())||!CASE.equals(n.path("caseId").asText())||rs.getLong("revision")!=n.path("revision").asLong())throw new IllegalArgumentException("Foreign case");selected=row(n.path("status").asText(),rs.getLong("revision"),java.time.Instant.parse(rs.getString("updated_at")).toString(),n.path("outcome").isNull()?null:J.mapper().treeToValue(n.path("outcome"),CaseOutcome.class));if(rs.next())throw new IllegalArgumentException("Duplicate case");}}}
  else if(args[0].equals("offline")){var n=J.mapper().readTree(Files.readAllBytes(Path.of(args[1])));run=n.path("runId").asText();if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||n.path("cases").size()!=1)throw new IllegalArgumentException("Unsafe scope");var v=n.path("cases").path(CASE);selected=row(v.path("status").asText(),v.path("revision").asLong(),v.path("updatedAt").asText(),v.path("outcome").isNull()?null:J.mapper().treeToValue(v.path("outcome"),CaseOutcome.class));}
  else throw new IllegalArgumentException("Unknown mode");System.out.println(J.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-default-algorithm-stored-v1","runId",run,"cases",Map.of(CASE,selected))));
 }
}
