package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import java.sql.DriverManager;
import java.util.*;
/** All public outbox row identities/statuses, including Suite-only aborted actions. */
public final class ReadDefaultAlgorithmOutbox {
 public static void main(String[]args)throws Exception{
  if(args.length!=1||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");var rows=new ArrayList<Map<String,Object>>();
  try(var c=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");var q=c.prepareStatement("SELECT case_id,action_id,status,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? ORDER BY created_at,action_id")){q.setString(1,args[0]);try(var rs=q.executeQuery()){while(rs.next()){var n=new TreeMap<String,Object>();for(var f:List.of("case_id","action_id","status","transcript_entry_id","created_at","updated_at"))n.put(f,rs.getString(f));rows.add(n);}}}
  var j=new JsonCodec();j.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);System.out.println(j.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("runId",args[0],"rows",rows,"count",rows.size(),"readonly",true)));
 }
}
