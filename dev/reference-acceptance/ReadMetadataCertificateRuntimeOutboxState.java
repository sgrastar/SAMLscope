package com.samlscope.runner.cases;
import com.samlscope.store.JsonCodec;
import java.sql.DriverManager;
import java.util.*;
/** Selected public outbox identity/status only. No payload, headers, body or credentials are read. */
public final class ReadMetadataCertificateRuntimeOutboxState {
 public static void main(String[]args)throws Exception{
  if(args.length!=1||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe run");var rows=new ArrayList<Map<String,Object>>();
  try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");var statement=connection.prepareStatement("SELECT action_id,status,transcript_entry_id,created_at,updated_at FROM outbox_actions WHERE run_id=? AND case_id=? ORDER BY created_at,action_id")){
   statement.setString(1,args[0]);statement.setString(2,"IIP-MD06-a6-idp-01");try(var result=statement.executeQuery()){while(result.next()){var row=new TreeMap<String,Object>();for(var name:List.of("action_id","status","transcript_entry_id","created_at","updated_at"))row.put(name,result.getString(name));rows.add(row);}}
  }var json=new JsonCodec();json.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);System.out.println(json.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("runId",args[0],"caseId","IIP-MD06-a6-idp-01","rows",rows,"count",rows.size(),"readonly",true)));
 }
}
