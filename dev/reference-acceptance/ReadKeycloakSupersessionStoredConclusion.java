package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;

/** Narrow read-only query of public supersession outcome. Case state/credentials are never exported. */
public final class ReadKeycloakSupersessionStoredConclusion {
    private static final JsonCodec JSON=new JsonCodec();
    private static final Map<String,Rfc2119Level> LEVELS=Map.of("IIP-MD06-ab-idp-01",Rfc2119Level.MUST);
    public static void main(String[]args)throws Exception {
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var cases=new TreeMap<String,Object>();String run;
        if(args.length==3&&args[0].equals("capture")&&LEVELS.containsKey(args[2])) {
            run=args[1];if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
                var query=connection.prepareStatement("SELECT revision,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
                for(var id:List.of(args[2])) {
                    query.setString(1,run);query.setString(2,id);
                    try(var rows=query.executeQuery()) {
                        if(!rows.next())throw new IllegalStateException("Missing stored supersession case");
                        var document=JSON.mapper().readTree(rows.getString("document_json"));
                        if(!run.equals(document.path("runId").asText())||!id.equals(document.path("caseId").asText())
                            ||rows.getLong("revision")!=document.path("revision").asLong())
                            throw new IllegalStateException("Unfinished/foreign supersession case");
                        var value=new LinkedHashMap<String,Object>();value.put("status",document.path("status").asText());value.put("revision",document.path("revision").asLong());value.put("updatedAt",document.path("updatedAt"));
                        var outcome=document.path("outcome").isNull()?null:JSON.mapper().treeToValue(document.path("outcome"),CaseOutcome.class);
                        value.put("outcome",outcome);value.put("verdict",outcome==null?null:Evaluator.toVerdict(LEVELS.get(id),outcome));
                        try(var outbox=connection.prepareStatement("SELECT COUNT(*) AS n FROM outbox_actions WHERE run_id=? AND case_id=?")){outbox.setString(1,run);outbox.setString(2,id);try(var count=outbox.executeQuery()){if(!count.next())throw new IllegalStateException("Outbox readback unavailable");value.put("outboxCount",count.getLong("n"));}}
                        cases.put(id,value);
                        if(rows.next())throw new IllegalStateException("Duplicate supersession case");
                    }
                }
            }
        }else if(args.length==2&&args[0].equals("offline")) {
            var original=JSON.mapper().readTree(Files.readAllBytes(Path.of(args[1])));run=original.path("runId").asText();
            if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||original.path("cases").size()!=1)throw new IllegalArgumentException("Invalid stored case original");
            var id=original.path("cases").fieldNames().next();if(!LEVELS.containsKey(id))throw new IllegalArgumentException("Unsupported case");
            var row=original.path("cases").path(id);var outcome=row.path("outcome").isNull()?null:JSON.mapper().treeToValue(row.path("outcome"),CaseOutcome.class);
            var value=new LinkedHashMap<String,Object>();value.put("status",row.path("status").asText());value.put("revision",row.path("revision").asLong());value.put("updatedAt",row.path("updatedAt"));value.put("outcome",outcome);value.put("verdict",outcome==null?null:Evaluator.toVerdict(LEVELS.get(id),outcome));value.put("outboxCount",row.path("outboxCount").asLong());cases.put(id,value);
        }else throw new IllegalArgumentException("capture Run Case or offline stored-original.json");
        System.out.println(JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-keycloak-supersession-stored-conclusion-v1","runId",run,"cases",cases)));
    }
}
