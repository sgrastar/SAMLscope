package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;

/** Narrow read-only query of one public SLO outcome. Case state/credentials are never exported. */
public final class ReadShibbolethSloStoredConclusion {
    private static final JsonCodec JSON=new JsonCodec();
    private static final Map<String,Rfc2119Level> LEVELS=Map.of("IIP-IDP17-s-idp-01",Rfc2119Level.MUST);
    public static void main(String[]args)throws Exception {
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        var cases=new TreeMap<String,Object>();String run;
        if(args.length==2&&args[0].equals("capture")) {
            run=args[1];if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
                var query=connection.prepareStatement("SELECT revision,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
                for(var id:new TreeSet<>(LEVELS.keySet())) {
                    query.setString(1,run);query.setString(2,id);
                    try(var rows=query.executeQuery()) {
                        if(!rows.next())throw new IllegalStateException("Missing stored SLO case");
                        var document=JSON.mapper().readTree(rows.getString("document_json"));
                        if(!run.equals(document.path("runId").asText())||!id.equals(document.path("caseId").asText())
                            ||!"FINISHED".equals(document.path("status").asText())||rows.getLong("revision")!=document.path("revision").asLong())
                            throw new IllegalStateException("Unfinished/foreign SLO case");
                        var outcome=JSON.mapper().treeToValue(document.path("outcome"),CaseOutcome.class);
                        cases.put(id,Map.of("outcome",outcome,"verdict",Evaluator.toVerdict(LEVELS.get(id),outcome),
                                "revision",document.path("revision").asLong(),"updatedAt",JSON.mapper().treeToValue(document.path("updatedAt"),java.time.Instant.class).toString()));
                        if(rows.next())throw new IllegalStateException("Duplicate SLO case");
                    }
                }
            }
        }else if(args.length==2&&args[0].equals("offline")) {
            var original=JSON.mapper().readTree(Files.readAllBytes(Path.of(args[1])));run=original.path("runId").asText();
            if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||original.path("cases").size()!=LEVELS.size())throw new IllegalArgumentException("Invalid stored case original");
            for(var id:new TreeSet<>(LEVELS.keySet())) {
                var outcome=JSON.mapper().treeToValue(original.path("cases").path(id).path("outcome"),CaseOutcome.class);
                var saved=original.path("cases").path(id);
                cases.put(id,Map.of("outcome",outcome,"verdict",Evaluator.toVerdict(LEVELS.get(id),outcome),
                        "revision",saved.path("revision").asLong(),"updatedAt",saved.path("updatedAt").asText()));
            }
        }else throw new IllegalArgumentException("capture Run or offline stored-original.json");
        System.out.println(JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-native-slo-stored-conclusions-v1","runId",run,"cases",cases)));
    }
}
