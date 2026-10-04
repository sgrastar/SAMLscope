package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;

/** Narrow read-only query of four public outcomes. Case state/credentials are never exported. */
public final class ReadShibbolethUiStoredConclusions {
    private static final JsonCodec JSON=new JsonCodec();
    private static final Map<String,Rfc2119Level> LEVELS=Map.of("IIP-MD05-fb-idp-01",Rfc2119Level.SHOULD_NOT,
        "IIP-MD05-fg-idp-01",Rfc2119Level.MUST,"IIP-MD05-fh-idp-01",Rfc2119Level.SHOULD_NOT,"IIP-MD05-fj-idp-01",Rfc2119Level.SHOULD);
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
                        if(!rows.next())throw new IllegalStateException("Missing stored UI case");
                        var document=JSON.mapper().readTree(rows.getString("document_json"));
                        if(!run.equals(document.path("runId").asText())||!id.equals(document.path("caseId").asText())
                            ||!"FINISHED".equals(document.path("status").asText())||rows.getLong("revision")!=document.path("revision").asLong())
                            throw new IllegalStateException("Unfinished/foreign UI case");
                        var outcome=JSON.mapper().treeToValue(document.path("outcome"),CaseOutcome.class);
                        cases.put(id,Map.of("outcome",outcome,"verdict",Evaluator.toVerdict(LEVELS.get(id),outcome)));
                        if(rows.next())throw new IllegalStateException("Duplicate UI case");
                    }
                }
            }
        }else if(args.length==2&&args[0].equals("offline")) {
            var original=JSON.mapper().readTree(Files.readAllBytes(Path.of(args[1])));run=original.path("runId").asText();
            if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||original.path("cases").size()!=LEVELS.size())throw new IllegalArgumentException("Invalid stored case original");
            for(var id:new TreeSet<>(LEVELS.keySet())) {
                var outcome=JSON.mapper().treeToValue(original.path("cases").path(id).path("outcome"),CaseOutcome.class);
                cases.put(id,Map.of("outcome",outcome,"verdict",Evaluator.toVerdict(LEVELS.get(id),outcome)));
            }
        }else throw new IllegalArgumentException("capture Run or offline stored-original.json");
        System.out.println(JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-native-ui-stored-conclusions-v1","runId",run,"cases",cases)));
    }
}
