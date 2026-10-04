package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.sql.DriverManager;
import java.util.*;

/** Read-only public state/outcome projection for exactly the two metadata application cases. */
public final class ReadMetadataApplicationStoredConclusions {
    private static final List<String> CASES=List.of("IIP-MD06-a-idp-01","IIP-MD06-ab-idp-01");
    private static final JsonCodec JSON=new JsonCodec();
    public static void main(String[] args) throws Exception {
        if(args.length!=1||!args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Run required");
        String run=args[0];var values=new TreeMap<String,Object>();
        try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
            var statement=connection.prepareStatement("SELECT revision,updated_at,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
            for(String id:CASES) {
                statement.setString(1,run);statement.setString(2,id);
                try(var rows=statement.executeQuery()) {
                    if(!rows.next())throw new IllegalStateException("Missing approved case slot");
                    var doc=JSON.mapper().readTree(rows.getString("document_json"));
                    require(run.equals(doc.path("runId").asText())&&id.equals(doc.path("caseId").asText())&&doc.path("revision").asLong()==rows.getLong("revision"));
                    var value=new LinkedHashMap<String,Object>();value.put("status",doc.path("status").asText());value.put("revision",doc.path("revision").asLong());
                    value.put("updatedAt",doc.path("updatedAt"));value.put("updatedAtIso",java.time.Instant.parse(rows.getString("updated_at")).toString());
                    var outcome=doc.path("outcome").isNull()?null:JSON.mapper().treeToValue(doc.path("outcome"),CaseOutcome.class);
                    value.put("outcome",outcome);value.put("verdict",outcome==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,outcome));
                    var state=doc.path("state");value.put("phase",state.path("phase").asText());
                    var fixture=state.path("data").path("fixture_id");value.put("fixtureId",fixture.isTextual()?fixture.asText():null);
                    try(var box=connection.prepareStatement("SELECT status,COUNT(*) AS n FROM outbox_actions WHERE run_id=? AND case_id=? GROUP BY status")) {
                        box.setString(1,run);box.setString(2,id);long count=0;var boxes=new ArrayList<Map<String,Object>>();
                        try(var entries=box.executeQuery()){while(entries.next()){long n=entries.getLong("n");count+=n;boxes.add(Map.of("status",entries.getString("status"),"count",n));}}
                        value.put("outboxCount",count);value.put("outboxStates",boxes);
                    }
                    values.put(id,value);require(!rows.next());
                }
            }
        }
        System.out.println(JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-metadata-application-stored-conclusion-v1","runId",run,"cases",values)));
    }
    private static void require(boolean condition){if(!condition)throw new IllegalStateException("Ambiguous/foreign native application state");}
}
