package com.samlscope.runner.cases;
import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.DriverManager;
import java.util.*;

/** Read-only selected public conclusion; excludes CaseState and every private credential. */
public final class ReadShibbolethForceAuthnMechanismStoredConclusion {
    private static final JsonCodec JSON=new JsonCodec();
    private static final List<String> CASES=List.of("IIP-IDP06-b-idp-01");
    private static Map<String,Object> record(String status,long revision,String updatedAt,CaseOutcome outcome) {
        if(!Set.of("PENDING","WAITING_CONFIG","WAITING_INPUT","WAITING_INBOUND","FINISHED").contains(status)||(status.equals("FINISHED")!=(outcome!=null)))throw new IllegalArgumentException("Unexpected selected state");
        var value=new TreeMap<String,Object>();value.put("status",status);value.put("revision",revision);value.put("updatedAt",updatedAt);value.put("outcome",outcome);
        value.put("verdict",outcome==null?null:Evaluator.toVerdict(Rfc2119Level.MUST,outcome));return value;
    }
    public static void main(String[]args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("capture Run or offline original");
        JSON.mapper().enable(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
        String run;Map<String,Object> cases=new TreeMap<>();
        if(args[0].equals("capture")) {
            run=args[1];if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("Unsafe Run");
            try(var connection=DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
                var query=connection.prepareStatement("SELECT revision,updated_at,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
                for(String CASE:CASES){query.setString(1,run);query.setString(2,CASE);
                try(var rows=query.executeQuery()) {
                    if(!rows.next())throw new IllegalArgumentException("No selected execution");
                    var document=JSON.mapper().readTree(rows.getString("document_json"));
                    if(!run.equals(document.path("runId").asText())||!CASE.equals(document.path("caseId").asText())
                        ||rows.getLong("revision")!=document.path("revision").asLong())throw new IllegalArgumentException("Foreign selected execution");
                    var outcome=document.path("outcome").isNull()?null:JSON.mapper().treeToValue(document.path("outcome"),CaseOutcome.class);
                    // SQLite stores the original ISO Instant separately; do not round its numeric JSON tree.
                    var at=java.time.Instant.parse(rows.getString("updated_at")).toString();
                    cases.put(CASE,record(document.path("status").asText(),rows.getLong("revision"),at,outcome));
                    if(rows.next())throw new IllegalArgumentException("Duplicate selected execution");
                }}
            }
        }else if(args[0].equals("offline")) {
            var original=JSON.mapper().readTree(Files.readAllBytes(Path.of(args[1])));run=original.path("runId").asText();
            if(!run.matches("run_[0-9A-HJKMNP-TV-Z]{26}")||original.path("cases").size()!=1)throw new IllegalArgumentException("Unsafe original scope");
            for(String CASE:CASES){var item=original.path("cases").path(CASE);var outcome=item.path("outcome").isNull()?null:JSON.mapper().treeToValue(item.path("outcome"),CaseOutcome.class);
            cases.put(CASE,record(item.path("status").asText(),item.path("revision").asLong(),item.path("updatedAt").asText(),outcome));}
        }else throw new IllegalArgumentException("Unknown mode");
        System.out.println(JSON.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("schema","samlscope-shibboleth-forceauthn-mechanism-stored-v1","runId",run,"cases",cases)));
    }
}
