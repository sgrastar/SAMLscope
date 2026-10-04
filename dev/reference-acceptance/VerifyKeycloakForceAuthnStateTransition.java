package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.*;
import com.samlscope.core.caseexec.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;

/** Read-only proof that central reevaluation adds exactly its preserved prior-result audit. */
public final class VerifyKeycloakForceAuthnStateTransition {
    private static final ObjectMapper JSON=new JsonCodec().mapper();
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static void require(boolean value,String reason){if(!value)throw new IllegalArgumentException(reason);}
    public static void main(String[] args)throws Exception {
        Path data=Path.of(args[0]);String run=args[1];Path output=Path.of(args[2]);
        require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"),"Invalid Run identity");
        String raw;
        try(var connection=java.sql.DriverManager.getConnection("jdbc:sqlite:file:"+data.resolve("samlscope.db")+"?mode=ro");
            var query=connection.prepareStatement("SELECT document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
            query.setString(1,run);query.setString(2,"IIP-IDP06-b-idp-01");
            try(var rows=query.executeQuery()){require(rows.next(),"Missing approved case");raw=rows.getString(1);require(!rows.next(),"Ambiguous approved case");}
        }
        var execution=JSON.readValue(raw,CaseExecution.class);
        require(run.equals(execution.runId())&&"IIP-IDP06-b-idp-01".equals(execution.caseId()),"Foreign stored case");
        var dataWithoutAudit=new LinkedHashMap<String,Object>(execution.state().data());
        Object audit=dataWithoutAudit.remove("previous_recorded_evidence_result");
        require(audit instanceof Map<?,?>&&execution.outcome()!=null
            &&JSON.valueToTree(audit).equals(JSON.valueToTree(execution.outcome().details().get("previous_recorded_evidence_result"))),"Central state/outcome audit differs");
        var report=new TreeMap<String,Object>();report.put("schema","samlscope-keycloak-forceauthn-state-transition-v1");
        report.put("runId",run);report.put("caseId",execution.caseId());report.put("revision",execution.revision());
        report.put("documentSha256",hash(raw.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        report.put("stateSha256",hash(JSON.writeValueAsBytes(execution.state())));
        report.put("stateWithoutPriorAuditSha256",hash(JSON.writeValueAsBytes(new CaseState(execution.state().phase(),dataWithoutAudit))));
        report.put("stateAuditEqualsOutcomeAudit",true);report.put("priorResultAudit",audit);
        Files.write(output,JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(report));
    }
}
