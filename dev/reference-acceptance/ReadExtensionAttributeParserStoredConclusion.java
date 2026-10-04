package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.*;
import com.samlscope.store.JsonCodec;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.*;

/** Read-only projection of one approved CaseOutcome and its outbox count; never exports CaseState. */
public final class ReadExtensionAttributeParserStoredConclusion {
    public static void main(String[] args) throws Exception {
        if (args.length != 1 || !args[0].matches("run_[0-9A-HJKMNP-TV-Z]{26}")) throw new IllegalArgumentException("Run required");
        var run = args[0]; var json = new JsonCodec().mapper(); var output = new LinkedHashMap<String,Object>();
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:/data/samlscope.db?mode=ro");
                var query = connection.prepareStatement("SELECT revision,updated_at,document_json FROM case_executions WHERE run_id=? AND case_id=?")) {
            query.setString(1, run); query.setString(2, ExtensionAttributeParserEvidence.ID);
            try (var rows = query.executeQuery()) {
                if (!rows.next()) throw new IllegalStateException("Stored case missing");
                var document = json.readTree(rows.getString("document_json"));
                if (!run.equals(document.path("runId").asText()) || !ExtensionAttributeParserEvidence.ID.equals(document.path("caseId").asText())
                        || document.path("revision").asLong() != rows.getLong("revision")) throw new IllegalStateException("Stored identity differs");
                var outcome = document.path("outcome").isNull() ? null : json.treeToValue(document.path("outcome"), CaseOutcome.class);
                output.put("runId", run); output.put("caseId", ExtensionAttributeParserEvidence.ID); output.put("status", document.path("status").asText());
                output.put("revision", rows.getLong("revision")); output.put("updatedAtIso", Instant.parse(rows.getString("updated_at")).toString());
                output.put("outcome", outcome); output.put("verdict", outcome == null ? null : Evaluator.toVerdict(Rfc2119Level.MUST_NOT, outcome));
                if (rows.next()) throw new IllegalStateException("Duplicate stored case");
            }
            try (var count = connection.prepareStatement("SELECT COUNT(*) AS n FROM outbox_actions WHERE run_id=? AND case_id=?")) {
                count.setString(1, run); count.setString(2, ExtensionAttributeParserEvidence.ID);
                try (var rows = count.executeQuery()) { if (!rows.next()) throw new IllegalStateException("Outbox unavailable"); output.put("outboxCount", rows.getLong("n")); }
            }
        }
        System.out.println(json.writerWithDefaultPrettyPrinter().writeValueAsString(output));
    }
}
