package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.samlscope.store.JsonCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Read-only, consistent operation identities; never exports request bodies or credentials. */
public final class ReadRunProtocolOperations {
    private static final ObjectMapper JSON = new JsonCodec().mapper();
    private static String hash(String value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8)));
    }
    private static void require(boolean value, String reason) {
        if (!value) throw new IllegalArgumentException(reason);
    }
    public static void main(String[] args) throws Exception {
        require(args.length == 3, "Expected data-directory, Run, output");
        String run = args[1];
        require(run.matches("run_[0-9A-HJKMNP-TV-Z]{26}"), "Invalid Run");
        Path database = Path.of(args[0]).toAbsolutePath().normalize().resolve("samlscope.db");
        require(Files.isRegularFile(database) && !Files.isSymbolicLink(database), "Actual database required");
        var snapshot = new LinkedHashMap<String, Object>();
        snapshot.put("schema", "samlscope-run-protocol-operations-v1");
        snapshot.put("runId", run);
        try (var connection = DriverManager.getConnection("jdbc:sqlite:file:" + database + "?mode=ro")) {
            connection.setAutoCommit(false);
            try (var query = connection.prepareStatement("SELECT document_json FROM runs WHERE id=?")) {
                query.setString(1, run);
                try (var rows = query.executeQuery()) {
                    require(rows.next(), "Actual Run missing");
                    String original = rows.getString(1);
                    var document = JSON.readTree(original);
                    require(run.equals(document.path("id").asText()), "Run identity mismatch");
                    snapshot.put("planId", document.path("planId").asText());
                    snapshot.put("runStatus", document.path("status").asText());
                    snapshot.put("runDocumentSha256", hash(original));
                    require(!rows.next(), "Duplicate Run");
                }
            }
            snapshot.put("transcriptEntries", transcripts(connection, run));
            snapshot.put("outboxActions", outbox(connection, run));
            snapshot.put("caseExecutions", executions(connection, run));
            connection.rollback();
        }
        snapshot.put("capturedAtUtc", Instant.now().toString());
        Files.write(Path.of(args[2]), JSON.writerWithDefaultPrettyPrinter().writeValueAsBytes(snapshot));
    }
    private static Object transcripts(Connection connection, String run) throws Exception {
        var result = new ArrayList<Map<String, Object>>();
        try (var query = connection.prepareStatement(
                "SELECT id,document_json FROM transcript_entries WHERE run_id=? ORDER BY timestamp,id")) {
            query.setString(1, run);
            try (var rows = query.executeQuery()) {
                while (rows.next()) {
                    require(result.size() < 20_000, "Transcript bound exceeded");
                    String original = rows.getString(2); var entry = JSON.readTree(original);
                    require(run.equals(entry.path("runId").asText())
                            && rows.getString(1).equals(entry.path("id").asText()), "Foreign transcript");
                    var row = new LinkedHashMap<String, Object>();
                    row.put("id", rows.getString(1)); row.put("entrySha256", hash(original));
                    row.put("direction", entry.path("direction").asText());
                    row.put("type", entry.path("samlSummary").path("type").asText());
                    row.put("method", entry.path("method").asText());
                    result.add(row);
                }
            }
        }
        return result;
    }
    private static Object outbox(Connection connection, String run) throws Exception {
        var result = new ArrayList<Map<String, Object>>();
        try (var query = connection.prepareStatement("""
                SELECT action_id,case_id,kind,status,action_json,send_result_json,transcript_entry_id
                FROM outbox_actions WHERE run_id=? ORDER BY created_at,action_id
                """)) {
            query.setString(1, run);
            try (var rows = query.executeQuery()) {
                while (rows.next()) {
                    require(result.size() < 20_000, "Outbox bound exceeded");
                    String original = rows.getString(5); var action = JSON.readTree(original);
                    require(rows.getString(1).equals(action.path("actionId").asText())
                            && rows.getString(3).equals(action.path("kind").asText()), "Outbox identity mismatch");
                    var row = new LinkedHashMap<String, Object>();
                    row.put("actionId", rows.getString(1)); row.put("caseId", rows.getString(2));
                    row.put("kind", rows.getString(3)); row.put("status", rows.getString(4));
                    row.put("actionSha256", hash(original)); row.put("sendResultSha256", hash(rows.getString(6)));
                    row.put("transcriptEntryId", rows.getString(7)); result.add(row);
                }
            }
        }
        return result;
    }
    private static Object executions(Connection connection, String run) throws Exception {
        var result = new ArrayList<Map<String, Object>>();
        try (var query = connection.prepareStatement("""
                SELECT case_id,revision,status,document_json FROM case_executions
                WHERE run_id=? ORDER BY case_id
                """)) {
            query.setString(1, run);
            try (var rows = query.executeQuery()) {
                while (rows.next()) {
                    require(result.size() < 20_000, "Execution bound exceeded");
                    String original = rows.getString(4); var document = JSON.readTree(original);
                    require(run.equals(document.path("runId").asText())
                            && rows.getString(1).equals(document.path("caseId").asText())
                            && rows.getLong(2) == document.path("revision").asLong(), "Execution identity mismatch");
                    result.add(Map.of("caseId", rows.getString(1), "revision", rows.getLong(2),
                            "status", rows.getString(3), "documentSha256", hash(original)));
                }
            }
        }
        return result;
    }
}
