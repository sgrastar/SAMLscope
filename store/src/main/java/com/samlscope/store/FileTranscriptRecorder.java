package com.samlscope.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import com.samlscope.core.Identifiers;
import com.samlscope.core.transcript.TranscriptEntry;
import com.samlscope.core.transcript.TranscriptHistoryLimitExceeded;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.core.transcript.TranscriptInput;
import com.samlscope.core.transcript.TranscriptRecorder;

public final class FileTranscriptRecorder implements TranscriptRecorder, TranscriptContentReader {
    private final SqliteDatabase database;
    private final JsonCodec json;
    private final Path directory;
    private final Limits limits;
    private final Redactor redactor = new Redactor();

    public FileTranscriptRecorder(SqliteDatabase database, JsonCodec json, Path dataDirectory) {
        this(database, json, dataDirectory, null);
    }

    public FileTranscriptRecorder(
            SqliteDatabase database, JsonCodec json, Path dataDirectory, Limits limits) {
        this.database = database;
        this.json = json;
        this.directory = dataDirectory.resolve("transcripts");
        this.limits = limits;
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            throw new StoreException("Could not create transcript directory", e);
        }
    }

    @Override
    public TranscriptEntry record(TranscriptInput input) {
        var clean = redactor.sanitize(input.headers(), input.body(), input.contentType(), input.rawQuery(), input.url());
        var id = Identifiers.newId("tx");
        var runDirectory = safeRunDirectory(input.runId());
        String bodyRef = null;
        String samlRef = null;
        Connection connection = null;
        try {
            connection = database.open();
            connection.setAutoCommit(false);
            reserveCapacity(
                    connection, input,
                    (long) clean.body().length + input.decodedSaml().length);
            Files.createDirectories(runDirectory);
            bodyRef = writeIfPresent(runDirectory, id + ".body", clean.body());
            samlRef = writeIfPresent(runDirectory, id + ".saml.xml", input.decodedSaml());
            var entry = new TranscriptEntry(
                    id, input.runId(), input.direction(), input.timestamp(), input.correlationId(), input.method(),
                    clean.url(), input.status(), clean.headers(), bodyRef, clean.body().length, samlRef,
                    input.decodedSaml().length, input.contentType(), clean.rawQuery(), input.samlSummary());
            try (var statement = connection.prepareStatement(
                         "INSERT INTO transcript_entries(id, run_id, timestamp, document_json) VALUES(?, ?, ?, ?)")) {
                statement.setString(1, id);
                statement.setString(2, input.runId());
                statement.setString(3, input.timestamp().toString());
                statement.setString(4, json.write(entry));
                statement.executeUpdate();
            }
            connection.commit();
            return entry;
        } catch (CapacityExceeded | AdmissionRateExceeded e) {
            try {
                connection.commit();
            } catch (SQLException commitFailure) {
                rollback(connection);
                throw new StoreException("Could not persist Transcript rejection state", commitFailure);
            }
            throw e;
        } catch (IOException | SQLException e) {
            rollback(connection);
            deleteWrittenContent(bodyRef, samlRef);
            throw new StoreException("Could not record transcript entry", e);
        } catch (RuntimeException e) {
            rollback(connection);
            deleteWrittenContent(bodyRef, samlRef);
            throw e;
        } finally {
            close(connection);
        }
    }

    /** Deletes a Plan and its persisted evidence, releasing global hosted capacity. */
    public boolean deletePlanAndEvidence(String planId) {
        if (planId == null || !planId.matches("plan_[0-9A-HJKMNP-TV-Z]{26}")) {
            throw new IllegalArgumentException("Invalid plan ID");
        }
        var runIds = runIdsForPlan(planId);
        markRunsRejected(runIds);
        var dataDirectory = directory.getParent();
        for (var runId : runIds) {
            deleteTree(directory.resolve(runId));
            deleteTree(dataDirectory.resolve("results").resolve(runId));
            deleteTree(dataDirectory.resolve("target-metadata").resolve(runId + ".xml"));
        }
        // Keep the database rows until all file removals succeed so an interrupted
        // deletion can enumerate the same Runs on retry.
        deleteTree(dataDirectory.resolve("target-metadata").resolve(planId + ".xml"));
        deleteTree(dataDirectory.resolve("keys").resolve(planId));

        try (var connection = database.open()) {
            connection.setAutoCommit(false);
            long releasedEntries = 0;
            long releasedBytes = 0;
            try (var usage = connection.prepareStatement(
                    "SELECT entry_count, stored_bytes FROM transcript_usage WHERE run_id = ?")) {
                for (var runId : runIds) {
                    usage.setString(1, runId);
                    try (var rows = usage.executeQuery()) {
                        if (rows.next()) {
                            releasedEntries += rows.getLong(1);
                            releasedBytes += rows.getLong(2);
                        }
                    }
                }
            }
            boolean deleted;
            try (var delete = connection.prepareStatement("DELETE FROM plans WHERE id = ?")) {
                delete.setString(1, planId);
                deleted = delete.executeUpdate() == 1;
            }
            if (deleted) {
                try (var release = connection.prepareStatement(
                        "UPDATE transcript_global_usage SET "
                                + "entry_count = MAX(0, entry_count - ?), "
                                + "stored_bytes = MAX(0, stored_bytes - ?) WHERE singleton = 1")) {
                    release.setLong(1, releasedEntries);
                    release.setLong(2, releasedBytes);
                    release.executeUpdate();
                }
            }
            connection.commit();
            return deleted;
        } catch (SQLException e) {
            throw new StoreException("Could not delete Plan Transcript evidence", e);
        }
    }

    @Override
    public List<TranscriptEntry> list(String runId) {
        return list(runId, null);
    }

    @Override
    public List<TranscriptEntry> listBounded(String runId, int maximumEntries) {
        if (maximumEntries < 1) throw new IllegalArgumentException("maximumEntries must be positive");
        return list(runId, maximumEntries);
    }

    private List<TranscriptEntry> list(String runId, Integer maximumEntries) {
        var entries = new ArrayList<TranscriptEntry>();
        try (var connection = database.open();
             var statement = connection.prepareStatement(
                     "SELECT document_json FROM transcript_entries WHERE run_id = ? ORDER BY timestamp, id"
                             + (maximumEntries == null ? "" : " LIMIT ?"))) {
            statement.setString(1, runId);
            if (maximumEntries != null) statement.setInt(2, maximumEntries + 1);
            try (var rows = statement.executeQuery()) {
                while (rows.next()) entries.add(json.read(rows.getString(1), TranscriptEntry.class));
            }
            if (maximumEntries != null && entries.size() > maximumEntries) {
                throw new TranscriptHistoryLimitExceeded(runId, maximumEntries);
            }
            return List.copyOf(entries);
        } catch (SQLException e) {
            throw new StoreException("Could not list transcript entries", e);
        }
    }

    @Override
    public TranscriptEntry updateSamlAnalysis(
            String entryId, String correlationId, java.util.Map<String, Object> samlSummary) {
        try (var connection = database.open();
             var select = connection.prepareStatement(
                     "SELECT document_json FROM transcript_entries WHERE id = ?")) {
            select.setString(1, entryId);
            TranscriptEntry existing;
            try (var rows = select.executeQuery()) {
                if (!rows.next()) throw new IllegalArgumentException("Unknown Transcript entry");
                existing = json.read(rows.getString(1), TranscriptEntry.class);
            }
            var updated = new TranscriptEntry(
                    existing.id(), existing.runId(), existing.direction(), existing.timestamp(),
                    correlationId, existing.method(), existing.url(), existing.status(),
                    existing.headers(), existing.bodyRef(), existing.bodyBytes(), existing.decodedSamlRef(),
                    existing.decodedSamlBytes(), existing.contentType(), existing.rawQuery(),
                    java.util.Map.copyOf(samlSummary == null ? java.util.Map.of() : samlSummary));
            try (var update = connection.prepareStatement(
                    "UPDATE transcript_entries SET document_json = ? WHERE id = ?")) {
                update.setString(1, json.write(updated));
                update.setString(2, entryId);
                update.executeUpdate();
            }
            return updated;
        } catch (SQLException e) {
            throw new StoreException("Could not update Transcript summary", e);
        }
    }

    @Override
    public byte[] readDecodedSaml(TranscriptEntry entry) {
        if (entry == null || entry.decodedSamlRef() == null || entry.decodedSamlRef().isBlank()) {
            throw new IllegalArgumentException("Transcript entry has no decoded SAML content");
        }
        var dataRoot = directory.getParent().toAbsolutePath().normalize();
        var resolved = dataRoot.resolve(entry.decodedSamlRef()).normalize();
        if (!resolved.startsWith(directory.toAbsolutePath().normalize())) {
            throw new IllegalArgumentException("Transcript content reference escapes the transcript directory");
        }
        try {
            var bytes = Files.readAllBytes(resolved);
            if (bytes.length != entry.decodedSamlBytes()) {
                throw new StoreException("Decoded SAML content length does not match its Transcript entry");
            }
            return bytes;
        } catch (IOException e) {
            throw new StoreException("Could not read decoded SAML content", e);
        }
    }

    private Path safeRunDirectory(String runId) {
        if (runId == null || !runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")) {
            throw new IllegalArgumentException("Invalid run ID");
        }
        return directory.resolve(runId);
    }

    private String writeIfPresent(Path parent, String name, byte[] bytes) throws IOException {
        if (bytes.length == 0) return null;
        var path = parent.resolve(name);
        Files.write(path, bytes);
        return directory.getParent().relativize(path).toString();
    }

    private void reserveCapacity(
            Connection connection, TranscriptInput input, long additionalBytes)
            throws SQLException {
        var runId = input.runId();
        initializeRunUsage(connection, runId);
        try (var initialize = connection.prepareStatement(
                "INSERT INTO transcript_global_usage(singleton, entry_count, stored_bytes) "
                        + "VALUES(1, 0, 0) ON CONFLICT(singleton) DO NOTHING")) {
            initialize.executeUpdate();
        }

        var runUsage = readUsage(connection,
                "SELECT entry_count, stored_bytes, rejected FROM transcript_usage WHERE run_id = ?",
                runId);
        if (runUsage.rejected()) {
            throw new CapacityExceeded(
                    "Transcript evidence was previously rejected; this Run cannot accept more evidence");
        }
        if (limits != null) {
            if (input.direction() == com.samlscope.core.transcript.Direction.INBOUND) {
                reserveIngressRate(connection, input);
            }
            var globalUsage = readUsage(connection,
                    "SELECT entry_count, stored_bytes, 0 FROM transcript_global_usage WHERE singleton = 1",
                    null);
            if (runUsage.entryCount() >= limits.maximumEntries()
                    || exceeds(runUsage.storedBytes(), additionalBytes, limits.maximumStoredBytes())
                    || globalUsage.entryCount() >= limits.maximumGlobalEntries()
                    || exceeds(
                            globalUsage.storedBytes(), additionalBytes,
                            limits.maximumGlobalStoredBytes())) {
                markRejected(connection, runId);
                throw new CapacityExceeded(
                        "Hosted Transcript capacity is exhausted; this Run cannot be published");
            }
        }

        updateUsage(connection,
                "UPDATE transcript_usage SET entry_count = entry_count + 1, "
                        + "stored_bytes = stored_bytes + ? WHERE run_id = ?",
                additionalBytes, runId);
        updateUsage(connection,
                "UPDATE transcript_global_usage SET entry_count = entry_count + 1, "
                        + "stored_bytes = stored_bytes + ? WHERE singleton = 1",
                additionalBytes, null);
    }

    private void reserveIngressRate(Connection connection, TranscriptInput input) throws SQLException {
        var windowMinute = input.timestamp().getEpochSecond() / 60;
        try (var runRate = connection.prepareStatement(
                "INSERT INTO transcript_ingress_rate(run_id, window_minute, request_count) "
                        + "VALUES(?, ?, 0) ON CONFLICT(run_id) DO UPDATE SET "
                        + "request_count = CASE WHEN window_minute = excluded.window_minute "
                        + "THEN request_count ELSE 0 END, window_minute = excluded.window_minute")) {
            runRate.setString(1, input.runId());
            runRate.setLong(2, windowMinute);
            runRate.executeUpdate();
        }
        try (var globalRate = connection.prepareStatement(
                "INSERT INTO transcript_global_ingress_rate(singleton, window_minute, request_count) "
                        + "VALUES(1, ?, 0) ON CONFLICT(singleton) DO UPDATE SET "
                        + "request_count = CASE WHEN window_minute = excluded.window_minute "
                        + "THEN request_count ELSE 0 END, window_minute = excluded.window_minute")) {
            globalRate.setLong(1, windowMinute);
            globalRate.executeUpdate();
        }
        var runCount = readRateCount(connection,
                "SELECT request_count FROM transcript_ingress_rate WHERE run_id = ?", input.runId());
        var globalCount = readRateCount(connection,
                "SELECT request_count FROM transcript_global_ingress_rate WHERE singleton = 1", null);
        if (runCount >= limits.maximumInboundRequestsPerMinute()
                || globalCount >= limits.maximumGlobalInboundRequestsPerMinute()) {
            markRejected(connection, input.runId());
            throw new AdmissionRateExceeded(
                    "Hosted Transcript ingress rate was exceeded; this Run cannot be published");
        }
        incrementRate(connection,
                "UPDATE transcript_ingress_rate SET request_count = request_count + 1 WHERE run_id = ?",
                input.runId());
        incrementRate(connection,
                "UPDATE transcript_global_ingress_rate SET request_count = request_count + 1 "
                        + "WHERE singleton = 1",
                null);
    }

    private long readRateCount(Connection connection, String sql, String runId) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            if (runId != null) statement.setString(1, runId);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) throw new StoreException("Could not read Transcript ingress rate");
                return rows.getLong(1);
            }
        }
    }

    private void incrementRate(Connection connection, String sql, String runId) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            if (runId != null) statement.setString(1, runId);
            if (statement.executeUpdate() != 1) {
                throw new StoreException("Could not account for Transcript ingress rate");
            }
        }
    }

    private void initializeRunUsage(Connection connection, String runId) throws SQLException {
        try (var initialize = connection.prepareStatement(
                "INSERT INTO transcript_usage(run_id, entry_count, stored_bytes) VALUES(?, 0, 0) "
                        + "ON CONFLICT(run_id) DO NOTHING")) {
            initialize.setString(1, runId);
            initialize.executeUpdate();
        }
    }

    private static boolean exceeds(long current, long additional, long maximum) {
        return current > maximum || additional > maximum - current;
    }

    private Usage readUsage(Connection connection, String sql, String runId) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            if (runId != null) statement.setString(1, runId);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) throw new StoreException("Could not read Transcript capacity");
                return new Usage(rows.getLong(1), rows.getLong(2), rows.getInt(3) == 1);
            }
        }
    }

    private void updateUsage(Connection connection, String sql, long additionalBytes, String runId)
            throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            statement.setLong(1, additionalBytes);
            if (runId != null) statement.setString(2, runId);
            if (statement.executeUpdate() != 1) {
                throw new StoreException("Could not account for Transcript capacity");
            }
        }
    }

    private void markRejected(Connection connection, String runId) throws SQLException {
        try (var reject = connection.prepareStatement(
                "UPDATE transcript_usage SET rejected = 1, "
                        + "rejected_at = COALESCE(rejected_at, ?) WHERE run_id = ?")) {
            reject.setString(1, java.time.Instant.now().toString());
            reject.setString(2, runId);
            if (reject.executeUpdate() != 1) {
                throw new StoreException("Could not persist Transcript rejection state");
            }
        }
        try (var unpublish = connection.prepareStatement(
                "DELETE FROM published_runs WHERE run_id = ?")) {
            unpublish.setString(1, runId);
            unpublish.executeUpdate();
        }
    }

    private List<String> runIdsForPlan(String planId) {
        var runIds = new ArrayList<String>();
        try (var connection = database.open();
             var statement = connection.prepareStatement("SELECT id FROM runs WHERE plan_id = ?")) {
            statement.setString(1, planId);
            try (var rows = statement.executeQuery()) {
                while (rows.next()) runIds.add(rows.getString(1));
            }
            return List.copyOf(runIds);
        } catch (SQLException e) {
            throw new StoreException("Could not list Plan Runs for Transcript deletion", e);
        }
    }

    private void markRunsRejected(List<String> runIds) {
        if (runIds.isEmpty()) return;
        try (var connection = database.open()) {
            connection.setAutoCommit(false);
            for (var runId : runIds) {
                initializeRunUsage(connection, runId);
                markRejected(connection, runId);
            }
            connection.commit();
        } catch (SQLException e) {
            throw new StoreException("Could not protect Runs before Transcript deletion", e);
        }
    }

    private void deleteTree(Path root) {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            for (var path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        } catch (IOException e) {
            throw new StoreException("Could not delete Plan Transcript content", e);
        }
    }

    private void deleteWrittenContent(String... references) {
        for (var reference : references) {
            if (reference == null) continue;
            try {
                Files.deleteIfExists(directory.getParent().resolve(reference).normalize());
            } catch (IOException ignored) {
                // A failed database transaction must not be hidden by best-effort orphan cleanup.
            }
        }
    }

    private static void rollback(Connection connection) {
        if (connection == null) return;
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // Preserve the original failure.
        }
    }

    private static void close(Connection connection) {
        if (connection == null) return;
        try {
            connection.close();
        } catch (SQLException ignored) {
            // The operation has already completed or failed.
        }
    }

    private record Usage(long entryCount, long storedBytes, boolean rejected) {}

    public record Limits(
            int maximumEntries,
            long maximumStoredBytes,
            long maximumGlobalEntries,
            long maximumGlobalStoredBytes,
            int maximumInboundRequestsPerMinute,
            int maximumGlobalInboundRequestsPerMinute) {
        public Limits {
            if (maximumEntries < 1 || maximumStoredBytes < 1
                    || maximumGlobalEntries < 1 || maximumGlobalStoredBytes < 1
                    || maximumInboundRequestsPerMinute < 1
                    || maximumGlobalInboundRequestsPerMinute < 1) {
                throw new IllegalArgumentException("Transcript limits must be positive");
            }
        }
    }

    public static final class CapacityExceeded extends RuntimeException {
        public CapacityExceeded(String message) {
            super(message);
        }
    }

    public static final class AdmissionRateExceeded extends RuntimeException {
        public AdmissionRateExceeded(String message) {
            super(message);
        }
    }
}
