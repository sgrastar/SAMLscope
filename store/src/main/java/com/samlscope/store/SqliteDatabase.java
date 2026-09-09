package com.samlscope.store;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;

public final class SqliteDatabase {
    private static final String DATABASE_FILENAME = "samlscope.db";
    private static final String LEGACY_DATABASE_FILENAME = "samlier.db";

    private final String jdbcUrl;

    public SqliteDatabase(Path dataDirectory) {
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            throw new StoreException("Could not create data directory", e);
        }
        this.jdbcUrl = "jdbc:sqlite:" + selectDatabasePath(dataDirectory).toAbsolutePath();
        migrate();
    }

    private static Path selectDatabasePath(Path dataDirectory) {
        var current = dataDirectory.resolve(DATABASE_FILENAME);
        var legacy = dataDirectory.resolve(LEGACY_DATABASE_FILENAME);
        if (!Files.exists(current) && Files.exists(legacy)) {
            // Keep using the legacy file in place. Renaming an SQLite database without coordinating
            // its WAL and shared-memory sidecars can discard committed-but-uncheckpointed data.
            return legacy;
        }
        return current;
    }

    public Connection open() {
        try {
            var connection = DriverManager.getConnection(jdbcUrl);
            try (var statement = connection.createStatement()) {
                statement.execute("PRAGMA foreign_keys = ON");
                statement.execute("PRAGMA busy_timeout = 5000");
                statement.execute("PRAGMA journal_mode = WAL");
            } catch (SQLException error) {
                try { connection.close(); }
                catch (SQLException closeError) { error.addSuppressed(closeError); }
                throw error;
            }
            return connection;
        } catch (SQLException e) {
            throw new StoreException("Could not open SQLite database", e);
        }
    }

    private void migrate() {
        try (var connection = open()) {
            connection.setAutoCommit(false);
            try (var statement = connection.createStatement()) {
                statement.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
            }
            applyMigration(connection, 1, "/db/migration/V001__initial_schema.sql");
            applyMigration(connection, 2, "/db/migration/V002__case_execution_outbox.sql");
            applyMigration(connection, 3, "/db/migration/V003__applicability_inputs.sql");
            applyMigration(connection, 4, "/db/migration/V004__run_access_grants.sql");
            applyMigration(connection, 5, "/db/migration/V005__published_runs.sql");
            applyMigration(connection, 6, "/db/migration/V006__run_session_lookup.sql");
            applyMigration(connection, 7, "/db/migration/V007__transcript_usage.sql");
            applyMigration(connection, 8, "/db/migration/V008__target_connections.sql");
            if (applyMigration(connection, 11, "/db/migration/V011__target_revision_summaries.sql")) {
                SqliteTargetConnectionRepository.backfillSummaries(connection, new JsonCodec());
            }
            connection.commit();
        } catch (SQLException | IOException e) {
            throw new StoreException("Could not apply database migrations", e);
        }
    }

    private boolean applyMigration(Connection connection, int version, String resourceName)
            throws SQLException, IOException {
        try (var query = connection.prepareStatement("SELECT 1 FROM schema_migrations WHERE version = ?")) {
            query.setInt(1, version);
            if (query.executeQuery().next()) return false;
        }
        var resource = SqliteDatabase.class.getResourceAsStream(resourceName);
        if (resource == null) throw new StoreException("Missing database migration V" + version);
        var sql = new String(resource.readAllBytes(), StandardCharsets.UTF_8);
        try (var statement = connection.createStatement()) {
            for (var command : sql.split(";")) {
                if (!command.isBlank()) statement.execute(command);
            }
        }
        try (var insert = connection.prepareStatement(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)")) {
            insert.setInt(1, version);
            insert.setString(2, Instant.now().toString());
            insert.executeUpdate();
        }
        return true;
    }
}
