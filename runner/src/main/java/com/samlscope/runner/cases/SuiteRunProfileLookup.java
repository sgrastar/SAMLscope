package com.samlscope.runner.cases;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.util.Objects;
import com.samlscope.store.JsonCodec;

/** Read-only profile binding for native evidence adapters that are created inside Runner. */
final class SuiteRunProfileLookup {
    private final Path dataDirectory;

    SuiteRunProfileLookup(Path dataDirectory) {
        this.dataDirectory = Objects.requireNonNull(dataDirectory).toAbsolutePath().normalize();
    }

    String profile(String runId) {
        if (runId == null || !runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")) {
            throw new IllegalArgumentException("Invalid Run identity");
        }
        var current = dataDirectory.resolve("samlscope.db");
        var legacy = dataDirectory.resolve("samlier.db");
        var database = Files.exists(current) ? current : legacy;
        if (!Files.isRegularFile(database)) throw new IllegalArgumentException("Suite database unavailable");
        var url = "jdbc:sqlite:file:" + database + "?mode=ro";
        try (var connection = DriverManager.getConnection(url);
             var statement = connection.prepareStatement("""
                     SELECT p.document_json
                     FROM runs r JOIN plans p ON p.id = r.plan_id
                     WHERE r.id = ?
                     """)) {
            statement.setString(1, runId);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) throw new IllegalArgumentException("Unknown Run");
                var document = new JsonCodec().mapper().readTree(rows.getString(1));
                var profile = document.path("profile");
                if (!profile.isTextual() || rows.next()) throw new IllegalArgumentException("Ambiguous Run profile");
                return profile.asText();
            }
        } catch (java.sql.SQLException | java.io.IOException unavailable) {
            throw new IllegalArgumentException("Could not bind Run profile", unavailable);
        }
    }

    static Path configuredDataDirectory() {
        var current = System.getenv("SAMLSCOPE_DATA_DIR");
        var legacy = System.getenv("SAMLIER_DATA_DIR");
        if (current != null && legacy != null && !current.equals(legacy)) {
            throw new IllegalArgumentException("Conflicting Suite data directories");
        }
        return Path.of(current != null ? current : legacy != null ? legacy : "/data").toAbsolutePath().normalize();
    }
}
