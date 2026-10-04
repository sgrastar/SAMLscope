package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Instant;
import com.samlscope.store.SqliteDatabase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SuiteRunProfileLookupTest {
    private static final String RUN = "run_0123456789ABCDEFGHJKMNPQRS";
    private static final String PLAN = "plan_0123456789ABCDEFGHJKMNPQRS";
    @TempDir Path directory;

    @Test
    void readsTheProfileThroughTheRunPlanForeignKeyWithoutWriting() throws Exception {
        var database = new SqliteDatabase(directory);
        try (var connection = database.open()) {
            try (var plan = connection.prepareStatement(
                    "INSERT INTO plans(id,document_json,created_at,updated_at) VALUES(?,?,?,?)")) {
                plan.setString(1, PLAN);
                plan.setString(2, "{\"profile\":\"browser_sso_idp\"}");
                plan.setString(3, Instant.EPOCH.toString());
                plan.setString(4, Instant.EPOCH.toString());
                plan.executeUpdate();
            }
            try (var run = connection.prepareStatement(
                    "INSERT INTO runs(id,plan_id,status,document_json,created_at,updated_at) VALUES(?,?,?,?,?,?)")) {
                run.setString(1, RUN); run.setString(2, PLAN); run.setString(3, "COMPLETED");
                run.setString(4, "{}"); run.setString(5, Instant.EPOCH.toString());
                run.setString(6, Instant.EPOCH.toString()); run.executeUpdate();
            }
        }
        var lookup = new SuiteRunProfileLookup(directory);
        assertEquals("browser_sso_idp", lookup.profile(RUN));
        assertThrows(IllegalArgumentException.class,
                () -> lookup.profile("run_00000000000000000000000000"));
    }
}
