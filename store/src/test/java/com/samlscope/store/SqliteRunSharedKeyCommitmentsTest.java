package com.samlscope.store;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqliteRunSharedKeyCommitmentsTest {
    @TempDir Path directory;
    @Test void fixedIdentitySurvivesRestartAndUnknownRunsCannotBind() throws Exception {
        var db = new SqliteDatabase(directory);
        try (var c=db.open(); var s=c.createStatement()) {
            s.executeUpdate("INSERT INTO plans(id,document_json,created_at,updated_at) VALUES('p','{}','now','now')");
            s.executeUpdate("INSERT INTO runs(id,plan_id,status,document_json,created_at,updated_at) VALUES('r','p','CREATED','{}','now','now')");
        }
        var repository = new SqliteRunSharedKeyCommitments(db);
        repository.bind("r", "a".repeat(64));
        repository = new SqliteRunSharedKeyCommitments(new SqliteDatabase(directory));
        repository.bind("r", "a".repeat(64));
        var reopened = repository;
        assertThrows(IllegalArgumentException.class, () -> reopened.bind("r", "b".repeat(64)));
        assertThrows(StoreException.class, () -> reopened.bind("unknown", "a".repeat(64)));
        try (var c=db.open(); var s=c.createStatement(); var rows=s.executeQuery("SELECT key_sha256 FROM run_shared_key_commitments WHERE run_id='r'")) {
            assertTrue(rows.next()); assertEquals("a".repeat(64), rows.getString(1));
        }
    }
}
