package com.samlscope.store;

import java.sql.SQLException;
import java.util.Objects;

/** Atomic, durable Run input identity. This repository never accepts key material. */
public final class SqliteRunSharedKeyCommitments {
    private final SqliteDatabase database;
    public SqliteRunSharedKeyCommitments(SqliteDatabase database) {
        this.database = Objects.requireNonNull(database);
    }
    public void bind(String runId, String digest) {
        if (digest == null || !digest.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("Invalid shared-key digest");
        try (var connection = database.open()) {
            try (var insert = connection.prepareStatement(
                    "INSERT INTO run_shared_key_commitments(run_id,key_sha256) VALUES(?,?) ON CONFLICT(run_id) DO NOTHING")) {
                insert.setString(1, runId); insert.setString(2, digest); insert.executeUpdate();
            }
            try (var query = connection.prepareStatement(
                    "SELECT key_sha256 FROM run_shared_key_commitments WHERE run_id=?")) {
                query.setString(1, runId);
                try (var rows = query.executeQuery()) {
                    if (!rows.next() || !digest.equals(rows.getString(1)))
                        throw new IllegalArgumentException("This Run has a different fixed shared key; create a new Run");
                }
            }
        } catch (SQLException error) { throw new StoreException("Could not bind Run shared-key identity", error); }
    }
}
