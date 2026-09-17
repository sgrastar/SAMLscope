-- Only a digest is persisted. Secret key bytes exist only during an evaluation call.
CREATE TABLE run_shared_key_commitments (
    run_id TEXT PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    key_sha256 TEXT NOT NULL
);
