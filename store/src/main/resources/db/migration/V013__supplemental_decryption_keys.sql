CREATE TABLE supplemental_decryption_keys (
    run_id TEXT PRIMARY KEY NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    document_json TEXT NOT NULL
);
