CREATE TABLE target_connections (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    document_json TEXT NOT NULL
);
CREATE INDEX target_connections_owner ON target_connections(owner_id);
CREATE TABLE target_metadata_revisions (
    connection_id TEXT NOT NULL REFERENCES target_connections(id),
    id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    PRIMARY KEY(connection_id, id)
);
