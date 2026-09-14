CREATE TABLE application_users (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('ANONYMOUS', 'USER', 'ADMIN')),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DELETING')),
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    enrolled INTEGER NOT NULL DEFAULT 0,
    version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE deleted_user_ids (id TEXT PRIMARY KEY);
INSERT INTO application_users(id, role, created_at)
    SELECT owner_id, 'USER', MIN(p.created_at) FROM hosted_plan_owners o
    JOIN plans p ON p.id = o.plan_id WHERE owner_id LIKE 'oidc:%' GROUP BY owner_id;
INSERT OR IGNORE INTO application_users(id, role, created_at)
    SELECT owner_id, 'USER', strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
    FROM target_connections WHERE owner_id LIKE 'oidc:%';
