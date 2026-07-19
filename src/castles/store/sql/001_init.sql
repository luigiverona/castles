CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    account_id TEXT NOT NULL,
    address TEXT NOT NULL,
    UNIQUE(provider, account_id)
);

CREATE TABLE checkpoints (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    successful_at TEXT NOT NULL
);

CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK(mode IN ('initial', 'incremental', 'since', 'full')),
    status TEXT NOT NULL CHECK(status IN ('running', 'complete', 'partial', 'failed')),
    generation TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    discovered INTEGER NOT NULL DEFAULT 0 CHECK(discovered >= 0),
    processed INTEGER NOT NULL DEFAULT 0 CHECK(processed >= 0),
    skipped INTEGER NOT NULL DEFAULT 0 CHECK(skipped >= 0)
);

CREATE TABLE messages (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    generation TEXT NOT NULL,
    message_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY(account_id, generation, message_key)
);

CREATE TABLE findings (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    generation TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    payload TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    PRIMARY KEY(account_id, generation, entity_key)
);

CREATE INDEX messages_account_generation ON messages(account_id, generation);
CREATE INDEX findings_account_generation ON findings(account_id, generation);
CREATE INDEX scans_account_started ON scans(account_id, started_at DESC);

