-- 001_secrets.sql — Secret storage tables.

CREATE TABLE IF NOT EXISTS vault_secrets (
    id          TEXT        PRIMARY KEY,
    key         TEXT        NOT NULL,
    app_id      TEXT        NOT NULL,
    encrypted_value BYTEA   NOT NULL,
    encryption_alg  TEXT    NOT NULL DEFAULT '',
    encryption_key_id TEXT  NOT NULL DEFAULT '',
    version     BIGINT      NOT NULL DEFAULT 1,
    metadata    JSONB       DEFAULT '{}',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key, app_id)
);

CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id              TEXT        PRIMARY KEY,
    secret_key      TEXT        NOT NULL,
    app_id          TEXT        NOT NULL,
    version         BIGINT      NOT NULL,
    encrypted_value BYTEA       NOT NULL,
    created_by      TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_key, app_id, version)
);

CREATE INDEX IF NOT EXISTS idx_secret_versions_key ON vault_secret_versions (secret_key, app_id);
