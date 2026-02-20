-- 003_config.sql — Runtime config and override tables.

CREATE TABLE IF NOT EXISTS vault_config (
    id          TEXT        PRIMARY KEY,
    key         TEXT        NOT NULL,
    value       JSONB       NOT NULL,
    value_type  TEXT        NOT NULL DEFAULT '',
    version     BIGINT      NOT NULL DEFAULT 1,
    description TEXT        NOT NULL DEFAULT '',
    app_id      TEXT        NOT NULL,
    metadata    JSONB       DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key, app_id)
);

CREATE TABLE IF NOT EXISTS vault_config_versions (
    id          TEXT        PRIMARY KEY,
    config_key  TEXT        NOT NULL,
    app_id      TEXT        NOT NULL,
    version     BIGINT      NOT NULL,
    value       JSONB       NOT NULL,
    created_by  TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (config_key, app_id, version)
);

CREATE INDEX IF NOT EXISTS idx_config_versions_key ON vault_config_versions (config_key, app_id);

CREATE TABLE IF NOT EXISTS vault_overrides (
    id          TEXT        PRIMARY KEY,
    key         TEXT        NOT NULL,
    value       JSONB       NOT NULL,
    app_id      TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    metadata    JSONB       DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key, app_id, tenant_id)
);
