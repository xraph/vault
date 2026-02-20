-- 002_flags.sql — Feature flag tables.

CREATE TABLE IF NOT EXISTS vault_flags (
    id              TEXT        PRIMARY KEY,
    key             TEXT        NOT NULL,
    type            TEXT        NOT NULL DEFAULT 'bool',
    default_value   JSONB       NOT NULL DEFAULT 'false',
    description     TEXT        NOT NULL DEFAULT '',
    tags            JSONB       DEFAULT '[]',
    variants        JSONB       DEFAULT '[]',
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    app_id          TEXT        NOT NULL,
    metadata        JSONB       DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key, app_id)
);

CREATE TABLE IF NOT EXISTS vault_flag_rules (
    id          TEXT        PRIMARY KEY,
    flag_key    TEXT        NOT NULL,
    app_id      TEXT        NOT NULL,
    priority    INT         NOT NULL DEFAULT 0,
    type        TEXT        NOT NULL,
    config      JSONB       NOT NULL DEFAULT '{}',
    return_value JSONB      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flag_rules_key ON vault_flag_rules (flag_key, app_id, priority);

CREATE TABLE IF NOT EXISTS vault_flag_overrides (
    id          TEXT        PRIMARY KEY,
    flag_key    TEXT        NOT NULL,
    app_id      TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    value       JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (flag_key, app_id, tenant_id)
);
