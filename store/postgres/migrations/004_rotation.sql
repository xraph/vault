-- 004_rotation.sql — Rotation policy and record tables.

CREATE TABLE IF NOT EXISTS vault_rotation_policies (
    id                TEXT        PRIMARY KEY,
    secret_key        TEXT        NOT NULL,
    app_id            TEXT        NOT NULL,
    interval_ns       BIGINT      NOT NULL DEFAULT 0,
    enabled           BOOLEAN     NOT NULL DEFAULT FALSE,
    last_rotated_at   TIMESTAMPTZ,
    next_rotation_at  TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (secret_key, app_id)
);

CREATE TABLE IF NOT EXISTS vault_rotation_records (
    id          TEXT        PRIMARY KEY,
    secret_key  TEXT        NOT NULL,
    app_id      TEXT        NOT NULL,
    old_version BIGINT      NOT NULL,
    new_version BIGINT      NOT NULL,
    rotated_by  TEXT        NOT NULL DEFAULT '',
    rotated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rotation_records_key ON vault_rotation_records (secret_key, app_id, rotated_at DESC);
