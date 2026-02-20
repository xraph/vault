-- 005_audit.sql — Audit log table.

CREATE TABLE IF NOT EXISTS vault_audit (
    id          TEXT        PRIMARY KEY,
    action      TEXT        NOT NULL,
    resource    TEXT        NOT NULL,
    key         TEXT        NOT NULL DEFAULT '',
    app_id      TEXT        NOT NULL DEFAULT '',
    tenant_id   TEXT        NOT NULL DEFAULT '',
    user_id     TEXT        NOT NULL DEFAULT '',
    ip          TEXT        NOT NULL DEFAULT '',
    outcome     TEXT        NOT NULL DEFAULT 'success',
    metadata    JSONB       DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_app ON vault_audit (app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_key ON vault_audit (key, app_id, created_at DESC);
