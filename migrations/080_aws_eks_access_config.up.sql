-- migrations/080_aws_eks_access_config.up.sql
CREATE TABLE IF NOT EXISTS cluster_aws_config (
    id                  BIGSERIAL PRIMARY KEY,
    account_id          TEXT,
    region              TEXT,
    cluster_name        TEXT NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    authentication_mode TEXT,
    access_entries      JSONB,
    aws_auth_present    BOOLEAN,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at)
);
