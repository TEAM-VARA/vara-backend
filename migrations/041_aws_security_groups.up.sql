CREATE TABLE IF NOT EXISTS aws_security_groups (
    id              BIGSERIAL PRIMARY KEY,
    account_id      TEXT NOT NULL,
    region          TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    group_id        TEXT NOT NULL,
    group_name      TEXT,
    vpc_id          TEXT,
    description     TEXT,
    ingress_rules   JSONB NOT NULL DEFAULT '[]'::JSONB,
    egress_rules    JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, region, snapshot_at, group_id)
);

CREATE INDEX IF NOT EXISTS idx_aws_sg_account_region ON aws_security_groups (account_id, region);
CREATE INDEX IF NOT EXISTS idx_aws_sg_group_id       ON aws_security_groups (group_id);
CREATE INDEX IF NOT EXISTS idx_aws_sg_ingress_gin    ON aws_security_groups USING GIN (ingress_rules);