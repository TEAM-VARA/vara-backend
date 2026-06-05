CREATE TABLE IF NOT EXISTS aws_kms_keys (
    id               BIGSERIAL PRIMARY KEY,
    account_id       TEXT NOT NULL,
    region           TEXT NOT NULL,
    snapshot_at      TIMESTAMPTZ NOT NULL,
    key_id           TEXT NOT NULL,
    arn              TEXT,
    key_state        TEXT,          -- Enabled / Disabled / PendingDeletion ...
    key_manager      TEXT,          -- AWS(자동관리) / CUSTOMER(고객관리)
    key_spec         TEXT,          -- SYMMETRIC_DEFAULT / RSA_2048 ...
    enabled          BOOLEAN,
    rotation_enabled BOOLEAN,       -- ★ 자동 키 교체 여부 (ISMS-P 핵심)
    description      TEXT,
    creation_date    TIMESTAMPTZ,
    received_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, region, snapshot_at, key_id)
);

CREATE INDEX IF NOT EXISTS idx_aws_kms_account_region ON aws_kms_keys (account_id, region);
CREATE INDEX IF NOT EXISTS idx_aws_kms_key_id        ON aws_kms_keys (key_id);