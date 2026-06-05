CREATE TABLE IF NOT EXISTS aws_cloudtrail_trails (
    id                          BIGSERIAL PRIMARY KEY,
    account_id                  TEXT NOT NULL,
    region                      TEXT NOT NULL,
    snapshot_at                 TIMESTAMPTZ NOT NULL,
    name                        TEXT NOT NULL,
    trail_arn                   TEXT NOT NULL,
    home_region                 TEXT,
    s3_bucket                   TEXT,
    is_multi_region             BOOLEAN,
    include_global_events       BOOLEAN,
    kms_key_id                  TEXT,           -- 로그 암호화 키 (null이면 미암호화)
    log_file_validation_enabled BOOLEAN,
    is_logging                  BOOLEAN,        -- ★ 실제 로깅 상태 (GetTrailStatus)
    received_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (account_id, region, snapshot_at, trail_arn)
);

CREATE INDEX IF NOT EXISTS idx_aws_ct_account_region ON aws_cloudtrail_trails (account_id, region);