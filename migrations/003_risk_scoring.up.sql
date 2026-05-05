-- Risk Scoring 결과 저장 테이블
-- POST /risk 결과를 여기 저장하고 GET /risk/details에서 조회

CREATE TABLE IF NOT EXISTS risk_scoring_results (
    pod_id            TEXT        PRIMARY KEY,
    image_name        TEXT        NOT NULL,
    image_digest      TEXT        NOT NULL,
    result_json       JSONB       NOT NULL,
    details_json      JSONB,
    digest_check_json JSONB,
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_scoring_computed_at
    ON risk_scoring_results (computed_at DESC);
