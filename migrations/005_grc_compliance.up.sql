-- ============================================================
-- 005_grc_compliance.up.sql
-- GRC 컴플라이언스 정규화 스키마 (5개 테이블)
-- ============================================================

-- 002에서 생성된 불필요 테이블 정리
DROP TABLE IF EXISTS compliance_isms_p_mappings;
DROP TABLE IF EXISTS compliance_exposures;
DROP TABLE IF EXISTS compliance_vulnerabilities;
DROP TABLE IF EXISTS compliance_assets;

-- ── 1) 통합 체크 테이블 ──
CREATE TABLE IF NOT EXISTS grc_checks (
    check_id        VARCHAR(20)   PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    isms_p_item_id  VARCHAR(10)   NOT NULL,
    ruleset_version VARCHAR(20)   NOT NULL DEFAULT '',

    -- 작업 상태
    status          VARCHAR(20)   NOT NULL DEFAULT 'queued',
    progress_pct    SMALLINT      NOT NULL DEFAULT 0
                    CHECK (progress_pct BETWEEN 0 AND 100),
    auto_collect    BOOLEAN       NOT NULL DEFAULT FALSE,

    -- 시간
    submitted_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,

    -- 결과 (완료 시 채워짐)
    verdict         VARCHAR(10),
    severity        VARCHAR(10),
    summary_text    TEXT,
    total_rules     SMALLINT,
    passed_rules    SMALLINT,
    failed_rules    SMALLINT,
    skipped_rules   SMALLINT,
    evidence_count  SMALLINT,

    -- 에러 (실패 시)
    error           JSONB,

    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_grc_checks_company   ON grc_checks(company_id);
CREATE INDEX IF NOT EXISTS idx_grc_checks_status    ON grc_checks(status);
CREATE INDEX IF NOT EXISTS idx_grc_checks_item      ON grc_checks(isms_p_item_id);
CREATE INDEX IF NOT EXISTS idx_grc_checks_verdict   ON grc_checks(verdict) WHERE verdict IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_grc_checks_submitted ON grc_checks(submitted_at DESC);

-- ── 2) 증적 파일 ──
CREATE TABLE IF NOT EXISTS grc_evidence_files (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    filename        VARCHAR(255)  NOT NULL,
    evidence_type   VARCHAR(50)   NOT NULL,
    system          VARCHAR(50),
    description     TEXT,
    storage_path    TEXT          NOT NULL,
    file_size_bytes BIGINT,
    target_rule_ids TEXT[],
    extracted_text  TEXT,
    content_hash    VARCHAR(64),
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_grc_evidence_check ON grc_evidence_files(check_id);
CREATE INDEX IF NOT EXISTS idx_grc_evidence_hash  ON grc_evidence_files(content_hash) WHERE content_hash IS NOT NULL;

-- ── 3) 룰별 평가 결과 ──
CREATE TABLE IF NOT EXISTS grc_rule_results (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    rule_id         VARCHAR(20)   NOT NULL,
    check_category  VARCHAR(50)   NOT NULL,
    evidence_type   VARCHAR(100),
    system          VARCHAR(50),
    verdict         VARCHAR(10)   NOT NULL,
    evidence_files  TEXT[]        NOT NULL DEFAULT '{}',
    matched_indicators TEXT[],
    skip_reason     TEXT,

    UNIQUE (check_id, rule_id)
);

CREATE INDEX IF NOT EXISTS idx_grc_rule_results_check   ON grc_rule_results(check_id);
CREATE INDEX IF NOT EXISTS idx_grc_rule_results_verdict ON grc_rule_results(verdict);
CREATE INDEX IF NOT EXISTS idx_grc_rule_results_rule    ON grc_rule_results(rule_id);

-- ── 4) 위반사항 ──
CREATE TABLE IF NOT EXISTS grc_violations (
    id              BIGSERIAL     PRIMARY KEY,
    rule_result_id  BIGINT        NOT NULL REFERENCES grc_rule_results(id) ON DELETE CASCADE,
    field           VARCHAR(100),
    pattern         VARCHAR(255),
    expected        TEXT,
    actual          TEXT,
    description     TEXT          NOT NULL,
    severity        VARCHAR(10)   NOT NULL DEFAULT 'medium'
);

CREATE INDEX IF NOT EXISTS idx_grc_violations_result ON grc_violations(rule_result_id);

-- ── 5) 개선 권고사항 ──
CREATE TABLE IF NOT EXISTS grc_recommendations (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    rule_id         VARCHAR(20)   NOT NULL,
    action          TEXT          NOT NULL,
    reference       TEXT          NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_grc_recommendations_check ON grc_recommendations(check_id);
