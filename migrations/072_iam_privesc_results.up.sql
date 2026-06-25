-- migrations/066_iam_privesc_results.up.sql
--
-- IAM 권한상승 탐지 — 결과 테이블(탐지 코드가 적재 → 대시보드/리포트가 읽음).
--
-- 모델: 탐지 "실행(run)" 단위로 누적(append). 소스는 최신만 유지하지만,
--   result 쪽은 실행 이력을 남겨 룰셋 변경 전후 비교·추세 확인이 가능하다.
--   "현재 posture"는 아래 뷰로 계정별 최신 run만 조회.

-- 탐지 실행 1건 = 한 계정 스냅샷에 대한 한 번의 룰셋 평가.
CREATE TABLE IF NOT EXISTS scan_runs (
    run_id            BIGSERIAL   PRIMARY KEY,
    account_id        TEXT        NOT NULL,
    account_alias     TEXT,
    source_scanned_at TIMESTAMPTZ,                 -- 평가한 스냅샷의 snapshot_at
    ruleset_name      TEXT,
    ruleset_version   TEXT,
    core_only         BOOLEAN     NOT NULL DEFAULT FALSE,
    total_principals  INTEGER     NOT NULL DEFAULT 0,
    critical_count    INTEGER     NOT NULL DEFAULT 0,
    warning_count     INTEGER     NOT NULL DEFAULT 0,
    info_count        INTEGER     NOT NULL DEFAULT 0,
    ok_count          INTEGER     NOT NULL DEFAULT 0,
    detected_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- principal(User/Role/Group) 1개당 1행: 해당 run에서의 최종 상태.
CREATE TABLE IF NOT EXISTS principal_results (
    id             BIGSERIAL  PRIMARY KEY,
    run_id         BIGINT     NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    account_id     TEXT       NOT NULL,
    principal_kind TEXT       NOT NULL,            -- user | role | group
    principal_name TEXT       NOT NULL,
    principal_arn  TEXT       NOT NULL,
    status         TEXT       NOT NULL,            -- critical | warning | info | ok
    notes          JSONB      NOT NULL DEFAULT '[]'::jsonb   -- 권한경계/신뢰정책 등 보조 노트
);

-- 발견 항목 1개당 1행(단일 룰 또는 콤보). principal당 0..N개.
CREATE TABLE IF NOT EXISTS findings (
    id             BIGSERIAL  PRIMARY KEY,
    run_id         BIGINT     NOT NULL REFERENCES scan_runs(run_id) ON DELETE CASCADE,
    account_id     TEXT       NOT NULL,
    principal_kind TEXT       NOT NULL,
    principal_name TEXT       NOT NULL,
    principal_arn  TEXT       NOT NULL,
    finding_type   TEXT       NOT NULL,            -- rule | combo
    rule_id        TEXT       NOT NULL,
    action         TEXT       NOT NULL,            -- 매칭된 IAM 액션(콤보는 "a + b")
    severity       TEXT       NOT NULL,            -- 보정 후 위험도
    base_severity  TEXT       NOT NULL,            -- 룰 정의상 기본 위험도
    is_core        BOOLEAN    NOT NULL DEFAULT FALSE,
    title_ko       TEXT,
    category       TEXT,
    notes          JSONB      NOT NULL DEFAULT '[]'::jsonb,   -- 위험도 보정 사유 등
    sources        JSONB      NOT NULL DEFAULT '[]'::jsonb,   -- 권한 출처 정책 목록
    aws_doc        TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_account        ON scan_runs (account_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_principal_results_run    ON principal_results (run_id);
CREATE INDEX IF NOT EXISTS idx_principal_results_status ON principal_results (status);
CREATE INDEX IF NOT EXISTS idx_findings_run            ON findings (run_id);
CREATE INDEX IF NOT EXISTS idx_findings_account_sev    ON findings (account_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_rule           ON findings (rule_id);

-- 뷰: 계정별 "현재 posture" = 계정마다 가장 최근 run.
CREATE OR REPLACE VIEW latest_scan_runs AS
SELECT DISTINCT ON (account_id) *
FROM scan_runs
ORDER BY account_id, detected_at DESC, run_id DESC;

-- 현재 시점의 위험 principal(양호 제외) 목록.
CREATE OR REPLACE VIEW current_flagged_principals AS
SELECT pr.*
FROM principal_results pr
JOIN latest_scan_runs lr ON lr.run_id = pr.run_id
WHERE pr.status <> 'ok';

-- 현재 시점의 발견 항목 전체.
CREATE OR REPLACE VIEW current_findings AS
SELECT f.*
FROM findings f
JOIN latest_scan_runs lr ON lr.run_id = f.run_id;
