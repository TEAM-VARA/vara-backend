-- ============================================================================
-- VARA Risk Scoring — Global CVE Score (Phase 1: NVD/EPSS/KEV/ExploitDB)
-- ============================================================================
--
-- CVE 단위 Global Score를 영속화하는 테이블.
-- PostgreSQL을 캐시로도 사용 (expires_at 컬럼).
--
-- Phase 1 (현재):
--   - CVSS:  NVD API에서 조회
--   - EPSS:  FIRST.org API에서 조회
--   - SSVC:  KEV (1차) / ExploitDB (2차) / None (3차) — Vulnrichment 미사용
--
-- Phase 2 (예정):
--   - Vulnrichment를 SSVC의 1차 데이터 소스로 추가
--   - 디렉토리 구조 조사 필요
--
-- 캐시 정책:
--   - 새로 계산되면 expires_at = NOW() + 24시간
--   - 조회 시 expires_at 지났으면 재계산 권장 (애플리케이션 결정)
-- ============================================================================


CREATE TABLE IF NOT EXISTS cve_global_scores (
    cve_id            TEXT PRIMARY KEY,

    -- CVSS (NVD 출처)
    cvss_score        NUMERIC(3, 1),    -- 0.0 ~ 10.0
    cvss_severity     TEXT,             -- CRITICAL/HIGH/MEDIUM/LOW
    cvss_vector       TEXT,
    cvss_found        BOOLEAN NOT NULL DEFAULT FALSE,

    -- EPSS (FIRST.org 출처)
    epss_score        NUMERIC(7, 6),    -- 0.000000 ~ 1.000000
    epss_percentile   NUMERIC(7, 6),
    epss_found        BOOLEAN NOT NULL DEFAULT FALSE,

    -- SSVC-Exploitation (KEV/ExploitDB 기반)
    ssvc_exploitation TEXT NOT NULL,    -- 'active' | 'poc' | 'none'
    ssvc_source       TEXT NOT NULL,    -- 'kev' | 'exploitdb' | 'none'
    in_kev            BOOLEAN NOT NULL DEFAULT FALSE,
    in_exploitdb      BOOLEAN NOT NULL DEFAULT FALSE,

    -- 종합 Global Score
    -- 공식: (0.4 × CVSS/10 + 0.3 × EPSS + 0.3 × SSVC_value) × 100
    global_score      NUMERIC(5, 2) NOT NULL DEFAULT 0,    -- 0.00 ~ 100.00

    -- 항목별 가중 점수 (디버깅용)
    cvss_contribution NUMERIC(5, 2) NOT NULL DEFAULT 0,    -- CVSS_normalized * w_cvss * 100
    epss_contribution NUMERIC(5, 2) NOT NULL DEFAULT 0,
    ssvc_contribution NUMERIC(5, 2) NOT NULL DEFAULT 0,

    -- 캐시
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,

    -- 원본 데이터 (감사/디버깅용)
    raw_nvd           JSONB,
    raw_epss          JSONB,
    raw_kev           JSONB,
    raw_exploitdb     JSONB
);


-- 인덱스
CREATE INDEX IF NOT EXISTS idx_cve_scores_expires
    ON cve_global_scores (expires_at);

CREATE INDEX IF NOT EXISTS idx_cve_scores_global
    ON cve_global_scores (global_score DESC);

CREATE INDEX IF NOT EXISTS idx_cve_scores_severity
    ON cve_global_scores (cvss_severity);

CREATE INDEX IF NOT EXISTS idx_cve_scores_kev
    ON cve_global_scores (in_kev) WHERE in_kev = TRUE;
