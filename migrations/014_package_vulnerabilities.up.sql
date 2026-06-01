-- ============================================================================
-- VARA Package Vulnerabilities — PURL → CVE 매칭 (osv.dev)
-- ============================================================================
--
-- 작업 B-5에서 추출한 PURL을 osv.dev API로 보내 매칭되는 취약점을 받습니다.
--
-- 흐름:
--   sbom_packages.purl
--     ↓ osv.dev API 호출
--   package_vulnerabilities (PURL × CVE)
--
-- 동시에 캐시 (24h TTL):
--   package_osv_queries (이미 조회한 PURL 기록)
-- ============================================================================

-- ─────────────────────────────────────────
-- 1. 취약점 매핑
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS package_vulnerabilities (
    id              BIGSERIAL PRIMARY KEY,

    -- 패키지 식별
    purl            TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,

    -- 취약점
    vuln_id         TEXT NOT NULL,        -- CVE-2017-3735 / GHSA-... / GO-2024-...
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    summary         TEXT,
    severity_score  NUMERIC(3, 1),        -- CVSS 0.0~10.0
    severity_vector TEXT,
    severity_label  TEXT,                 -- Critical/High/Medium/Low/None (도출)

    -- 시점
    fetched_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,

    UNIQUE (purl, vuln_id)
);

CREATE INDEX IF NOT EXISTS idx_pkgvuln_purl       ON package_vulnerabilities (purl);
CREATE INDEX IF NOT EXISTS idx_pkgvuln_vuln_id    ON package_vulnerabilities (vuln_id);
CREATE INDEX IF NOT EXISTS idx_pkgvuln_name       ON package_vulnerabilities (name);
CREATE INDEX IF NOT EXISTS idx_pkgvuln_severity   ON package_vulnerabilities (severity_score DESC);
CREATE INDEX IF NOT EXISTS idx_pkgvuln_expires    ON package_vulnerabilities (expires_at);

-- ─────────────────────────────────────────
-- 2. PURL별 osv.dev 조회 기록 (캐시 + 빈 응답도 기록)
-- ─────────────────────────────────────────
--
-- 목적: 취약점이 0건이어도 "이미 조회함"을 기록하여
--       동일 PURL 반복 호출 방지.

CREATE TABLE IF NOT EXISTS package_osv_queries (
    purl            TEXT PRIMARY KEY,
    queried_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    vuln_count      INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_osv_query_expires ON package_osv_queries (expires_at);
