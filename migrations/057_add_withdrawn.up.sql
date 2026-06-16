-- 056_add_withdrawn.up.sql
--
-- package_vulnerabilities에 OSV의 "철회(withdrawn)" 시점 저장.
--   withdrawn_at : OSV가 이 권고를 철회/무효화한 시각 (있으면 진짜 취약점이 아님)
--
-- 용도: 철회된 CVE를 알림·타임라인·패치현황·역추적·대응속도 집계에서 제외.
-- nullable — 대부분의 정상 CVE는 NULL.

ALTER TABLE package_vulnerabilities
    ADD COLUMN IF NOT EXISTS withdrawn_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_pkgvuln_withdrawn
    ON package_vulnerabilities (withdrawn_at)
    WHERE withdrawn_at IS NOT NULL;

COMMENT ON COLUMN package_vulnerabilities.withdrawn_at IS 'OSV 권고 철회 시각 (OSV withdrawn). NOT NULL이면 무효 CVE → 집계 제외';
