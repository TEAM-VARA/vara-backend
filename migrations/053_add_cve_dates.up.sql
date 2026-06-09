-- 053_add_cve_dates.up.sql
--
-- package_vulnerabilities에 OSV의 취약점 공개/수정 시점 저장.
--   published_at : CVE가 공개된 시점 (OSV published)
--   modified_at  : OSV 레코드 최종 수정 시점 (OSV modified)
--
-- 용도: 파드/이미지 단위 CVE 발생 타임라인·빈도 분석 (1단계).
-- 둘 다 nullable — OSV가 일부 권고에 해당 필드를 주지 않을 수 있음.

ALTER TABLE package_vulnerabilities
    ADD COLUMN IF NOT EXISTS published_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS modified_at  TIMESTAMPTZ;

-- 타임라인 집계(published_at 기준 정렬/그룹핑) 가속용
CREATE INDEX IF NOT EXISTS idx_pkgvuln_published_at
    ON package_vulnerabilities (published_at);

COMMENT ON COLUMN package_vulnerabilities.published_at IS 'CVE 공개 시점 (OSV published, RFC3339)';
COMMENT ON COLUMN package_vulnerabilities.modified_at  IS 'OSV 레코드 최종 수정 시점 (OSV modified)';
