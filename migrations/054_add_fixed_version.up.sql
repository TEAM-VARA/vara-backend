-- 054_add_fixed_version.up.sql
--
-- package_vulnerabilities에 OSV가 알려주는 "고쳐진 버전" 저장.
--   fixed_version : 이 CVE가 해결된 패키지 버전 (OSV affected.ranges.events.fixed)
--
-- 용도: "이 버전으로 올리면 해결" 패치 정보 (2단계).
-- nullable — 아직 패치가 없거나(미상), last_affected만 있거나, GIT 커밋 범위면 NULL.
-- 릴리스 "날짜"는 OSV가 주지 않으므로 별도(deps.dev, 3단계).

ALTER TABLE package_vulnerabilities
    ADD COLUMN IF NOT EXISTS fixed_version TEXT;

COMMENT ON COLUMN package_vulnerabilities.fixed_version IS '취약점이 고쳐진 패키지 버전 (OSV fixed). NULL=미상/패치없음';
