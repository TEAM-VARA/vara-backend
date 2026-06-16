-- 055_package_version_releases.up.sql
--
-- deps.dev에서 수집한 패키지 버전별 릴리스 날짜 저장 (3단계).
--   - 릴리스 주기(공급망 건강도) + 보안 대응속도(CVE→fixed 버전 릴리스) 계산의 기반.
--   - GetPackage 1콜로 한 패키지의 전 버전을 받아 적재.
--
-- system: MAVEN/NPM/PYPI/GO/CARGO/RUBYGEMS/NUGET (deps.dev 표기)
-- name:   deps.dev 정규 패키지명 (Maven은 "group:artifact")

CREATE TABLE IF NOT EXISTS package_version_releases (
    system        TEXT        NOT NULL,
    name          TEXT        NOT NULL,
    version       TEXT        NOT NULL,
    published_at  TIMESTAMPTZ,                       -- 릴리스 시각 (없을 수 있음)
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (system, name, version)
);

CREATE INDEX IF NOT EXISTS idx_pkgver_sysname
    ON package_version_releases (system, name);

-- 패키지 단위 조회 캐시 (이미 받은 패키지 재조회 방지, package_osv_queries와 동일 패턴)
CREATE TABLE IF NOT EXISTS depsdev_queries (
    system        TEXT        NOT NULL,
    name          TEXT        NOT NULL,
    queried_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    version_count INT         NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (system, name)
);

CREATE INDEX IF NOT EXISTS idx_depsdev_queries_expires
    ON depsdev_queries (expires_at);

COMMENT ON TABLE package_version_releases IS 'deps.dev 패키지 버전별 릴리스 날짜 (릴리스 주기·보안 대응속도 계산용)';
COMMENT ON TABLE depsdev_queries          IS 'deps.dev 패키지 조회 캐시 (재조회 방지)';
