-- ============================================================================
-- VARA SBOM Packages — PURL 단위로 정규화
-- ============================================================================
--
-- sboms.raw_data (JSONB)는 Trivy SBOM 통째로 저장.
-- 본 테이블은 그 안의 모든 패키지를 PURL 단위로 펼쳐서 저장합니다.
--
-- 효과:
--   - 패키지/버전 검색 빠름 (인덱스 활용)
--   - osv.dev 등 외부 도구 호환 (PURL 표준)
--   - 패키지 인벤토리, 라이센스 추적 등 분석에 활용
--
-- 작업 흐름:
--   sbom_service.go가 sboms 저장 시 자동으로 sbom_packages도 채움.
-- ============================================================================

CREATE TABLE IF NOT EXISTS sbom_packages (
    id              BIGSERIAL PRIMARY KEY,

    -- SBOM 참조 (sboms.image_digest와 동일)
    image_digest    TEXT NOT NULL,

    -- 패키지 식별
    purl            TEXT NOT NULL,         -- 'pkg:deb/debian/openssl@1.1.0j-1~deb9u1?arch=...'
    name            TEXT NOT NULL,         -- 'openssl'
    version         TEXT NOT NULL,         -- '1.1.0j-1~deb9u1'
    ecosystem       TEXT NOT NULL,         -- 'deb' / 'npm' / 'pypi' / 'maven' / 'golang' / 'apk' / 'rpm'

    -- 메타데이터
    arch            TEXT,                  -- 'amd64' / 'all' / 'noarch'
    src_name        TEXT,                  -- 소스 패키지명 (deb/rpm)
    src_version     TEXT,                  -- 소스 버전
    layer_digest    TEXT,                  -- 이 패키지가 발견된 레이어
    pkg_class       TEXT,                  -- 'os-pkgs' / 'lang-pkgs'
    target          TEXT,                  -- Result.Target ('nginx:1.14.0 (debian 9.5)')
    licenses        TEXT[],                -- ['GPL-2.0-only', 'MIT']

    extracted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (image_digest, purl)
);

CREATE INDEX IF NOT EXISTS idx_sbom_pkg_digest    ON sbom_packages (image_digest);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg_name      ON sbom_packages (name);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg_purl      ON sbom_packages (purl);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg_ecosystem ON sbom_packages (ecosystem);
CREATE INDEX IF NOT EXISTS idx_sbom_pkg_name_ver  ON sbom_packages (name, version);
