-- VARA 백엔드 초기 스키마 (기본 골격만)
-- 실행: psql -h <host> -U vara -d vara -f 001_init.sql
-- 또는 DBeaver SQL Editor에서 실행

-- Pod 메타데이터
CREATE TABLE IF NOT EXISTS pods (
    pod_uid       TEXT        PRIMARY KEY,
    pod_name      TEXT        NOT NULL,
    namespace     TEXT        NOT NULL,
    node_name     TEXT,
    ip            TEXT,
    image         TEXT,
    image_digest  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 트래픽 데이터
CREATE TABLE IF NOT EXISTS traffic (
    id          BIGSERIAL   PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    bytes       BIGINT,
    packets     BIGINT
);

-- SBOM
CREATE TABLE IF NOT EXISTS sboms (
    id            BIGSERIAL   PRIMARY KEY,
    image         TEXT        NOT NULL,
    image_digest  TEXT        NOT NULL,
    raw_data      JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CVE
CREATE TABLE IF NOT EXISTS cves (
    id            BIGSERIAL   PRIMARY KEY,
    image_digest  TEXT        NOT NULL,
    cve_id        TEXT        NOT NULL,
    severity      TEXT
);
