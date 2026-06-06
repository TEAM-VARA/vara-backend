-- agent 수집 경로(/agents/*)가 사용하는 legacy 테이블 복원
-- 배경: 초기 스키마(001_init.sql)가 renumber 때 통째로 누락됨.
--       048(sboms)에 이어 나머지 3종 + 코드가 요구하는 UNIQUE 제약 복원.
-- DDL 기준: internal/repository/postgres/agent_repo.go의 INSERT/ON CONFLICT

-- sboms upsert용 UNIQUE (ON CONFLICT (image_digest) 대응)
DROP INDEX IF EXISTS idx_sboms_image_digest;
CREATE UNIQUE INDEX IF NOT EXISTS uq_sboms_image_digest ON sboms (image_digest);

-- pods (UpsertPod: ON CONFLICT (pod_uid))
CREATE TABLE IF NOT EXISTS pods (
    id           BIGSERIAL   PRIMARY KEY,
    pod_uid      TEXT        NOT NULL UNIQUE,
    pod_name     TEXT,
    namespace    TEXT,
    node_name    TEXT,
    ip           TEXT,
    image        TEXT,
    image_digest TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ,
    deleted_at   TIMESTAMPTZ
);

-- cves (UpsertSBOM: ON CONFLICT (image_digest, cve_id))
CREATE TABLE IF NOT EXISTS cves (
    id                BIGSERIAL        PRIMARY KEY,
    image_digest      TEXT             NOT NULL,
    cve_id            TEXT             NOT NULL,
    severity          TEXT,
    package_name      TEXT,
    installed_version TEXT,
    fixed_version     TEXT,
    cvss_score        DOUBLE PRECISION,
    created_at        TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_cves_digest_cve ON cves (image_digest, cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves (cve_id);

-- traffic (InsertTraffic: 일반 INSERT)
CREATE TABLE IF NOT EXISTS traffic (
    id      BIGSERIAL   PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL,
    src_ip  TEXT        NOT NULL,
    dst_ip  TEXT        NOT NULL,
    bytes   BIGINT,
    packets BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts ON traffic (ts);