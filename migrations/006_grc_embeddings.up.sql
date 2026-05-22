-- ============================================================
-- 006_grc_embeddings.up.sql
-- GRC 증적/지침 임베딩 + 클라우드 환경 정보 테이블
-- pgvector 확장은 002_pgvector.up.sql 에서 이미 활성화됨
-- ============================================================

-- ── 1) grc_evidence_files에 임베딩 컬럼 추가 ──
ALTER TABLE grc_evidence_files
  ADD COLUMN IF NOT EXISTS guideline_text      TEXT,
  ADD COLUMN IF NOT EXISTS evidence_embedding   vector(1024),
  ADD COLUMN IF NOT EXISTS guideline_embedding  vector(1024);

-- HNSW 인덱스 (cosine similarity)
CREATE INDEX IF NOT EXISTS idx_grc_evidence_emb
  ON grc_evidence_files USING hnsw (evidence_embedding vector_cosine_ops)
  WHERE evidence_embedding IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_grc_guideline_emb
  ON grc_evidence_files USING hnsw (guideline_embedding vector_cosine_ops)
  WHERE guideline_embedding IS NOT NULL;

-- ── 2) 클라우드 환경 정보 테이블 ──
CREATE TABLE IF NOT EXISTS grc_cloud_environments (
    id              BIGSERIAL     PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    check_id        VARCHAR(20)   REFERENCES grc_checks(check_id) ON DELETE SET NULL,
    resource_type   VARCHAR(50)   NOT NULL,
    resource_name   VARCHAR(255)  NOT NULL,
    namespace       VARCHAR(255),
    cluster_name    VARCHAR(255),
    raw_data        JSONB         NOT NULL,
    extracted_text  TEXT,
    embedding       vector(1024),
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_company
  ON grc_cloud_environments(company_id);

CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_check
  ON grc_cloud_environments(check_id) WHERE check_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_type
  ON grc_cloud_environments(resource_type);

CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_emb
  ON grc_cloud_environments USING hnsw (embedding vector_cosine_ops)
  WHERE embedding IS NOT NULL;
