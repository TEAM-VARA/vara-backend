-- ============================================================
-- 006_grc_embeddings.down.sql
-- 롤백: 임베딩 컬럼 제거 + 클라우드 환경 테이블 삭제
-- ============================================================

DROP TABLE IF EXISTS grc_cloud_environments;

ALTER TABLE grc_evidence_files
  DROP COLUMN IF EXISTS guideline_text,
  DROP COLUMN IF EXISTS evidence_embedding,
  DROP COLUMN IF EXISTS guideline_embedding;
