-- 최신 버전 조회 인덱스 제거
DROP INDEX IF EXISTS idx_grc_guidelines_latest;

-- 버전 포함 유니크 인덱스 제거
DROP INDEX IF EXISTS uq_grc_guidelines_item_file_ver;
DROP INDEX IF EXISTS uq_grc_guidelines_company_file_ver;

-- 동일 (company_id, isms_p_item_id, filename) 중복 버전 정리 (최신 version만 남김) — 030 유니크 복원 전 필수
DELETE FROM grc_guidelines g
USING grc_guidelines newer
WHERE g.company_id = newer.company_id
  AND g.filename = newer.filename
  AND g.isms_p_item_id IS NOT DISTINCT FROM newer.isms_p_item_id
  AND g.version < newer.version;

-- 030의 (버전 미포함) 유니크 인덱스 복원
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_item_file
    ON grc_guidelines (company_id, isms_p_item_id, filename)
    WHERE isms_p_item_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_company_file
    ON grc_guidelines (company_id, filename)
    WHERE isms_p_item_id IS NULL;

-- version 컬럼 제거
ALTER TABLE grc_guidelines DROP COLUMN IF EXISTS version;
