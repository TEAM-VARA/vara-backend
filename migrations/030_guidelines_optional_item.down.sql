-- 공용 지침 데이터 삭제 (NOT NULL 복원 전 필수)
DELETE FROM grc_guidelines WHERE isms_p_item_id IS NULL;

-- 인덱스 제거
DROP INDEX IF EXISTS idx_grc_guidelines_company_wide;
DROP INDEX IF EXISTS uq_grc_guidelines_company_file;
DROP INDEX IF EXISTS uq_grc_guidelines_item_file;

-- NOT NULL 복원
ALTER TABLE grc_guidelines ALTER COLUMN isms_p_item_id SET NOT NULL;

-- 기존 UNIQUE 제약 복원
ALTER TABLE grc_guidelines
    ADD CONSTRAINT grc_guidelines_company_id_isms_p_item_id_filename_key
    UNIQUE (company_id, isms_p_item_id, filename);
