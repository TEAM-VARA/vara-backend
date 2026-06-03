-- isms_p_item_id를 nullable로 변경 (회사 공용 지침 지원)
ALTER TABLE grc_guidelines ALTER COLUMN isms_p_item_id DROP NOT NULL;

-- 기존 UNIQUE(company_id, isms_p_item_id, filename) 제거
ALTER TABLE grc_guidelines DROP CONSTRAINT IF EXISTS grc_guidelines_company_id_isms_p_item_id_filename_key;

-- 항목별 지침: (company_id, isms_p_item_id, filename) 유니크
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_item_file
    ON grc_guidelines (company_id, isms_p_item_id, filename)
    WHERE isms_p_item_id IS NOT NULL;

-- 공용 지침: (company_id, filename) 유니크
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_company_file
    ON grc_guidelines (company_id, filename)
    WHERE isms_p_item_id IS NULL;

-- 공용 지침 조회 인덱스
CREATE INDEX IF NOT EXISTS idx_grc_guidelines_company_wide
    ON grc_guidelines (company_id)
    WHERE isms_p_item_id IS NULL;
