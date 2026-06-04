-- 지침 파일 시간 기준 버전 관리: version 컬럼 추가
-- 같은 (company_id, isms_p_item_id, filename) 재업로드 시 내용이 다르면 version+1로 누적 보관,
-- 내용이 같으면(content_hash 동일) 기존 최신 버전을 재사용한다(서비스 로직).
ALTER TABLE grc_guidelines ADD COLUMN IF NOT EXISTS version INT NOT NULL DEFAULT 1;

-- 030에서 만든 (버전 미포함) 유니크 인덱스 제거 → 버전 포함으로 교체
DROP INDEX IF EXISTS uq_grc_guidelines_item_file;
DROP INDEX IF EXISTS uq_grc_guidelines_company_file;

-- 항목별 지침: (company_id, isms_p_item_id, filename, version) 유니크
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_item_file_ver
    ON grc_guidelines (company_id, isms_p_item_id, filename, version)
    WHERE isms_p_item_id IS NOT NULL;

-- 공용 지침: (company_id, filename, version) 유니크
CREATE UNIQUE INDEX IF NOT EXISTS uq_grc_guidelines_company_file_ver
    ON grc_guidelines (company_id, filename, version)
    WHERE isms_p_item_id IS NULL;

-- 최신 버전 조회 가속 (company_id, isms_p_item_id, filename, version DESC)
CREATE INDEX IF NOT EXISTS idx_grc_guidelines_latest
    ON grc_guidelines (company_id, isms_p_item_id, filename, version DESC);
