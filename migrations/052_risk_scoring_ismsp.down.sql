-- 052_risk_scoring_ismsp (down): 추가한 컬럼만 제거한다.
-- 테이블 자체는 이 마이그레이션이 생성한 것이 아니므로 유지한다.
ALTER TABLE risk_scoring_results
    DROP COLUMN IF EXISTS ismsp_risk_json;
