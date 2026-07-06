-- 052_risk_scoring_ismsp: /risk/details 에 ISMS-P 미준수 가산(위반 룰) 내역을 저장한다.
--
-- 배경: POST /pods/{id}/risk 응답에는 ismsp_risk(위반 룰 목록)가 담기지만 DB에는
--       저장되지 않아 GET /pods/{id}/risk/details 재조회 시 사라졌다. 이 컬럼에
--       ISMS-P 가산 내역(JSON: addend · count_high/medium/low · rules[])을 그대로 보존한다.
--
-- 주의: risk_scoring_results 테이블은 과거 추적된 마이그레이션 외부에서 생성되어
--       리포지토리에 CREATE 문이 없다. 신규 환경에서도 안전하도록 IF NOT EXISTS로
--       테이블을 방어적으로 보장한 뒤 컬럼을 추가한다(기존 DB에서는 no-op).

CREATE TABLE IF NOT EXISTS risk_scoring_results (
    pod_id            TEXT PRIMARY KEY,
    image_name        TEXT,
    image_digest      TEXT,
    result_json       JSONB,
    details_json      JSONB,
    digest_check_json JSONB,
    computed_at       TIMESTAMPTZ
);

ALTER TABLE risk_scoring_results
    ADD COLUMN IF NOT EXISTS ismsp_risk_json JSONB;
