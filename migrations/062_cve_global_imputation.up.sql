-- migrations/061_cve_global_imputation.up.sql
--
-- CVSS 결측 보완(imputation) 메타데이터. NVD에 CVSS가 없을 때
-- OSV severity_score 또는 LLM 추정으로 채운 사실을 기록한다.
--
--   imputation_source: '' (NVD 직접) | 'osv' (OSV severity) | 'ai' (LLM 추정)
--   cvss_imputed     : source='ai'일 때 true (LLM 추정 — confidence 페널티 적용 대상)
--   imputation_confidence: 0~1 (ai 추정 신뢰도; nvd/osv는 1.0)

ALTER TABLE cve_global_scores
    ADD COLUMN IF NOT EXISTS cvss_imputed          BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS imputation_source     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS imputation_confidence REAL    NOT NULL DEFAULT 0;

COMMENT ON COLUMN cve_global_scores.imputation_source     IS '"" NVD직접 | osv | ai';
COMMENT ON COLUMN cve_global_scores.cvss_imputed          IS 'true=LLM 추정(ai). confidence 페널티 적용';
COMMENT ON COLUMN cve_global_scores.imputation_confidence IS 'ai 추정 신뢰도 0~1 (nvd/osv=1.0)';
