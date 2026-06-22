-- migrations/061_cve_global_imputation.down.sql
ALTER TABLE cve_global_scores
    DROP COLUMN IF EXISTS cvss_imputed,
    DROP COLUMN IF EXISTS imputation_source,
    DROP COLUMN IF EXISTS imputation_confidence;
