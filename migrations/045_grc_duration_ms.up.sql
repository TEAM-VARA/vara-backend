ALTER TABLE grc_cluster_compliance_results
    ADD COLUMN IF NOT EXISTS duration_ms BIGINT NOT NULL DEFAULT 0;
