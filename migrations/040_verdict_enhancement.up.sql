-- ============================================================================
-- Migration 040: Enhanced verdict enum + metadata fields
-- ============================================================================

-- 1. Widen verdict constraint to accept new enum values
ALTER TABLE grc_rule_results
    DROP CONSTRAINT IF EXISTS grc_rule_results_verdict_check;

ALTER TABLE grc_rule_results
    ADD CONSTRAINT grc_rule_results_verdict_check
        CHECK (verdict IS NULL OR verdict IN (
            '준수', '미준수', '검토필요', 'skipped',
            'MET', 'NOT_MET', 'NO_DATA', 'INDETERMINATE', 'NEEDS_REVIEW', 'SKIPPED'));

-- 2. Add new metadata columns (all nullable for backward compat)
ALTER TABLE grc_rule_results
    ADD COLUMN IF NOT EXISTS reason         TEXT,
    ADD COLUMN IF NOT EXISTS missing_inputs JSONB,
    ADD COLUMN IF NOT EXISTS evidence_data  JSONB,
    ADD COLUMN IF NOT EXISTS layer          VARCHAR(5),
    ADD COLUMN IF NOT EXISTS offcluster_satisfaction_conditions JSONB;

-- 3. Widen grc_checks verdict column to accept new values
ALTER TABLE grc_checks
    ALTER COLUMN verdict TYPE VARCHAR(20);

-- 4. Widen grc_pod_graph_evaluations overall_verdict
ALTER TABLE grc_pod_graph_evaluations
    ALTER COLUMN overall_verdict TYPE VARCHAR(20);

-- 5. Add counters to cluster compliance results
ALTER TABLE grc_cluster_compliance_results
    ADD COLUMN IF NOT EXISTS no_data_items        INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS indeterminate_items   INT NOT NULL DEFAULT 0;
