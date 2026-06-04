-- ============================================================================
-- Migration 024: Unified rule results (auto + manual judgment modes)
--
-- Adds manual-judgment columns to grc_rule_results so that both R-rules
-- (auto judgment) and F-findings (manual judgment) can be stored in the
-- same table.  Existing auto-mode rows are not disturbed; all new columns
-- are nullable or carry a safe default.
-- ============================================================================

ALTER TABLE grc_rule_results
    ADD COLUMN IF NOT EXISTS judgment_mode           VARCHAR(10)  NOT NULL DEFAULT 'auto',
    ADD COLUMN IF NOT EXISTS verdict_type            VARCHAR(30),
    ADD COLUMN IF NOT EXISTS matched                 BOOLEAN,
    ADD COLUMN IF NOT EXISTS observation             TEXT,
    ADD COLUMN IF NOT EXISTS evidence_json           JSONB        NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS affected_resources      JSONB        NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS manual_check_areas      JSONB,
    ADD COLUMN IF NOT EXISTS additional_review_items JSONB,
    ADD COLUMN IF NOT EXISTS automation_coverage     JSONB,
    ADD COLUMN IF NOT EXISTS alternative_controls    JSONB,
    ADD COLUMN IF NOT EXISTS compliance_mappings     JSONB,
    ADD COLUMN IF NOT EXISTS kisa_defect_case_refs   JSONB,
    ADD COLUMN IF NOT EXISTS deferred                BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS deferred_reason         TEXT,
    ADD COLUMN IF NOT EXISTS isms_p_item_id          VARCHAR(20);

-- Constraints
ALTER TABLE grc_rule_results DROP CONSTRAINT IF EXISTS grc_rule_results_judgment_mode_check;
ALTER TABLE grc_rule_results ADD  CONSTRAINT grc_rule_results_judgment_mode_check
    CHECK (judgment_mode IN ('auto','manual'));

ALTER TABLE grc_rule_results DROP CONSTRAINT IF EXISTS grc_rule_results_verdict_type_check;
ALTER TABLE grc_rule_results ADD  CONSTRAINT grc_rule_results_verdict_type_check
    CHECK (verdict_type IS NULL OR verdict_type IN ('compliant_indicator','potential_finding','needs_review'));

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_grc_rr_judgment_mode ON grc_rule_results(judgment_mode);
CREATE INDEX IF NOT EXISTS idx_grc_rr_verdict_type  ON grc_rule_results(verdict_type)
    WHERE verdict_type IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_grc_rr_matched       ON grc_rule_results(matched)
    WHERE matched IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_grc_rr_isms_p_item   ON grc_rule_results(isms_p_item_id)
    WHERE isms_p_item_id IS NOT NULL;

-- ============================================================================
-- compliance_findings, finding_evaluations, finding_cluster_summaries are kept
-- as read-only historical archive.  No new data will be written to them after
-- this migration; all new evaluations go into grc_rule_results.
-- ============================================================================
