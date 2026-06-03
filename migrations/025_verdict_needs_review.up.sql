-- ============================================================================
-- Migration 025: Add 'additional_evidence' verdict_type + '검토필요' verdict
--
-- verdict_type CHECK: 'additional_evidence' is for informational/report-only
-- rules that always run but do not contribute to pass/fail judgment.
--
-- verdict column: '검토필요' is the new intermediate state for manual rules
-- where a potential finding is detected (matched=true on potential_finding)
-- or the rule genuinely cannot be auto-judged (needs_review).
-- ============================================================================

-- 1. Widen verdict_type to include 'additional_evidence'
ALTER TABLE grc_rule_results
    DROP CONSTRAINT IF EXISTS grc_rule_results_verdict_type_check;

ALTER TABLE grc_rule_results
    ADD CONSTRAINT grc_rule_results_verdict_type_check
        CHECK (verdict_type IS NULL OR verdict_type IN (
            'compliant_indicator',
            'potential_finding',
            'needs_review',
            'additional_evidence'));

-- 2. Widen verdict to include '검토필요'
--    (Only adds constraint if one exists; safe to run multiple times.)
ALTER TABLE grc_rule_results
    DROP CONSTRAINT IF EXISTS grc_rule_results_verdict_check;

ALTER TABLE grc_rule_results
    ADD CONSTRAINT grc_rule_results_verdict_check
        CHECK (verdict IS NULL OR verdict IN (
            '준수', '미준수', '검토필요', 'skipped'));
