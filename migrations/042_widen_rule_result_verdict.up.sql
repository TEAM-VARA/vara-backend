-- ============================================================================
-- Migration 041: Widen grc_rule_results.verdict to VARCHAR(20)
--
-- Root cause: migration 040 widened grc_checks.verdict to VARCHAR(20)
-- but missed grc_rule_results.verdict (still VARCHAR(10)).
-- GL evaluator produces INDETERMINATE (13 chars) and NEEDS_REVIEW (12 chars)
-- which overflow VARCHAR(10), causing SaveCheckResult to fail.
-- ============================================================================

ALTER TABLE grc_rule_results
    ALTER COLUMN verdict TYPE VARCHAR(20);
