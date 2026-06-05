-- Revert grc_rule_results.verdict back to VARCHAR(10)
ALTER TABLE grc_rule_results
    ALTER COLUMN verdict TYPE VARCHAR(10);
