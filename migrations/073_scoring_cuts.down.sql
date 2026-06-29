-- migrations/073_scoring_cuts.down.sql
ALTER TABLE scoring_weights
  DROP COLUMN IF EXISTS cut_emergency,
  DROP COLUMN IF EXISTS cut_warning,
  DROP COLUMN IF EXISTS cut_caution;
