-- migrations/066_iam_privesc_results.down.sql
DROP VIEW IF EXISTS current_findings;
DROP VIEW IF EXISTS current_flagged_principals;
DROP VIEW IF EXISTS latest_scan_runs;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS principal_results;
DROP TABLE IF EXISTS scan_runs;
