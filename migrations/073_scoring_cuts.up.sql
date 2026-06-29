-- migrations/073_scoring_cuts.up.sql
--
-- 위험 등급 컷(Final/Local 공용)을 scoring_weights에 추가한다.
-- 운영자가 대시보드에서 가중치와 함께 조정할 수 있다.
--   emergency : score >= cut_emergency
--   warning   : score >= cut_warning
--   caution   : score >= cut_caution
--   safe      : score <  cut_caution
-- 규칙: 0 <= cut_caution < cut_warning < cut_emergency <= 100 (앱에서 검증)

ALTER TABLE scoring_weights
  ADD COLUMN IF NOT EXISTS cut_emergency NUMERIC(5,2) NOT NULL DEFAULT 75,
  ADD COLUMN IF NOT EXISTS cut_warning   NUMERIC(5,2) NOT NULL DEFAULT 50,
  ADD COLUMN IF NOT EXISTS cut_caution   NUMERIC(5,2) NOT NULL DEFAULT 25;
