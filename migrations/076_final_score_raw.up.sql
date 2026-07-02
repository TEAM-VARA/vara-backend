-- final_scores에 clamp(100 상한) 적용 전 raw 점수를 저장한다.
-- final_score       : 0~100 (상한 clamp, ISMS-P 가산 포함) — 화면 표시·등급용
-- final_score_raw   : 상한 없는 원점수 (ISMS-P 가산 포함) — 동점(100) 파드 랭킹 tiebreak용
--                     예) (Global×0.7 + Exposure×0.3) × Toxic + ISMS-P가산 = 189.3
ALTER TABLE final_scores ADD COLUMN IF NOT EXISTS final_score_raw DOUBLE PRECISION;
