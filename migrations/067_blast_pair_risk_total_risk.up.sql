-- total_risk = 소스 파드의 MC 총위험도(= Σ_B reach_prob(A→B), "A 털리면 닿는 파드 기대 개수").
-- 소스 단위 스칼라라 (src,*) 행마다 동일값이 중복 적재된다(의도된 비정규화).
ALTER TABLE blast_pair_risk ADD COLUMN IF NOT EXISTS total_risk real NOT NULL DEFAULT 0;
