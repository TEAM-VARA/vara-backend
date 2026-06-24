-- choke_score = reach_prob(A→X) × total_risk(X): X를 통과하는 기대 위험(risk-hub 점수).
--   = "A가 X에 닿을 확률" × "X가 퍼뜨리는 기대 규모(total_risk)".
--   행 단위(src,dst)로 사전계산해 둔다(현재는 blast-graph 요청 시 즉석 계산 중 → 적재로 전환).
ALTER TABLE blast_pair_risk ADD COLUMN IF NOT EXISTS choke_score real NOT NULL DEFAULT 0;

-- win_channel = 이 (src→dst) 도달의 대표 경로 종류("host" | "network" | "rbac").
--   엣지 색 결정용. blast_pair_risk는 멀티홉 closure라 "대표 채널" 선정 규칙이 필요하며,
--   값은 MC 사전계산(적재) 코드에서 채운다. 미적재 시 '' (색 없음).
ALTER TABLE blast_pair_risk ADD COLUMN IF NOT EXISTS win_channel text NOT NULL DEFAULT '';
