-- migrations/077_edges_min_dst_port.up.sql
--
-- edges.min_dst_port 추가 — network(connects_to/observed) 엣지의 방향 판정용.
-- 한 pod 쌍에서 관측된 dst_port의 최소값. <32768 이면 요청(client->server) 방향이 관측된 것.
-- blast_edges 생성 시(LoadObservedFlows) 요청 방향 flow만 쓰기 위해 이 컬럼을 필터한다.
-- edges의 기존 행/방향은 그대로 두고(topology/PageRank 등 다른 소비자 보호) 비파괴적으로 컬럼만 추가한다.
-- connects_to 외 edge_type은 NULL로 남는다.

ALTER TABLE edges
    ADD COLUMN IF NOT EXISTS min_dst_port INTEGER;

COMMENT ON COLUMN edges.min_dst_port IS 'connects_to/observed 전용. 이 pod 쌍에서 관측된 dst_port의 최소값. <32768 이면 요청(client->server) 방향이 관측된 것. blast network 채널 방향 판정용. 다른 edge_type은 NULL.';
