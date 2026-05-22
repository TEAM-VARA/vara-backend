-- migrations/016_edges.up.sql
--
-- Edges 테이블 — Pod 간 통신 관계 저장 (Blast Radius 그래프)
--
-- 한 row = (cluster, source Pod, target Pod, layer, snapshot) 조합
-- 같은 (src, dst) 쌍의 여러 통신은 weight로 집계됨
--
-- 현재 layer: network 만 (host 제외, identity/supply_chain은 추후)

CREATE TABLE IF NOT EXISTS edges (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    
    -- 식별 (Pod-to-Pod)
    source_pod_uid  TEXT NOT NULL,    -- 시작 Pod uid
    target_pod_uid  TEXT NOT NULL,    -- 도착 Pod uid
    layer           TEXT NOT NULL,    -- network / identity / supply_chain
    
    -- 통신 메타 (network layer 기준)
    weight          INTEGER NOT NULL DEFAULT 1,    -- 통신 횟수 집계
    traffic_weight  REAL    NOT NULL DEFAULT 0.8,  -- layer 가중치 (network=0.8)
    
    -- 표시용 추가 정보 (FE에서 활용)
    source_name      TEXT,
    source_namespace TEXT,
    target_name      TEXT,
    target_namespace TEXT,
    
    -- 시점
    first_seen_at   TIMESTAMPTZ,
    last_seen_at    TIMESTAMPTZ,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- 동일 (cluster, src, dst, layer, snapshot)은 upsert
    UNIQUE (cluster_name, source_pod_uid, target_pod_uid, layer, snapshot_at)
);

-- 조회 인덱스
CREATE INDEX IF NOT EXISTS idx_edges_cluster_snapshot 
    ON edges(cluster_name, snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_edges_source 
    ON edges(cluster_name, source_pod_uid);

CREATE INDEX IF NOT EXISTS idx_edges_target 
    ON edges(cluster_name, target_pod_uid);

CREATE INDEX IF NOT EXISTS idx_edges_layer 
    ON edges(cluster_name, layer);

CREATE INDEX IF NOT EXISTS idx_edges_computed_at 
    ON edges USING brin(computed_at);

COMMENT ON TABLE edges IS 'Pod 간 통신 그래프 edges (Blast Radius 시각화용)';
COMMENT ON COLUMN edges.layer IS 'network/identity/supply_chain. host는 미사용';
COMMENT ON COLUMN edges.weight IS '통신 횟수 (GROUP BY 집계)';
COMMENT ON COLUMN edges.traffic_weight IS 'layer 가중치. network=0.8, identity=0.7, supply_chain=0.6';
COMMENT ON COLUMN edges.snapshot_at IS '집계 시점 — 같은 시점 (src, dst, layer)은 upsert';
