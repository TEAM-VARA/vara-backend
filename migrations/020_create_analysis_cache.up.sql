-- 020_create_analysis_cache.up.sql
-- 그래프 분석 자동화 캐시 테이블
-- BFS Blast Radius, PageRank+Betweenness, Dijkstra 최단경로 사전계산 결과

-- ─────────────────────────────────────────
-- 1. BFS Blast Radius 캐시 (Pod별 영향 범위)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pod_blast_radius (
    cluster_name    TEXT NOT NULL,
    pod_uid         TEXT NOT NULL,
    reachable_count INT NOT NULL DEFAULT 0,
    reachable_pods  JSONB DEFAULT '[]',        -- 도달 가능 노드 ID 리스트
    blast_score     REAL DEFAULT 0,            -- 영향 점수 (0~25)
    by_layer        JSONB DEFAULT '{}',        -- layer별 도달 수
    computed_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (cluster_name, pod_uid)
);

CREATE INDEX IF NOT EXISTS idx_blast_radius_score 
    ON pod_blast_radius(cluster_name, blast_score DESC);

-- ─────────────────────────────────────────
-- 2. 노드 중요도 (PageRank + Betweenness 통합)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS node_centrality (
    cluster_name TEXT NOT NULL,
    node_id      TEXT NOT NULL,
    label        TEXT,
    kind         TEXT,
    pagerank     REAL DEFAULT 0,    -- 자산 중요도 (목적지)
    betweenness  REAL DEFAULT 0,    -- 방어 길목 (병목)
    computed_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (cluster_name, node_id)
);

CREATE INDEX IF NOT EXISTS idx_centrality_pagerank 
    ON node_centrality(cluster_name, pagerank DESC);
CREATE INDEX IF NOT EXISTS idx_centrality_betweenness 
    ON node_centrality(cluster_name, betweenness DESC);

-- ─────────────────────────────────────────
-- 3. Dijkstra 최단 공격 경로 (외부 노출 → critical asset)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_path_cache (
    cluster_name TEXT NOT NULL,
    source_id    TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    path_nodes   JSONB DEFAULT '[]',   -- 경로 노드 ID 시퀀스
    path_labels  JSONB DEFAULT '[]',   -- 사용자 친화 이름
    path_layers  JSONB DEFAULT '[]',   -- 각 hop의 layer
    total_cost   REAL DEFAULT 0,       -- 누적 cost (낮을수록 쉬운 경로)
    hops         INT DEFAULT 0,
    computed_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (cluster_name, source_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_path_cost 
    ON attack_path_cache(cluster_name, total_cost ASC);

-- 주석
COMMENT ON TABLE pod_blast_radius IS 'BFS 영향 범위 사전계산 캐시';
COMMENT ON TABLE node_centrality IS 'PageRank(중요도) + Betweenness(길목) 사전계산';
COMMENT ON TABLE attack_path_cache IS 'Dijkstra 최단 공격 경로 (외부→critical)';