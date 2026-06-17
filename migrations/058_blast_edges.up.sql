-- migrations/058_blast_edges.up.sql
--
-- blast_edges — blast(횡적 전파) 모델의 directed 엣지 테이블.
-- 한 row = (cluster, source Pod A, target Pod B, snapshot) 1개 ordered pair.
-- P(B|A) = max(host, rbac, network) 를 채널별로 담고, max·−ln(p)·승자 채널을
-- 미리 계산해 적재한다. 소비자(점수 담당)는 이 테이블 위에서
-- cascade(Dijkstra/IC) → Σ reachProb×dst_value → 클러스터 정규화로 per-pod blast 점수를 낸다.
--
-- 설계 문서: docs/blast-channels-spec.md (§8 = 이 테이블)
--
-- 규칙:
--   * p_edge = max(p_host, p_rbac, p_net). 0이면 행을 적재하지 않음 → 항상 (0,1]
--   * neg_log_p = -ln(p_edge)  (Dijkstra 비용; reachProb=exp(-거리), p_edge=1 → 0)
--   * 채널 값 의미: host·rbac = 0/1, network = B.Risk(0~1)
--   * 엣지는 이미 게이트(directed·same-node·running·resourceNames·token)가 적용된 유효 엣지만 적재
--   * dst_value = value(B) (v1 = 1.0, 추후 vertical_direct)

CREATE TABLE IF NOT EXISTS blast_edges (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,

    -- 식별 (directed: A=source → B=target)
    source_pod_uid  TEXT NOT NULL,
    target_pod_uid  TEXT NOT NULL,

    -- 채널별 확률 (host·rbac = 0/1, network = B.Risk 0~1)
    p_host          REAL NOT NULL DEFAULT 0,
    p_rbac          REAL NOT NULL DEFAULT 0,
    p_net           REAL NOT NULL DEFAULT 0,

    -- 합성 (소비자가 바로 쓰는 값)
    p_edge          REAL NOT NULL,                 -- max(3채널), (0,1]
    neg_log_p       REAL NOT NULL,                 -- -ln(p_edge), >=0 (Dijkstra 비용)
    win_channel     TEXT NOT NULL,                 -- 'host' | 'rbac' | 'network'
    reason          TEXT,                          -- 드릴다운 설명, 예: 'rbac: pods/exec ns=dev'

    -- 타겟 가치 (denormalized; v1 = 1.0)
    dst_value       REAL NOT NULL DEFAULT 1.0,

    -- 표시용 (FE/디버그)
    source_name      TEXT,
    source_namespace TEXT,
    target_name      TEXT,
    target_namespace TEXT,

    -- 시점
    snapshot_at     TIMESTAMPTZ NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- 동일 (cluster, src, dst, snapshot)은 upsert
    UNIQUE (cluster_name, source_pod_uid, target_pod_uid, snapshot_at),
    CHECK (p_edge > 0 AND p_edge <= 1),
    CHECK (neg_log_p >= 0),
    CHECK (win_channel IN ('host', 'rbac', 'network'))
);

-- 조회 인덱스
CREATE INDEX IF NOT EXISTS idx_blast_edges_cluster_snapshot
    ON blast_edges (cluster_name, snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_blast_edges_source
    ON blast_edges (cluster_name, source_pod_uid, snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_blast_edges_target
    ON blast_edges (cluster_name, target_pod_uid, snapshot_at DESC);

CREATE INDEX IF NOT EXISTS idx_blast_edges_win_channel
    ON blast_edges (cluster_name, win_channel);

CREATE INDEX IF NOT EXISTS idx_blast_edges_computed_at
    ON blast_edges USING brin (computed_at);

COMMENT ON TABLE  blast_edges            IS 'blast 모델 directed 엣지 P(B|A)=max(host,rbac,network). 소비자는 cascade로 per-pod blast 점수 계산. 설계: docs/blast-channels-spec.md';
COMMENT ON COLUMN blast_edges.p_edge     IS 'max(p_host,p_rbac,p_net). 0이면 미적재 → (0,1]';
COMMENT ON COLUMN blast_edges.neg_log_p  IS '-ln(p_edge). Dijkstra cost (reachProb=exp(-거리)). p_edge=1 → 0';
COMMENT ON COLUMN blast_edges.win_channel IS 'p_edge를 만든 채널: host|rbac|network';
COMMENT ON COLUMN blast_edges.p_net      IS 'network 채널 = B.Risk(순수 likelihood=Global+Exposure). final_score 금지(순환)';
COMMENT ON COLUMN blast_edges.dst_value  IS 'value(B). v1=1.0(개수), 추후 vertical_direct(B의 initial 터미널 권한)';
