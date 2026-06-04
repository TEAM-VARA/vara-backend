-- migrations/017_edges_extended.up.sql
--
-- Edges 테이블 확장 — Blast Radius 시연용 (Blast_Radius_BE_추가요청.pdf v1.0)
--
-- [P0] 3.1 외부 IP 노드 지원
--   - target_pod_uid NULL 허용 (외부 IP / Service 노드용)
--   - target_type, target_ip, target_service_name 추가
--
-- [P0] 3.2 edge_type 컬럼 (semantic verb)
--   - network: can_reach | allows | selected_by | routed_by
--   - identity: assumes | binds | grants | escalates
--   - supply_chain: shares_image | shares_cve
--
-- [P0] 3.3 mode 컬럼 (declared / observed / anomaly)
--
-- [P1] 4.1 total_bytes — 트래픽 양 (observed mode 전용)
--
-- [P1] 4.2 identity layer 지원
--   - source_kind / target_kind
--   - 값: pod | service_account | role | cluster_role | service | external_ip

BEGIN;

-- ─────────────────────────────────────────────
-- 1. target_pod_uid NULL 허용 (외부 IP/Service 노드용)
-- ─────────────────────────────────────────────
ALTER TABLE edges
    ALTER COLUMN target_pod_uid DROP NOT NULL;

-- ─────────────────────────────────────────────
-- 2. 신규 컬럼 추가
-- ─────────────────────────────────────────────
ALTER TABLE edges
    -- [P0 3.1] 외부 IP / Service 노드
    ADD COLUMN IF NOT EXISTS target_type         TEXT NOT NULL DEFAULT 'pod',
    ADD COLUMN IF NOT EXISTS target_ip           TEXT,
    ADD COLUMN IF NOT EXISTS target_service_name TEXT,
    -- [P1 4.2] identity layer 노드 종류
    ADD COLUMN IF NOT EXISTS source_kind         TEXT NOT NULL DEFAULT 'pod',
    ADD COLUMN IF NOT EXISTS target_kind         TEXT NOT NULL DEFAULT 'pod',
    -- [P0 3.2] semantic verb
    ADD COLUMN IF NOT EXISTS edge_type           TEXT NOT NULL DEFAULT 'can_reach',
    -- [P0 3.3] declared/observed/anomaly
    ADD COLUMN IF NOT EXISTS mode                TEXT NOT NULL DEFAULT 'observed',
    -- [P1 4.1] 트래픽 양
    ADD COLUMN IF NOT EXISTS total_bytes         BIGINT NOT NULL DEFAULT 0;

-- ─────────────────────────────────────────────
-- 3. 기존 UNIQUE 제약 제거 → COALESCE 기반 UNIQUE INDEX로 대체
-- (target_pod_uid가 NULL 가능해졌으므로 UNIQUE CONSTRAINT 직접 사용 불가)
-- ─────────────────────────────────────────────
ALTER TABLE edges
    DROP CONSTRAINT IF EXISTS edges_cluster_name_source_pod_uid_target_pod_uid_layer_snap_key;

CREATE UNIQUE INDEX IF NOT EXISTS edges_unique_idx
    ON edges (
        cluster_name,
        source_pod_uid,
        COALESCE(target_pod_uid, 'ext:' || COALESCE(target_ip, target_service_name, '')),
        layer,
        edge_type,
        mode,
        snapshot_at
    );

-- ─────────────────────────────────────────────
-- 4. 추가 인덱스 (자주 쓰일 쿼리)
-- ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_edges_layer_mode
    ON edges(cluster_name, layer, mode);

CREATE INDEX IF NOT EXISTS idx_edges_target_type
    ON edges(cluster_name, target_type);

-- 기존 idx_edges_target을 NULL 허용 후 PARTIAL INDEX로 교체 (Pod 타겟만)
DROP INDEX IF EXISTS idx_edges_target;
CREATE INDEX IF NOT EXISTS idx_edges_target_pod
    ON edges(cluster_name, target_pod_uid)
    WHERE target_pod_uid IS NOT NULL;

-- ─────────────────────────────────────────────
-- 5. 컬럼 코멘트
-- ─────────────────────────────────────────────
COMMENT ON COLUMN edges.target_type         IS 'pod | external_ip | service';
COMMENT ON COLUMN edges.target_ip           IS '외부 IP 노드용 (target_type=external_ip)';
COMMENT ON COLUMN edges.target_service_name IS 'Service 노드용 (target_type=service)';
COMMENT ON COLUMN edges.source_kind         IS 'pod | service_account | role | cluster_role | external_ip';
COMMENT ON COLUMN edges.target_kind         IS 'pod | service_account | role | cluster_role | service | external_ip';
COMMENT ON COLUMN edges.edge_type           IS 'network: can_reach|allows|selected_by|routed_by | identity: assumes|binds|grants|escalates | supply_chain: shares_image|shares_cve';
COMMENT ON COLUMN edges.mode                IS 'declared (정책/스펙) | observed (eBPF 관측) | anomaly (observed && NOT declared)';
COMMENT ON COLUMN edges.total_bytes         IS 'eBPF 관측 트래픽 총 bytes (observed mode 전용)';

COMMIT;