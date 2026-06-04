-- ============================================================================
-- VARA Risk Scoring — Attack Path Scope (Phase 1: K8s 기반)
-- ============================================================================
--
-- 공격 경로 범위(Attack Path Scope) 평가 결과.
-- "이 Pod이 침해됐을 때 어디까지 갈 수 있는가"를 정량화.
--
-- Phase 1 (현재): K8s 데이터만
--   - K8s RBAC 권한 (40점)
--   - NetworkPolicy 격리 (30점)
--   - 민감 자원 마운트 (30점)
--
-- Phase 2 (예정): AWS IAM 통합
--   - ServiceAccount → IAM Role 매핑
--   - IAM 권한 확장
--
-- Phase 3 (예정): eBPF 결합
--   - 실제 통신 패턴 기반 정밀도 향상
-- ============================================================================


CREATE TABLE IF NOT EXISTS attack_path_scores (
    id                BIGSERIAL PRIMARY KEY,

    -- 식별
    cluster_name      TEXT NOT NULL,
    pod_uid           TEXT NOT NULL,
    pod_name          TEXT NOT NULL,
    pod_namespace     TEXT NOT NULL,

    -- 종합 점수 (0~100)
    total_score       INT NOT NULL,

    -- 항목별 점수
    rbac_score        INT NOT NULL,    -- 0~40
    network_score     INT NOT NULL,    -- 0~30
    mount_score       INT NOT NULL,    -- 0~30

    -- 각 항목의 판정 근거 (디버깅/감사용)
    rbac_details      JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- 예: {"level": "cluster-admin", "matched_bindings": [...]}

    network_details   JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- 예: {"isolation": "none", "matched_policies": []}

    mount_details     JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- 예: {"host_network": false, "host_path": false,
    --      "privileged": false, "secret_mounts": 2, "configmap_mounts": 1}

    -- 시점
    snapshot_at       TIMESTAMPTZ NOT NULL,
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (cluster_name, pod_uid, snapshot_at)
);


-- 인덱스
CREATE INDEX IF NOT EXISTS idx_attack_path_cluster_pod
    ON attack_path_scores (cluster_name, pod_uid);

CREATE INDEX IF NOT EXISTS idx_attack_path_total_score
    ON attack_path_scores (total_score DESC);

CREATE INDEX IF NOT EXISTS idx_attack_path_computed_at
    ON attack_path_scores USING BRIN (computed_at);
