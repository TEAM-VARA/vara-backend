-- ============================================================================
-- VARA Risk Scoring — Internet Exposure (Phase 1: K8s 데이터만 사용)
-- ============================================================================
--
-- 인터넷 노출 여부 판단 결과를 저장하는 테이블.
--
-- Phase 1 (현재): K8s 정의 기반
--   - Service.type (LoadBalancer, NodePort) 매칭
--   - Ingress.backend 매핑
--   - 단순 이진 점수 (exposed: 0 또는 20점)
--
-- Phase 2 (예정): AWS SG/LB 통합
-- Phase 3 (예정): NetworkPolicy 정밀 평가, eBPF 실제 통신 결합
--
-- 데이터 흐름:
--   compute API 호출 → 최신 snapshot 가져오기 → 판단 → INSERT
--   같은 (cluster, pod, snapshot) 조합은 UNIQUE → 재계산 시 갱신
-- ============================================================================


CREATE TABLE IF NOT EXISTS exposure_scores (
    id                BIGSERIAL PRIMARY KEY,

    -- 식별
    cluster_name      TEXT NOT NULL,
    pod_uid           TEXT NOT NULL,
    pod_name          TEXT NOT NULL,
    pod_namespace     TEXT NOT NULL,

    -- 판정 결과
    exposed           BOOLEAN NOT NULL,
    score             INT NOT NULL,  -- 0 또는 20

    -- 매칭 근거 (디버깅/감사용)
    matched_services  JSONB NOT NULL DEFAULT '[]'::JSONB,
    -- 예시: [{"name":"nginx-svc","namespace":"default","type":"LoadBalancer"}]

    matched_ingresses JSONB NOT NULL DEFAULT '[]'::JSONB,
    -- 예시: [{"name":"nginx-ing","namespace":"default","host":"test.example.com"}]

    -- 시점
    snapshot_at       TIMESTAMPTZ NOT NULL,
    computed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- 같은 snapshot 재계산 시 갱신 (idempotent)
    UNIQUE (cluster_name, pod_uid, snapshot_at)
);


-- 인덱스
CREATE INDEX IF NOT EXISTS idx_exposure_cluster_pod
    ON exposure_scores (cluster_name, pod_uid);

CREATE INDEX IF NOT EXISTS idx_exposure_computed_at
    ON exposure_scores USING BRIN (computed_at);

-- 노출된 Pod만 빠르게 조회 (대시보드용)
CREATE INDEX IF NOT EXISTS idx_exposure_exposed_only
    ON exposure_scores (cluster_name, exposed)
    WHERE exposed = TRUE;
