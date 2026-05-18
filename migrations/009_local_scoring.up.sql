-- ============================================================================
-- VARA Risk Scoring — Local Score (Pod-level Composite)
-- ============================================================================
--
-- Local Score는 인터넷 노출(C-1)과 공격 경로 범위(B-2c)를 통합한 Pod 단위 점수입니다.
--
-- 공식:
--   Local Score = exposure_contribution(0~20) + attack_path_contribution(0~80)
--               = exposure_score_raw + (attack_path_total / 100) × 80
--
--   범위: 0~100
--
-- 의미:
--   "이 Pod 자체가 가지는 침해 위험성"
--   - 외부 노출은 트리거 (entry point)
--   - 공격 경로는 침해 후 확장 영향력
--
-- 추후 Final Score(B-3):
--   Final = (0.6 × Global + 0.4 × Local) × Toxic_Multiplier × 100
-- ============================================================================

CREATE TABLE IF NOT EXISTS local_scores (
    id                          BIGSERIAL PRIMARY KEY,

    -- 식별
    cluster_name                TEXT NOT NULL,
    pod_uid                     TEXT NOT NULL,
    pod_name                    TEXT NOT NULL,
    pod_namespace               TEXT NOT NULL,

    -- 종합 점수 (0~100)
    local_score                 NUMERIC(5, 2) NOT NULL,

    -- 항목별 기여도
    exposure_contribution       NUMERIC(5, 2) NOT NULL,  -- 0~20
    attack_path_contribution    NUMERIC(5, 2) NOT NULL,  -- 0~80

    -- 원본 점수 참조 (트레이싱용)
    exposure_score_raw          INT NOT NULL,            -- 0 또는 20
    attack_path_score_raw       INT NOT NULL,            -- 0~100

    -- 핵심 신호 (필터/쿼리 편의용)
    exposed                     BOOLEAN NOT NULL,        -- 인터넷 노출 여부
    attack_path_level           TEXT NOT NULL,           -- "High" | "Medium" | "Low" | "Minimal"
    local_level                 TEXT NOT NULL,           -- "High" | "Medium" | "Low"

    -- 시점
    snapshot_at                 TIMESTAMPTZ NOT NULL,
    computed_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (cluster_name, pod_uid, snapshot_at)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_local_cluster_pod
    ON local_scores (cluster_name, pod_uid);

CREATE INDEX IF NOT EXISTS idx_local_score_desc
    ON local_scores (local_score DESC);

CREATE INDEX IF NOT EXISTS idx_local_exposed
    ON local_scores (exposed) WHERE exposed = true;

CREATE INDEX IF NOT EXISTS idx_local_computed_at
    ON local_scores USING BRIN (computed_at);
