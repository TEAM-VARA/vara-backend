-- ============================================================================
-- VARA Risk Scoring — Final Score (최종 통합 위험도)
-- ============================================================================
--
-- 6개 항목을 모두 통합한 Pod 단위 최종 점수.
--
-- 공식:
--   Final Score = (0.6 × Global_image + 0.4 × Local) × Toxic_Multiplier
--   - Global_image: 해당 Pod의 컨테이너 이미지 중 가장 위험한 것의 max_score (0~100)
--   - Local: 작업 B-2의 local_score (exposure + attack_path, 0~100)
--   - Toxic_Multiplier: 1.0 (작업 B-4 미구현 시 기본값, 추후 1.0~1.5)
--
-- 한 Pod에 여러 컨테이너가 있는 경우:
--   가장 위험한 컨테이너 이미지(max_score 최대)를 채택하여 보수적 평가.
-- ============================================================================

CREATE TABLE IF NOT EXISTS final_scores (
    id                       BIGSERIAL PRIMARY KEY,

    -- 식별
    cluster_name             TEXT NOT NULL,
    pod_uid                  TEXT NOT NULL,
    pod_name                 TEXT NOT NULL,
    pod_namespace            TEXT NOT NULL,

    -- 종합
    final_score              NUMERIC(5, 2) NOT NULL,   -- 0~100 (Toxic=1.0)
    risk_level               TEXT NOT NULL,             -- Critical/High/Medium/Low/None

    -- 기여도 (디버깅/감사용)
    global_contribution      NUMERIC(5, 2) NOT NULL,    -- = global_image_score × 0.6
    local_contribution       NUMERIC(5, 2) NOT NULL,    -- = local_score × 0.4
    toxic_multiplier         NUMERIC(3, 2) NOT NULL,    -- 1.0 (default)

    -- 원본 점수 (트레이싱)
    global_image_score       NUMERIC(5, 2) NOT NULL,    -- 0~100
    local_score              NUMERIC(5, 2) NOT NULL,    -- 0~100

    -- 사용된 이미지 (가장 위험한 컨테이너 기준)
    used_image_digest        TEXT,
    used_image_tag           TEXT,
    used_top_cve             TEXT,

    -- 누락 데이터 표시 (디버깅)
    missing_global_image     BOOLEAN NOT NULL DEFAULT false, -- image_global_scores 없음
    missing_local            BOOLEAN NOT NULL DEFAULT false, -- local_scores 없음
    missing_sbom             BOOLEAN NOT NULL DEFAULT false, -- SBOM 없음 → digest 못 찾음

    snapshot_at              TIMESTAMPTZ NOT NULL,
    computed_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (cluster_name, pod_uid, snapshot_at)
);

-- 인덱스
CREATE INDEX IF NOT EXISTS idx_final_cluster_pod
    ON final_scores (cluster_name, pod_uid);

CREATE INDEX IF NOT EXISTS idx_final_score_desc
    ON final_scores (final_score DESC);

CREATE INDEX IF NOT EXISTS idx_final_risk_level
    ON final_scores (risk_level);

CREATE INDEX IF NOT EXISTS idx_final_computed_at
    ON final_scores USING BRIN (computed_at);
