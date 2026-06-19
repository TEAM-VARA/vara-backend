-- migrations/060_scoring_weights.up.sql
--
-- scoring_weights — Risk Scoring 가중치 전역 단일 설정 (운영자가 대시보드에서 조정).
-- 한 행만 존재(id=1 singleton). 점수 계산 시 이 값을 주입한다.
--
-- 구성:
--   Final  = (global × final_weight_global + exposure × final_weight_exposure) × toxic_multiplier
--   Global = (cvss/10 × global_weight_cvss + epss × global_weight_epss + ssvc × global_weight_ssvc) × 100
--   Toxic  = 매칭된 룰의 Severity별 배수 (Critical/High/Medium)
--
-- 규칙:
--   * final_weight_*  합 = 1.0 (앱에서 검증)
--   * global_weight_* 합 = 1.0 (앱에서 검증)
--   * toxic_* >= 1.0
--   * 변경 시 영향 층(cve_global/image_global/toxic_results/final_scores) 재계산 필요

CREATE TABLE IF NOT EXISTS scoring_weights (
    id                    INT PRIMARY KEY DEFAULT 1 CHECK (id = 1), -- singleton

    -- Final 층
    final_weight_global   REAL NOT NULL DEFAULT 0.7,
    final_weight_exposure REAL NOT NULL DEFAULT 0.3,

    -- Global 층
    global_weight_cvss    REAL NOT NULL DEFAULT 0.4,
    global_weight_epss    REAL NOT NULL DEFAULT 0.3,
    global_weight_ssvc    REAL NOT NULL DEFAULT 0.3,

    -- Toxic 배수 (Severity별)
    toxic_critical        REAL NOT NULL DEFAULT 1.5,
    toxic_high            REAL NOT NULL DEFAULT 1.3,
    toxic_medium          REAL NOT NULL DEFAULT 1.2,

    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (final_weight_global >= 0 AND final_weight_exposure >= 0),
    CHECK (global_weight_cvss >= 0 AND global_weight_epss >= 0 AND global_weight_ssvc >= 0),
    CHECK (toxic_critical >= 1.0 AND toxic_high >= 1.0 AND toxic_medium >= 1.0)
);

-- 기본값 1행 시드 (없을 때만)
INSERT INTO scoring_weights (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;
