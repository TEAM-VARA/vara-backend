-- ============================================================================
-- VARA Risk Scoring — Toxic Combination (작업 B-4)
-- ============================================================================
--
-- 단일 신호로는 평범하지만 조합되면 위험이 폭발하는 패턴을 탐지합니다.
-- 매칭 시 Final Score에 multiplier를 곱하여 증폭합니다.
--
-- 점수 흐름:
--   final_scores 계산 시 toxic_results의 multiplier를 적용
--   Final = (0.6 × Global + 0.4 × Local) × Toxic_Multiplier
-- ============================================================================

-- ─────────────────────────────────────────
-- 1. 룰 정의 (정적)
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS toxic_rules (
    rule_id       TEXT PRIMARY KEY,            -- TOXIC-001 등
    name          TEXT NOT NULL,                -- 사람이 읽기 좋은 이름
    description   TEXT NOT NULL,                -- 왜 위험한지
    severity      TEXT NOT NULL,                -- Critical/High/Medium
    multiplier    NUMERIC(3, 2) NOT NULL,       -- 1.2 ~ 1.5

    -- 매칭 조건 (코드에서 평가, 여기엔 가독성용으로만 저장)
    conditions    TEXT NOT NULL,                -- "exposed=true AND has_kev=true"

    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 룰 시드 데이터 (10개)
INSERT INTO toxic_rules (rule_id, name, description, severity, multiplier, conditions) VALUES
    -- Critical (1.5x)
    ('TOXIC-001', '외부 노출 + 클러스터 최고 권한',
     '외부에서 접근 가능한 Pod이 cluster-admin 권한을 가짐 → 외부 침입 시 클러스터 전체 장악',
     'Critical', 1.5, 'externally_exposed AND cluster_admin'),

    ('TOXIC-002', '외부 노출 + KEV (실제 악용 중인 CVE)',
     '외부 노출 + 실제 야생에서 악용되고 있는 CVE 보유 → 즉시 침해 가능',
     'Critical', 1.5, 'externally_exposed AND has_kev_cve'),

    ('TOXIC-003', 'Privileged + HostNetwork + Secret',
     '컨테이너 탈출 가능 + 호스트 네트워크 + 인증정보 → 호스트 침해 → 측면 이동',
     'Critical', 1.5, 'privileged AND host_network AND secret_access'),

    -- High (1.3x)
    ('TOXIC-004', '최고 권한 + KEV',
     'cluster-admin + 실제 악용 중인 CVE → 침해 시 영향력 최대',
     'High', 1.3, 'cluster_admin AND has_kev_cve'),

    ('TOXIC-005', 'Privileged + Critical CVE',
     'privileged 컨테이너 + Critical 등급 CVE → 호스트 escape 위험',
     'High', 1.3, 'privileged AND has_critical_cve'),

    ('TOXIC-006', '외부 노출 + High CVE + Secret',
     '외부 노출 + 위험한 CVE + 인증정보 접근 → 침해 후 광범위한 자격증명 탈취',
     'High', 1.3, 'externally_exposed AND has_high_cve AND secret_access'),

    ('TOXIC-007', 'NetworkPolicy 없음 + 최고 권한',
     '네트워크 격리 안 됨 + cluster-admin → 침해 시 어떤 Pod와도 통신 가능',
     'High', 1.3, 'no_network_policy AND cluster_admin'),

    -- Medium (1.2x)
    ('TOXIC-008', '외부 노출 + High CVE',
     '외부 노출 + 위험 등급 CVE → 직접 침해 경로',
     'Medium', 1.2, 'externally_exposed AND has_high_cve'),

    ('TOXIC-009', 'Secret 접근 + 악용 가능',
     '인증정보 접근 권한 + 공개 exploit 또는 KEV',
     'Medium', 1.2, 'secret_access AND has_active_or_poc'),

    ('TOXIC-010', '최고 권한 + 리소스 무제한',
     'cluster-admin + 리소스 limit 없음 → 자원 고갈 공격 시 클러스터 영향',
     'Medium', 1.2, 'cluster_admin AND no_resource_limits')
ON CONFLICT (rule_id) DO NOTHING;

-- ─────────────────────────────────────────
-- 2. 매칭 결과
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS toxic_results (
    id                    BIGSERIAL PRIMARY KEY,

    cluster_name          TEXT NOT NULL,
    pod_uid               TEXT NOT NULL,
    pod_name              TEXT NOT NULL,
    pod_namespace         TEXT NOT NULL,

    -- 최종 multiplier (매칭된 룰 중 가장 큰 multiplier)
    multiplier            NUMERIC(3, 2) NOT NULL DEFAULT 1.0,

    -- 매칭된 룰 목록 (JSONB)
    --   [
    --     {"rule_id":"TOXIC-002","name":"...","severity":"Critical","multiplier":1.5,"reason":"exposed=true, has_kev=true"},
    --     ...
    --   ]
    matched_rules         JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- 감지된 신호 (디버깅용)
    signals               JSONB NOT NULL DEFAULT '{}'::jsonb,

    snapshot_at           TIMESTAMPTZ NOT NULL,
    computed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (cluster_name, pod_uid, snapshot_at)
);

CREATE INDEX IF NOT EXISTS idx_toxic_cluster_pod
    ON toxic_results (cluster_name, pod_uid);

CREATE INDEX IF NOT EXISTS idx_toxic_multiplier
    ON toxic_results (multiplier DESC) WHERE multiplier > 1.0;

CREATE INDEX IF NOT EXISTS idx_toxic_computed_at
    ON toxic_results USING BRIN (computed_at);
