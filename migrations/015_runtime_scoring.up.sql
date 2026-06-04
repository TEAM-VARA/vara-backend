-- migrations/015_runtime_scoring.up.sql
--
-- eBPF 기반 런타임 분석 결과를 기존 점수에 통합하기 위한 컬럼 추가.
-- 모든 컬럼은 nullable (forward-compatible).
-- 데이터 없으면 NULL → 정적 점수만 사용 (현재와 동일).
-- 데이터 있으면 동적 보정 적용.

-- ============================================
-- 1. attack_path_scores 보강
-- ============================================
ALTER TABLE attack_path_scores
  -- 실제 통신 그래프 (ebpf_network_flows 기반)
  ADD COLUMN IF NOT EXISTS runtime_network_score INTEGER,
  ADD COLUMN IF NOT EXISTS runtime_network_details JSONB,

  -- host_network 사용 여부 (forward-compatible)
  -- NULL = 데이터 없음 (Cluster Reader Agent가 아직 수집 안 함)
  -- true/false = 명시적 값
  ADD COLUMN IF NOT EXISTS uses_host_network BOOLEAN,

  -- RBAC 권한 과다 부여 분석
  ADD COLUMN IF NOT EXISTS overgrant_ratio REAL,
  ADD COLUMN IF NOT EXISTS overgranted_permissions JSONB;

-- runtime_network_details JSONB 구조 예시:
-- {
--   "actual_targets_count": 5,           // 실제 통신 대상 Pod 수
--   "internal_targets": ["uid1", "uid2"], // 내부 Pod 통신 대상
--   "external_targets_count": 2,         // 외부 IP 통신 수
--   "external_ips": ["8.8.8.8", "1.1.1.1"],
--   "diversity_score": 0.75,             // 통신 다양성 (0~1)
--   "window_hours": 1,                   // 분석 시간 윈도우
--   "flow_count": 1234,                  // 총 flow 수
--   "data_available": true               // false면 ebpf 데이터 없음
-- }

-- overgranted_permissions JSONB 구조 예시:
-- {
--   "defined_verbs": ["get", "list", "create", "delete", "update"],
--   "rbac_summary": {                    // 정의된 권한 요약
--     "has_wildcard_verbs": false,
--     "has_secret_access": true,
--     "verb_count": 5,
--     "resource_count": 12
--   },
--   "binding_count": 3,                  // 매칭된 RoleBinding 수
--   "high_privilege_resources": ["secrets", "configmaps"]
-- }

-- ============================================
-- 2. exposure_scores 보강
-- ============================================
ALTER TABLE exposure_scores
  -- 실제 외부 트래픽 검증
  ADD COLUMN IF NOT EXISTS runtime_actually_accessed BOOLEAN,
  ADD COLUMN IF NOT EXISTS runtime_external_traffic_count INTEGER,
  ADD COLUMN IF NOT EXISTS runtime_details JSONB;

-- runtime_details JSONB 구조 예시:
-- {
--   "external_source_ips": ["external_ip1", ...], // 외부에서 접근한 IP들
--   "internal_source_ips": ["10.0.x.x", ...],     // 내부 접근
--   "first_external_access": "2026-05-20T...",    // 최초 외부 접근 시각
--   "last_external_access": "2026-05-20T...",
--   "window_hours": 1,
--   "data_available": true
-- }

-- ============================================
-- 3. 인덱스 (분석 쿼리 가속)
-- ============================================
-- ebpf_network_flows를 시간 윈도우로 자주 조회 → 이미 brin index 있음
-- 추가 인덱스 불필요

-- ============================================
-- 4. 검증 (rollback 가능 명령)
-- ============================================
-- DROP은 011_runtime_scoring.down.sql 에 별도 작성
