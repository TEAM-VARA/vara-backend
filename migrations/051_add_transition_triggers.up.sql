-- ============================================================================
-- VARA RBAC Chain Analyzer - rbac_sa_reports 에 트리거 권한 컬럼 추가
-- ============================================================================
--
-- 배경:
--   기존 applied_transitions 는 "이 SA 에 어떤 룰이 걸렸나"(룰 ID 목록)만 보여줌.
--   예: ["R-DIRECT-01", "R-INDIRECT-01"]
--   하지만 "그 룰을 트리거한 권한이 무엇인가"는 안 보였음.
--   (그 데이터는 fixpoint provenance 의 matched_perms 에 이미 존재 — 리포트가 버리고 있었음)
--
-- 추가 컬럼 transition_triggers:
--   룰별로 그룹지어, 각 룰을 트리거한 권한(들)을 담는다.
--   - 한 룰이 여러 권한으로 트리거되면 triggered_by 에 모두 담음.
--   - 룰이 둘 이상 걸리면 항목(객체)이 룰 수만큼 늘어남 → 룰별 분리.
--   (관계형 테이블은 물리 컬럼 수를 동적으로 못 늘리므로, 룰별 분리는
--    JSONB 배열 안에서 표현. UI 에서 룰별 컬럼/카드로 펼치면 됨.)
--
-- 형태 (JSONB):
--   [
--     {"transition":"R-DIRECT-01",
--      "triggered_by":[{"api_group":"rbac.authorization.k8s.io","resource":"clusterroles",
--                       "verb":"escalate","namespace":null,"resource_name":null,"non_resource_url":null}]},
--     {"transition":"R-INDIRECT-01",
--      "triggered_by":[{"api_group":"","resource":"pods","verb":"create",
--                       "namespace":null,"resource_name":null,"non_resource_url":null}]}
--   ]
--
--   - transition  : 룰 ID (applied_transitions 의 각 원소와 1:1 대응)
--   - triggered_by : 그 룰을 트리거한 권한 dict 목록 (rbac_sa_permissions 와 동일 6필드)
--
-- 참고: applied_transitions 는 그대로 유지(하위호환). transition_triggers 는 그 상위집합.
-- ============================================================================

ALTER TABLE rbac_sa_reports
    ADD COLUMN IF NOT EXISTS transition_triggers JSONB NOT NULL DEFAULT '[]'::JSONB;

COMMENT ON COLUMN rbac_sa_reports.transition_triggers IS
    '룰별 트리거 권한. [{transition, triggered_by:[{api_group,resource,verb,namespace,resource_name,non_resource_url}]}]. fixpoint provenance.matched_perms 출처.';
