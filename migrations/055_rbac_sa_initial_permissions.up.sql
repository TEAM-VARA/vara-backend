-- ============================================================================
-- VARA RBAC Chain Analyzer - Migration SQL (add-on to 027)
-- ============================================================================
--
-- 추가 테이블: rbac_sa_initial_permissions
--   fixpoint(흡수) "적용 전" 의 직접 보유 권한 집합을 1권한=1행으로 적재.
--
-- 배경 / 왜 필요한가:
--   027 의 두 표만으로는 "흡수 전 직접 권한" 집합을 복원할 수 없다.
--     - rbac_sa_permissions  = 최종 = 직접 + 흡수 (fixpoint 후)
--     - rbac_escalation_paths = 흡수분만 (newly_absorbed)
--   → 직접(initial) 집합 자체가 어느 표에도 없다. FE "권한 상승 경로" 화면이
--     "원래 직접 보유 권한(흡수 전)" 을 보여주려면 이 표가 필요하다.
--
--   파이프라인상 directperm → fixpoint 사이의 initialSnapshot(흡수 전 사본)을 그대로 적재.
--   rbac_sa_permissions(최종)과 컬럼/인덱스 구조가 동일하다 — 단지 시점만 "흡수 전".
--
-- 설계 원칙: 027 과 동일.
--   1. 이력 미보존: 클러스터당 최신 한 벌만 유지.
--   2. compute 시 해당 cluster 행 전부 DELETE 후 새로 INSERT (027 트랜잭션에 합류).
--   3. 묶음 키 (cluster_name, sa_namespace, sa_name), BIGSERIAL id PK + 인덱스.
-- ============================================================================


-- ============================================================================
-- rbac_sa_initial_permissions — 흡수 전 직접 권한 전체 목록 (가진 권한당 1행)
-- ============================================================================
-- initialSnapshot 정규화. 각 SA가 fixpoint 적용 전 직접 보유한 권한 집합을 1권한=1행으로.
-- rbac_sa_permissions(최종 권한)과 짝을 이룬다(initial ↔ final).
-- rbac_sa_reports.initial_perm_count 와 행 수가 일치한다.

CREATE TABLE IF NOT EXISTS rbac_sa_initial_permissions (
    id               BIGSERIAL PRIMARY KEY,
    cluster_name     TEXT NOT NULL,
    sa_namespace     TEXT NOT NULL,
    sa_name          TEXT NOT NULL,
    api_group        TEXT NOT NULL,              -- "" = core, "*" = 전체
    resource         TEXT NOT NULL,              -- secrets, pods, "*" ...
    verb             TEXT NOT NULL,              -- get, list, "*" ...
    namespace        TEXT,                       -- NULL = 클러스터 전체
    resource_name    TEXT,                       -- 특정 이름 자원 한정 (보통 NULL)
    non_resource_url TEXT                         -- URL 권한일 때 (/metrics 등, 보통 NULL)
);

CREATE INDEX IF NOT EXISTS idx_initial_perms_sa
    ON rbac_sa_initial_permissions (cluster_name, sa_namespace, sa_name);

-- 권한 역질의(흡수 전 기준): "이 resource/verb 를 직접 가진 SA 찾기"
CREATE INDEX IF NOT EXISTS idx_initial_perms_lookup
    ON rbac_sa_initial_permissions (cluster_name, resource, verb);
