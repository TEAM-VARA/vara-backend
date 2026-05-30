-- ============================================================================
-- VARA RBAC Chain Analyzer - Migration SQL
-- ============================================================================
--
-- 대상: fixpoint 기반 RBAC 권한상승(privilege-escalation) 분석 결과 적재
--   파이프라인: snapshot(DB pin) → directperm → fixpoint → sareport → 이 테이블들
--
-- 설계 원칙:
-- 1. 이력 미보존(no-history): 클러스터당 "항상 최신 결과 한 벌"만 유지.
-- 2. compute 실행 시 해당 cluster 행을 전부 DELETE 후 새로 INSERT (한 트랜잭션).
--    → 직전 분석엔 있었으나 이번엔 사라진 SA의 유령 행을 남기지 않음.
-- 3. run_id 없음. snapshot_at 은 "언제 시점 데이터인지" 표시용 컬럼.
-- 4. 묶음 키는 (cluster_name, sa_namespace, sa_name).
--    - rbac_sa_reports:      SA당 1행 → 위 3개가 PK
--    - escalation_paths/perms: SA당 N행 → BIGSERIAL id PK + 인덱스
-- ============================================================================


-- ============================================================================
-- 1. rbac_analysis_meta — 클러스터별 분석 현황 (클러스터당 1행)
-- ============================================================================
-- sareport 의 Summary + 분석 시점 메타. 대시보드 상단 요약 숫자.

CREATE TABLE IF NOT EXISTS rbac_analysis_meta (
    cluster_name       TEXT PRIMARY KEY,
    snapshot_at        TIMESTAMPTZ NOT NULL,        -- RBAC 5종 공통 시점 (분석의 기준)
    snapshot_at_pods   TIMESTAMPTZ,                 -- cluster_pods 자체 MAX 시점
    snapshot_at_nodes  TIMESTAMPTZ,                 -- cluster_nodes 자체 MAX 시점
    computed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- 분석 실행 시각
    total_sas          INT NOT NULL,               -- 전체 ServiceAccount 수
    cluster_admin_sas  INT NOT NULL,               -- cluster-admin 도달 가능 SA 수
    changed_sas        INT NOT NULL,               -- 권한 흡수 발생 SA 수
    mounted_sas        INT NOT NULL,               -- Pod 에 마운트된 SA 수
    rules_version      TEXT                         -- 사용한 룰셋 버전 (선택)
);


-- ============================================================================
-- 2. rbac_sa_reports — 계정(SA)별 종합 성적표 (SA당 1행, 핵심 뷰)
-- ============================================================================
-- sareport.SAReport 와 1:1.

CREATE TABLE IF NOT EXISTS rbac_sa_reports (
    cluster_name          TEXT NOT NULL,
    sa_namespace          TEXT NOT NULL,
    sa_name               TEXT NOT NULL,
    snapshot_at           TIMESTAMPTZ NOT NULL,     -- 데이터 시점 (표시용)
    reaches_cluster_admin BOOLEAN NOT NULL,         -- cluster-admin 도달 여부 (위험)
    initial_perm_count    INT NOT NULL,             -- 직접 권한 수
    final_perm_count      INT NOT NULL,             -- fixpoint 후 권한 수
    delta_count           INT NOT NULL,             -- 증가량 (final - initial)
    applied_transitions   JSONB NOT NULL DEFAULT '[]'::JSONB,  -- ["R-INDIRECT-04", ...]
    used_by_pods          JSONB NOT NULL DEFAULT '[]'::JSONB,  -- [{name, namespace, phase, images}]
    direct_bindings       JSONB NOT NULL DEFAULT '[]'::JSONB,  -- [{kind, name, namespace, role_kind, role_name}]
    PRIMARY KEY (cluster_name, sa_namespace, sa_name)
);

-- 위험 SA만 빠르게 조회 (partial index)
CREATE INDEX IF NOT EXISTS idx_sa_reports_admin
    ON rbac_sa_reports (cluster_name) WHERE reaches_cluster_admin;

-- delta 큰 순(보기보다 위험한 계정) 정렬
CREATE INDEX IF NOT EXISTS idx_sa_reports_delta
    ON rbac_sa_reports (cluster_name, delta_count DESC);


-- ============================================================================
-- 3. rbac_escalation_paths — 권한상승 경로 상세 (새로 얻은 권한당 1행)
-- ============================================================================
-- provenance / delta 의 "newly_absorbed" 정규화. SA가 어떤 룰로 어떤 권한을
-- 누구한테서 흡수했는지 한 건씩 펼침. ②에서 드릴다운할 때 사용.

CREATE TABLE IF NOT EXISTS rbac_escalation_paths (
    id               BIGSERIAL PRIMARY KEY,
    cluster_name     TEXT NOT NULL,
    sa_namespace     TEXT NOT NULL,              -- 권한을 얻은 SA
    sa_name          TEXT NOT NULL,
    permission_repr  TEXT NOT NULL,              -- 사람용 표기 "batch/jobs.get @ ns=*"
    api_group        TEXT NOT NULL,              -- "" = core, "*" = 전체
    resource         TEXT NOT NULL,              -- secrets, deployments, "*" ...
    verb             TEXT NOT NULL,              -- get, create, "*" ...
    namespace        TEXT,                       -- NULL = 클러스터 전체
    via_transition   TEXT NOT NULL,              -- 흡수시킨 룰 (R-INDIRECT-04)
    absorbed_from_sa TEXT                         -- 권한을 가져온 원천 SA ("kube-system/default")
);

CREATE INDEX IF NOT EXISTS idx_esc_sa
    ON rbac_escalation_paths (cluster_name, sa_namespace, sa_name);
CREATE INDEX IF NOT EXISTS idx_esc_rule
    ON rbac_escalation_paths (cluster_name, via_transition);


-- ============================================================================
-- 4. rbac_sa_permissions — 최종 권한 전체 목록 (가진 권한당 1행)
-- ============================================================================
-- all_perms 정규화. 각 SA의 최종 권한 집합(원래 것 + 흡수한 것)을 1권한=1행으로.
-- "누가 secrets 를 get 할 수 있나" 같은 권한 역질의용. 가장 양 많음.

CREATE TABLE IF NOT EXISTS rbac_sa_permissions (
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

CREATE INDEX IF NOT EXISTS idx_perms_sa
    ON rbac_sa_permissions (cluster_name, sa_namespace, sa_name);

-- 권한 역질의: "이 resource/verb 를 가진 SA 찾기"
CREATE INDEX IF NOT EXISTS idx_perms_lookup
    ON rbac_sa_permissions (cluster_name, resource, verb);
