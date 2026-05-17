-- ============================================================================
-- VARA Cluster Reader Agent - Migration SQL
-- ============================================================================
--
-- 대상: 8개 cluster-reader 엔드포인트
--   POST /api/v1/agents/cluster-reader/{pods, nodes, services, workloads,
--                                        ingresses, network-policies,
--                                        sensitive-resources, rbac}
--
-- 설계:
-- 1. 중첩 배열/객체는 JSONB (containers, ports, rules 등)
-- 2. 최상위 필드는 일반 컬럼 (name, namespace, uid 등)
-- 3. 모든 행에 (cluster, snapshot_at) 태깅
-- 4. UNIQUE (cluster, snapshot_at, uid) → 같은 스냅샷 중복 INSERT 방지
-- 5. UPSERT (ON CONFLICT) → 재전송 시 idempotent
-- ============================================================================


-- ============================================================================
-- 0. 공통: 스냅샷 메타 (감사용)
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_snapshots (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    item_count      INT NOT NULL,
    UNIQUE (cluster_name, resource_type, snapshot_at)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_cluster_time
    ON cluster_snapshots (cluster_name, snapshot_at DESC);


-- ============================================================================
-- 1. /pods → cluster_pods + cluster_namespaces
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_pods (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    pod_uid         TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    node            TEXT,
    pod_ip          TEXT,
    phase           TEXT,
    restart_count   INT NOT NULL DEFAULT 0,
    service_account TEXT,
    labels          JSONB,
    annotations     JSONB,
    containers      JSONB NOT NULL DEFAULT '[]'::JSONB,
    volumes         JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, pod_uid)
);

CREATE INDEX IF NOT EXISTS idx_pods_cluster_ns ON cluster_pods (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_pods_uid ON cluster_pods (pod_uid);
CREATE INDEX IF NOT EXISTS idx_pods_node ON cluster_pods (cluster_name, node);
CREATE INDEX IF NOT EXISTS idx_pods_phase ON cluster_pods (phase);
CREATE INDEX IF NOT EXISTS idx_pods_containers_gin ON cluster_pods USING GIN (containers);
CREATE INDEX IF NOT EXISTS idx_pods_labels_gin ON cluster_pods USING GIN (labels);


CREATE TABLE IF NOT EXISTS cluster_namespaces (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    namespace       TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, namespace)
);


-- ============================================================================
-- 2. /nodes → cluster_nodes
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_nodes (
    id                  BIGSERIAL PRIMARY KEY,
    cluster_name        TEXT NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    node_uid            TEXT NOT NULL,
    name                TEXT NOT NULL,
    internal_ip         TEXT,
    external_ip         TEXT,
    status              TEXT,
    kernel_version      TEXT,
    os_image            TEXT,
    container_runtime   TEXT,
    kubelet_version     TEXT,
    labels              JSONB,
    pods_on_node        JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, node_uid)
);

CREATE INDEX IF NOT EXISTS idx_nodes_uid ON cluster_nodes (node_uid);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON cluster_nodes (status);
CREATE INDEX IF NOT EXISTS idx_nodes_kernel ON cluster_nodes (kernel_version);


-- ============================================================================
-- 3. /services → cluster_services
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_services (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    service_uid     TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    type            TEXT,
    cluster_ip      TEXT,
    external_name   TEXT,
    external_ips    JSONB,
    selector        JSONB,
    ports           JSONB NOT NULL DEFAULT '[]'::JSONB,
    endpoints       JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, service_uid)
);

CREATE INDEX IF NOT EXISTS idx_services_cluster_ns ON cluster_services (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_services_uid ON cluster_services (service_uid);
CREATE INDEX IF NOT EXISTS idx_services_type ON cluster_services (type);
CREATE INDEX IF NOT EXISTS idx_services_endpoints_gin ON cluster_services USING GIN (endpoints);


-- ============================================================================
-- 4. /workloads → cluster_workloads
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_workloads (
    id                  BIGSERIAL PRIMARY KEY,
    cluster_name        TEXT NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    workload_uid        TEXT NOT NULL,
    kind                TEXT NOT NULL,
    name                TEXT NOT NULL,
    namespace           TEXT NOT NULL,
    replicas_desired    INT NOT NULL DEFAULT 0,
    replicas_ready      INT NOT NULL DEFAULT 0,
    replicas_available  INT,
    selector            JSONB,
    template_labels     JSONB,
    containers          JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, workload_uid)
);

CREATE INDEX IF NOT EXISTS idx_workloads_cluster_ns ON cluster_workloads (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_workloads_uid ON cluster_workloads (workload_uid);
CREATE INDEX IF NOT EXISTS idx_workloads_kind ON cluster_workloads (kind);
CREATE INDEX IF NOT EXISTS idx_workloads_active ON cluster_workloads (cluster_name, namespace, kind)
    WHERE replicas_desired > 0;


-- ============================================================================
-- 5. /ingresses → cluster_ingresses
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_ingresses (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    ingress_uid     TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    ingress_class   TEXT,
    rules           JSONB NOT NULL DEFAULT '[]'::JSONB,
    tls             JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, ingress_uid)
);

CREATE INDEX IF NOT EXISTS idx_ingresses_cluster_ns ON cluster_ingresses (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_ingresses_class ON cluster_ingresses (ingress_class);


-- ============================================================================
-- 6. /network-policies → cluster_network_policies
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_network_policies (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    policy_uid      TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    pod_selector    JSONB,
    policy_types    JSONB NOT NULL DEFAULT '[]'::JSONB,
    ingress_rules   JSONB NOT NULL DEFAULT '[]'::JSONB,
    egress_rules    JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, policy_uid)
);

CREATE INDEX IF NOT EXISTS idx_netpol_cluster_ns
    ON cluster_network_policies (cluster_name, namespace);


-- ============================================================================
-- 7. /sensitive-resources → cluster_secrets, cluster_configmaps
-- ============================================================================
-- ⚠ Secret 내용(data 필드)은 절대 저장 X. 메타데이터만.

CREATE TABLE IF NOT EXISTS cluster_secrets (
    id                  BIGSERIAL PRIMARY KEY,
    cluster_name        TEXT NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    secret_uid          TEXT NOT NULL,
    name                TEXT NOT NULL,
    namespace           TEXT NOT NULL,
    type                TEXT,
    mounted_by_pods     JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, secret_uid)
);

CREATE INDEX IF NOT EXISTS idx_secrets_cluster_ns ON cluster_secrets (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_secrets_type ON cluster_secrets (type);


CREATE TABLE IF NOT EXISTS cluster_configmaps (
    id                  BIGSERIAL PRIMARY KEY,
    cluster_name        TEXT NOT NULL,
    snapshot_at         TIMESTAMPTZ NOT NULL,
    configmap_uid       TEXT NOT NULL,
    name                TEXT NOT NULL,
    namespace           TEXT NOT NULL,
    mounted_by_pods     JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, configmap_uid)
);

CREATE INDEX IF NOT EXISTS idx_configmaps_cluster_ns
    ON cluster_configmaps (cluster_name, namespace);


-- ============================================================================
-- 8. /rbac → 5종 RBAC 테이블
-- ============================================================================

CREATE TABLE IF NOT EXISTS cluster_service_accounts (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    sa_uid          TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    secrets         JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, sa_uid)
);

CREATE INDEX IF NOT EXISTS idx_sa_cluster_ns
    ON cluster_service_accounts (cluster_name, namespace);


CREATE TABLE IF NOT EXISTS cluster_cluster_roles (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    role_uid        TEXT NOT NULL,
    name            TEXT NOT NULL,
    rules           JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, role_uid)
);


CREATE TABLE IF NOT EXISTS cluster_roles (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    role_uid        TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    rules           JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, role_uid)
);

CREATE INDEX IF NOT EXISTS idx_roles_cluster_ns ON cluster_roles (cluster_name, namespace);


CREATE TABLE IF NOT EXISTS cluster_cluster_role_bindings (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    binding_uid     TEXT NOT NULL,
    name            TEXT NOT NULL,
    role_ref        JSONB NOT NULL,
    subjects        JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, binding_uid)
);

CREATE INDEX IF NOT EXISTS idx_crb_subjects_gin
    ON cluster_cluster_role_bindings USING GIN (subjects);


CREATE TABLE IF NOT EXISTS cluster_role_bindings (
    id              BIGSERIAL PRIMARY KEY,
    cluster_name    TEXT NOT NULL,
    snapshot_at     TIMESTAMPTZ NOT NULL,
    binding_uid     TEXT NOT NULL,
    name            TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    role_ref        JSONB NOT NULL,
    subjects        JSONB NOT NULL DEFAULT '[]'::JSONB,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cluster_name, snapshot_at, binding_uid)
);

CREATE INDEX IF NOT EXISTS idx_rb_cluster_ns
    ON cluster_role_bindings (cluster_name, namespace);
CREATE INDEX IF NOT EXISTS idx_rb_subjects_gin
    ON cluster_role_bindings USING GIN (subjects);
