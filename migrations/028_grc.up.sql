-- ============================================================================
-- VARA Backend - GRC 스키마 (전부 grc_ prefix)
-- ============================================================================

-- 1) 체크
CREATE TABLE IF NOT EXISTS grc_checks (
    check_id        VARCHAR(20)   PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    isms_p_item_id  VARCHAR(10)   NOT NULL,
    ruleset_version VARCHAR(20)   NOT NULL DEFAULT '',
    check_source    VARCHAR(20)   DEFAULT 'file',
    status          VARCHAR(20)   NOT NULL DEFAULT 'queued',
    progress_pct    SMALLINT      NOT NULL DEFAULT 0 CHECK (progress_pct BETWEEN 0 AND 100),
    auto_collect    BOOLEAN       NOT NULL DEFAULT FALSE,
    submitted_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    verdict         VARCHAR(10),
    severity        VARCHAR(10),
    summary_text    TEXT,
    total_rules     SMALLINT,
    passed_rules    SMALLINT,
    failed_rules    SMALLINT,
    skipped_rules   SMALLINT,
    evidence_count  SMALLINT,
    guideline_ids   BIGINT[],
    error           JSONB,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grc_checks_company   ON grc_checks(company_id);
CREATE INDEX IF NOT EXISTS idx_grc_checks_status    ON grc_checks(status);
CREATE INDEX IF NOT EXISTS idx_grc_checks_item      ON grc_checks(isms_p_item_id);
CREATE INDEX IF NOT EXISTS idx_grc_checks_submitted ON grc_checks(submitted_at DESC);

-- 2) 증적 파일
CREATE TABLE IF NOT EXISTS grc_evidence_files (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    filename        VARCHAR(255)  NOT NULL,
    evidence_type   VARCHAR(50)   NOT NULL,
    system          VARCHAR(50),
    description     TEXT,
    storage_path    TEXT          NOT NULL,
    file_size_bytes BIGINT,
    target_rule_ids TEXT[],
    extracted_text  TEXT,
    content_hash    VARCHAR(64),
    guideline_text      TEXT,
    evidence_embedding   vector(1024),
    guideline_embedding  vector(1024),
    k8s_source      JSONB,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grc_evidence_check ON grc_evidence_files(check_id);
CREATE INDEX IF NOT EXISTS idx_grc_evidence_hash  ON grc_evidence_files(content_hash) WHERE content_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_grc_evidence_emb   ON grc_evidence_files USING hnsw (evidence_embedding vector_cosine_ops) WHERE evidence_embedding IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_grc_guideline_emb  ON grc_evidence_files USING hnsw (guideline_embedding vector_cosine_ops) WHERE guideline_embedding IS NOT NULL;

-- 3) 룰별 평가 결과
CREATE TABLE IF NOT EXISTS grc_rule_results (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    rule_id         VARCHAR(20)   NOT NULL,
    check_category  VARCHAR(50)   NOT NULL,
    evidence_type   VARCHAR(100),
    system          VARCHAR(50),
    verdict         VARCHAR(10)   NOT NULL,
    evidence_files  TEXT[]        NOT NULL DEFAULT '{}',
    matched_indicators TEXT[],
    skip_reason     TEXT,
    evidence_sources    JSONB NOT NULL DEFAULT '[]'::jsonb,
    embedding_similarity DOUBLE PRECISION,
    UNIQUE (check_id, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_grc_rule_results_check   ON grc_rule_results(check_id);
CREATE INDEX IF NOT EXISTS idx_grc_rule_results_verdict ON grc_rule_results(verdict);

-- 4) 위반사항
CREATE TABLE IF NOT EXISTS grc_violations (
    id              BIGSERIAL     PRIMARY KEY,
    rule_result_id  BIGINT        NOT NULL REFERENCES grc_rule_results(id) ON DELETE CASCADE,
    field           VARCHAR(100),
    pattern         VARCHAR(255),
    expected        TEXT,
    actual          TEXT,
    description     TEXT          NOT NULL,
    severity        VARCHAR(10)   NOT NULL DEFAULT 'medium',
    k8s_cluster     VARCHAR(255),
    k8s_namespace   VARCHAR(255),
    k8s_kind        VARCHAR(100),
    k8s_name        VARCHAR(255),
    k8s_container   VARCHAR(255)
);
CREATE INDEX IF NOT EXISTS idx_grc_violations_result ON grc_violations(rule_result_id);

-- 5) 개선 권고
CREATE TABLE IF NOT EXISTS grc_recommendations (
    id              BIGSERIAL     PRIMARY KEY,
    check_id        VARCHAR(20)   NOT NULL REFERENCES grc_checks(check_id) ON DELETE CASCADE,
    rule_id         VARCHAR(20)   NOT NULL,
    action          TEXT          NOT NULL,
    reference       TEXT          NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_grc_recommendations_check ON grc_recommendations(check_id);

-- 6) 클라우드 환경
CREATE TABLE IF NOT EXISTS grc_cloud_environments (
    id              BIGSERIAL     PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    check_id        VARCHAR(20)   REFERENCES grc_checks(check_id) ON DELETE SET NULL,
    resource_type   VARCHAR(50)   NOT NULL,
    resource_name   VARCHAR(255)  NOT NULL,
    namespace       VARCHAR(255),
    cluster_name    VARCHAR(255),
    raw_data        JSONB         NOT NULL,
    extracted_text  TEXT,
    embedding       vector(1024),
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_company ON grc_cloud_environments(company_id);
CREATE INDEX IF NOT EXISTS idx_grc_cloud_env_emb     ON grc_cloud_environments USING hnsw (embedding vector_cosine_ops) WHERE embedding IS NOT NULL;

-- 7) 지침
CREATE TABLE IF NOT EXISTS grc_guidelines (
    id              BIGSERIAL     PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    isms_p_item_id  VARCHAR(10)   NOT NULL,
    filename        VARCHAR(255)  NOT NULL,
    storage_path    TEXT          NOT NULL,
    file_size_bytes BIGINT,
    content_hash    VARCHAR(64),
    extracted_text  TEXT,
    embedding       vector(1024),
    uploaded_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    UNIQUE(company_id, isms_p_item_id, filename)
);
CREATE INDEX IF NOT EXISTS idx_grc_guidelines_company ON grc_guidelines(company_id);
CREATE INDEX IF NOT EXISTS idx_grc_guidelines_item    ON grc_guidelines(company_id, isms_p_item_id);
CREATE INDEX IF NOT EXISTS idx_grc_guidelines_emb     ON grc_guidelines USING hnsw (embedding vector_cosine_ops) WHERE embedding IS NOT NULL;

-- 8) Pod Graph 평가 결과
CREATE TABLE IF NOT EXISTS grc_pod_graph_evaluations (
    id              BIGSERIAL     PRIMARY KEY,
    company_id      VARCHAR(64)   NOT NULL,
    cluster_name    VARCHAR(255),
    pod_name        VARCHAR(255)  NOT NULL,
    namespace       VARCHAR(255),
    overall_verdict VARCHAR(20)   NOT NULL,
    total_rules     INT           NOT NULL DEFAULT 0,
    passed          INT           NOT NULL DEFAULT 0,
    failed          INT           NOT NULL DEFAULT 0,
    skipped         INT           NOT NULL DEFAULT 0,
    rule_results    JSONB         NOT NULL,
    summary         JSONB,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grc_pge_company ON grc_pod_graph_evaluations(company_id);
CREATE INDEX IF NOT EXISTS idx_grc_pge_pod     ON grc_pod_graph_evaluations(pod_name, namespace);
CREATE INDEX IF NOT EXISTS idx_grc_pge_time    ON grc_pod_graph_evaluations(created_at DESC);

-- 9) Pod Graph 룰 마스터
CREATE TABLE IF NOT EXISTS grc_pod_graph_rules (
    rule_id           VARCHAR(30)   PRIMARY KEY,
    isms_p_item_id    VARCHAR(10)   NOT NULL,
    name              VARCHAR(200)  NOT NULL,
    severity          VARCHAR(20)   NOT NULL DEFAULT 'medium',
    judgment_source   VARCHAR(30)   NOT NULL DEFAULT 'k8s_native',
    check_category    VARCHAR(30)   NOT NULL DEFAULT 'pod_graph',
    evidence_type     TEXT,
    auto_collectable  BOOLEAN       NOT NULL DEFAULT true,
    enabled           BOOLEAN       NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_grc_pgr_item     ON grc_pod_graph_rules(isms_p_item_id);
CREATE INDEX IF NOT EXISTS idx_grc_pgr_severity ON grc_pod_graph_rules(severity);

-- Seed: 36 rules
INSERT INTO grc_pod_graph_rules (rule_id, isms_p_item_id, name, severity, judgment_source, check_category, evidence_type, auto_collectable) VALUES
  ('R-1.2.1-POD-01', '1.2.1', 'Namespace 자산 분류 라벨 점검', 'high', 'k8s_native', 'pod_graph', 'Namespace 필수 라벨 점검', true),
  ('R-1.2.1-POD-02', '1.2.1', '정보자산 분류 정책 존재', 'medium', 'k8s_native', 'pod_graph', '자산 분류 annotation 점검', true),
  ('R-1.2.2-POD-01', '1.2.2', 'ExternalName 외부 의존성 라벨 부재', 'medium', 'k8s_native', 'pod_graph', 'ExternalName Service 외부 의존성 라벨 점검', true),
  ('R-1.2.2-POD-02', '1.2.2', 'Ingress 흐름도 등록 annotation 부재', 'low', 'k8s_native', 'pod_graph', 'Ingress flow-registered annotation 점검', true),
  ('R-2.1.3-POD-01', '2.1.3', '워크로드 owner/contact annotation 부재', 'high', 'k8s_native', 'pod_graph', '워크로드 책임자 annotation 점검', true),
  ('R-2.1.3-POD-02', '2.1.3', 'security-class 라벨 부재', 'high', 'k8s_native', 'pod_graph', '보안 등급 라벨 점검', true),
  ('R-2.5.1-POD-01', '2.5.1', 'default ServiceAccount 사용', 'high', 'k8s_native', 'pod_graph', 'Pod default SA 사용 점검', true),
  ('R-2.5.1-POD-02', '2.5.1', 'ServiceAccount owner/team 라벨 부재', 'medium', 'k8s_native', 'pod_graph', 'SA 책임자 라벨 점검', true),
  ('R-2.5.1-POD-03', '2.5.1', '팀 간 ServiceAccount 공유', 'high', 'k8s_native', 'pod_graph', '교차 팀 SA 공유 점검', true),
  ('R-2.5.2-POD-01', '2.5.2', '추측 가능한 SA 이름', 'high', 'k8s_native', 'pod_graph', 'SA 이름 추측 가능성 점검', true),
  ('R-2.5.2-POD-02', '2.5.2', '일반 명명 패턴', 'medium', 'k8s_native', 'pod_graph', 'SA 일반 명명 패턴 점검', true),
  ('R-2.5.5-POD-01', '2.5.5', 'ServiceAccount 과잉 권한', 'critical', 'k8s_native', 'pod_graph', 'SA RBAC 과잉 권한 점검', true),
  ('R-2.5.5-POD-02', '2.5.5', '위험 동사 조합', 'critical', 'k8s_native', 'pod_graph', 'RBAC 위험 동사 조합 점검', true),
  ('R-2.6.1-POD-01', '2.6.1', 'hostNetwork 사용 점검', 'high', 'k8s_native', 'pod_graph', 'Pod 호스트 네트워크 공유 점검', true),
  ('R-2.6.1-POD-02', '2.6.1', 'NetworkPolicy 적용 점검', 'high', 'k8s_native', 'pod_graph', 'namespace NetworkPolicy 적용 점검', true),
  ('R-2.6.1-POD-03', '2.6.1', 'CNI NetworkPolicy 강제 지원 점검', 'high', 'k8s_native', 'pod_graph', 'CNI DaemonSet 종류 및 정책 강제 점검', true),
  ('R-2.6.1-POD-04', '2.6.1', 'cross-namespace 통신 통제 부재', 'high', 'k8s_native', 'pod_graph', 'cross-namespace 통신 NetworkPolicy 점검', true),
  ('R-2.6.3-POD-01', '2.6.3', 'Ingress 인증 annotation 미적용', 'high', 'k8s_native', 'pod_graph', 'Ingress 인증 설정 점검', true),
  ('R-2.6.3-POD-02', '2.6.3', 'mTLS 설정 점검', 'high', 'k8s_native', 'pod_graph', 'Service Mesh mTLS 점검', true),
  ('R-2.6.7-POD-01', '2.6.7', 'egress NetworkPolicy 미적용', 'medium', 'k8s_native', 'pod_graph', 'egress NetworkPolicy 적용 점검', true),
  ('R-2.7.1-POD-01', '2.7.1', 'Secret 암호화 점검', 'critical', 'k8s_native', 'pod_graph', 'Secret 평문 저장 점검', true),
  ('R-2.7.1-POD-02', '2.7.1', 'ConfigMap 내 민감정보 점검', 'high', 'k8s_native', 'pod_graph', 'ConfigMap 민감정보 포함 점검', true),
  ('R-2.7.1-POD-03', '2.7.1', '외부 노출 Ingress TLS 미설정', 'high', 'k8s_native', 'pod_graph', 'Ingress TLS 설정 점검', true),
  ('R-2.8.3-POD-01', '2.8.3', '워크로드 env 라벨 부재', 'high', 'k8s_native', 'pod_graph', '환경 라벨 점검', true),
  ('R-2.8.3-POD-02', '2.8.3', 'namespace 내 prod/dev 워크로드 혼재', 'high', 'k8s_native', 'pod_graph', '환경 분리 점검', true),
  ('R-2.8.3-POD-03', '2.8.3', 'prod Secret이 dev에서 참조', 'critical', 'k8s_native', 'pod_graph', '교차 환경 Secret 참조 점검', true),
  ('R-2.9.1-POD-01', '2.9.1', 'change-cause annotation 부재', 'medium', 'k8s_native', 'pod_graph', 'Deployment 변경 사유 기록 점검', true),
  ('R-2.9.1-POD-02', '2.9.1', 'revisionHistoryLimit=0', 'high', 'k8s_native', 'pod_graph', '롤백 이력 제한 점검', true),
  ('R-2.10.2-POD-08', '2.10.2', 'Namespace PSA 라벨 부재', 'high', 'k8s_native', 'pod_graph', 'Pod Security Admission 점검', true),
  ('R-2.10.3-POD-01', '2.10.3', 'LoadBalancer source range 미설정', 'high', 'k8s_native', 'pod_graph', 'LB source range 점검', true),
  ('R-2.10.3-POD-02', '2.10.3', '공개 Ingress WAF annotation 부재', 'high', 'k8s_native', 'pod_graph', 'WAF 적용 점검', true),
  ('R-2.10.3-POD-03', '2.10.3', 'NodePort Service 공개 의도 라벨 부재', 'medium', 'k8s_native', 'pod_graph', 'NodePort 공개 의도 점검', true),
  ('R-2.10.3-POD-04', '2.10.3', '공개 Ingress rate limit 미설정', 'medium', 'k8s_native', 'pod_graph', 'rate limit 점검', true),
  ('R-2.10.3-POD-05', '2.10.3', 'LoadBalancer 공개 의도 라벨 부재', 'medium', 'k8s_native', 'pod_graph', 'LB 공개 의도 점검', true),
  ('R-2.10.5-POD-01', '2.10.5', '외부 공개 Ingress TLS 미적용', 'critical', 'k8s_native', 'pod_graph', '외부 Ingress TLS 점검', true),
  ('R-2.10.5-POD-03', '2.10.5', 'ExternalName 평문 endpoint', 'high', 'k8s_native', 'pod_graph', 'ExternalName http:// 점검', true),
  ('R-2.10.8-POD-01', '2.10.8', 'Node kubeletVersion EOL', 'high', 'k8s_native', 'pod_graph', 'kubelet 버전 EOL 점검', true),
  ('R-2.10.8-POD-02', '2.10.8', '이미지 태그 mutable', 'medium', 'k8s_native', 'pod_graph', '이미지 태그 가변성 점검', true),
  ('R-2.10.8-POD-03', '2.10.8', '이미지 digest 미고정', 'high', 'k8s_native', 'pod_graph', '이미지 digest 고정 점검', true),
  ('R-2.11.3-POD-01', '2.11.3', 'prod 환경 shell exec 활동', 'critical', 'k8s_native', 'pod_graph', '운영 환경 Pod exec 점검', true)
ON CONFLICT (rule_id) DO NOTHING;
