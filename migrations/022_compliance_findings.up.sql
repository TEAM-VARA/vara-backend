-- ============================================================================
-- VARA Backend - Compliance Findings v2 (F-X.X.X-K8S-NN)
-- "컴플라이언스 점검 보조 도구" 관점: 도구는 관찰사항만 보고, 결함 판정은 심사원 몫
-- ============================================================================

-- 1) Finding 마스터 (27개 시드)
CREATE TABLE IF NOT EXISTS compliance_findings (
    finding_id              VARCHAR(50)   PRIMARY KEY,
    isms_p_item_id          VARCHAR(20)   NOT NULL,
    title                   TEXT          NOT NULL,

    -- verdict 4단계
    verdict_type            VARCHAR(30)   NOT NULL
        CHECK (verdict_type IN ('compliant_indicator','potential_finding','needs_review','additional_evidence')),

    -- 관찰 영역
    observation_template    TEXT          NOT NULL,
    target_resource         VARCHAR(50)   NOT NULL,
    required_data           JSONB         NOT NULL DEFAULT '[]',
    condition               JSONB         NOT NULL DEFAULT '{}',

    -- 컴플라이언스 매핑
    compliance_mappings     JSONB         NOT NULL DEFAULT '[]',
    kisa_defect_case_refs   JSONB         DEFAULT '[]',

    -- 추가 검토 필요 사항
    additional_review_items JSONB         NOT NULL DEFAULT '[]',
    manual_check_areas      JSONB         DEFAULT '[]',

    -- 자동화 커버리지
    automation_coverage     JSONB         DEFAULT '{}',

    -- 기타
    k8s_only_check          BOOLEAN       DEFAULT true,
    alternative_controls    JSONB         DEFAULT '[]',
    exception_conditions    JSONB,

    enabled                 BOOLEAN       DEFAULT true,
    deferred                BOOLEAN       DEFAULT false,
    deferred_reason         TEXT,

    created_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cf_item       ON compliance_findings(isms_p_item_id);
CREATE INDEX IF NOT EXISTS idx_cf_verdict    ON compliance_findings(verdict_type);
CREATE INDEX IF NOT EXISTS idx_cf_enabled    ON compliance_findings(enabled, deferred);

-- 2) Finding 평가 결과
CREATE TABLE IF NOT EXISTS finding_evaluations (
    id                      BIGSERIAL     PRIMARY KEY,
    finding_id              VARCHAR(50)   NOT NULL REFERENCES compliance_findings(finding_id),
    company_id              VARCHAR(64)   NOT NULL,
    cluster_name            VARCHAR(255)  NOT NULL,
    namespace               VARCHAR(255),
    pod_name                VARCHAR(255),
    evaluated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    matched                 BOOLEAN       NOT NULL,
    observation_text        TEXT,
    evidence                JSONB,

    -- 사용자 후속 조치
    user_status             VARCHAR(30)   DEFAULT 'pending',
    user_notes              TEXT,
    evidence_files          JSONB
);

CREATE INDEX IF NOT EXISTS idx_fe_company    ON finding_evaluations(company_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_fe_finding    ON finding_evaluations(finding_id);
CREATE INDEX IF NOT EXISTS idx_fe_cluster    ON finding_evaluations(cluster_name, namespace);

-- 3) 클러스터 단위 Finding 요약 (evaluate-cluster 결과)
CREATE TABLE IF NOT EXISTS finding_cluster_summaries (
    id                      BIGSERIAL     PRIMARY KEY,
    company_id              VARCHAR(64)   NOT NULL,
    cluster_name            VARCHAR(255)  NOT NULL,
    namespace               VARCHAR(255)  NOT NULL DEFAULT '',
    snapshot_at             TIMESTAMPTZ   NOT NULL,
    evaluated_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    total_findings          INT           NOT NULL DEFAULT 0,
    matched_count           INT           NOT NULL DEFAULT 0,
    unmatched_count         INT           NOT NULL DEFAULT 0,
    by_verdict              JSONB         NOT NULL DEFAULT '{}',
    findings_detail         JSONB         NOT NULL DEFAULT '[]',

    UNIQUE(company_id, cluster_name, namespace, snapshot_at)
);

CREATE INDEX IF NOT EXISTS idx_fcs_company   ON finding_cluster_summaries(company_id, evaluated_at DESC);

-- ============================================================================
-- 27개 Finding 시드 데이터
-- ============================================================================

-- 1.2.1 정보자산 식별
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-1.2.1-K8S-01', '1.2.1', 'K8s 클러스터 자산 인벤토리', 'compliant_indicator',
 '클러스터 ''{cluster}''에서 namespace {ns_count}개, Pod {pod_count}개, Service {svc_count}개, ConfigMap {cm_count}개 발견',
 'Cluster',
 '["cluster_namespaces","cluster_pods","cluster_services","cluster_configmaps"]',
 '{"operator":"inventory_report"}',
 '[{"framework":"ISMS-P","item":"1.2.1","match_strength":"supportive"}]',
 '[{"case_number":4,"description":"외부 위탁 IT 서비스 자산 식별 누락","match":"partial"}]',
 '["이 K8s 자산 목록이 회사 자산관리대장에 포함되어 있는가","K8s 외 자산(온프레미스, 외부 위탁 등)은 별도 식별되어 있는가","자산 분류 기준 문서를 보유하고 있는가","정기 자산 실사 기록(최소 연 1회) 보유 여부"]',
 '["정보자산 분류 기준 문서","외부 위탁 자산 식별 절차","자산관리시스템(CMDB)"]',
 '{"percentage":30,"covered":"K8s 클러스터 내 자산 식별","not_covered":"외부 자산, 분류 기준 합리성, 중요도 평가"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 1.2.2 현황 및 흐름분석
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-1.2.2-K8S-01', '1.2.2', '클러스터 내부 통신 관계 인벤토리', 'compliant_indicator',
 'Service {svc_count}개, Ingress {ing_count}개, NetworkPolicy {np_count}개 발견. 통신 그래프 엣지 {edge_count}개',
 'Cluster',
 '["cluster_services","cluster_ingresses","cluster_network_policies","cluster_pods"]',
 '{"operator":"traffic_graph_report"}',
 '[{"framework":"ISMS-P","item":"1.2.2","match_strength":"supportive"}]',
 '[]',
 '["이 통신 관계가 회사 정보흐름도에 반영되어 있는가","신규 서비스 추가 시 흐름도 갱신 절차 운영","개인정보 처리 흐름이 별도 표시되어 있는가"]',
 '["정보흐름도 문서","흐름도 갱신 절차","개인정보 처리 시스템 흐름도"]',
 '{"percentage":30,"covered":"K8s 통신 관계","not_covered":"흐름도 문서 자체, K8s 외 시스템 연계"}',
 true, null, null, true, false),
('F-1.2.2-K8S-02', '1.2.2', '외부 의존성 발견', 'compliant_indicator',
 'ExternalName Service {ext_svc_count}개 발견. 외부 도메인: {domain_list}. eBPF에서 외부 도메인 호출 {dns_count}회 관찰',
 'Service + eBPF',
 '["cluster_services","ebpf_dns_queries"]',
 '{"operator":"external_dependency_report","filter":{"type":"ExternalName"}}',
 '[{"framework":"ISMS-P","item":"1.2.2","match_strength":"supportive"}]',
 '[]',
 '["발견된 외부 의존성이 모두 정보흐름도에 등록되어 있는가","미등록 외부 연계 사유 확인","외부 위탁 계약 현황 매칭"]',
 '["외부 위탁 계약서","외부 연계 시스템 목록"]',
 '{"percentage":50,"covered":"클러스터에서 보이는 외부 연결","not_covered":"K8s 외 시스템의 외부 연결"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.1.3 정보자산 관리
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.1.3-K8S-01', '2.1.3', 'Pod 책임자 정보 부재', 'additional_evidence',
 'Pod {pod_count}개 중 책임자 정보(owner/contact annotation 또는 team 라벨) 부재 {missing_count}개. 목록: {missing_list}',
 'Pod',
 '["cluster_pods.annotations","cluster_pods.labels"]',
 '{"operator":"any_owner_indicator_exists","fields":["annotations.owner","annotations.contact","labels.team"]}',
 '[{"framework":"ISMS-P","item":"2.1.3","match_strength":"indirect"}]',
 '[]',
 '["회사가 K8s annotation으로 책임자를 관리하는 정책인가","외부 자산관리시스템(CMDB)에서 책임자 매핑 여부","책임자 미지정 자산의 사유 확인"]',
 '["자산관리시스템(CMDB) 책임자 매핑","책임자 지정 절차서"]',
 '{"percentage":30,"covered":"K8s 라벨 기반 책임자 식별","not_covered":"외부 시스템 매핑, 책임 위임 절차"}',
 true, '["외부 CMDB","ITSM 시스템"]', null, true, false),
('F-2.1.3-K8S-02', '2.1.3', '자산 변경 활동 감지', 'compliant_indicator',
 '최근 7일간 신규 워크로드 {created_count}개 생성, 폐기 {deleted_count}개 발견',
 'Workload (history)',
 '["cluster_workloads (snapshot history)"]',
 '{"operator":"change_activity_report","time_window":"7d"}',
 '[{"framework":"ISMS-P","item":"2.1.3","match_strength":"supportive"}]',
 '[]',
 '["이 변경 사항이 회사 자산관리 절차를 거쳤는가","자산관리대장에 반영되었는가","변경 신청/승인 결재 기록과 매칭"]',
 '["변경관리 시스템(ITSM)","자산관리대장"]',
 '{"percentage":100,"covered":"변경 감지","not_covered":"변경 절차 준수 여부"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.5.1 사용자 계정 관리
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.5.1-K8S-01', '2.5.1', 'default ServiceAccount 사용 발견', 'potential_finding',
 'Pod {pod_count}개가 default SA 사용 중. namespace 분포: {ns_distribution}. 목록: {pod_list}',
 'Pod',
 '["cluster_pods.service_account","cluster_pods.namespace"]',
 '{"operator":"in_set","field":"service_account","values":["","default"]}',
 '[{"framework":"ISMS-P","item":"2.5.1","match_strength":"direct"},{"framework":"개인정보보호법","item":"안전성 확보조치 - 계정 분리","match_strength":"direct"}]',
 '[{"case_number":null,"description":"공용 계정 사용","match":"direct"}]',
 '["해당 Pod가 인증범위 내 자산인가","default SA 사용에 대한 회사 정책상 예외 허용 사례인가","시스템 namespace는 예외 처리"]',
 '["계정 관리 정책","공용 계정 사용 예외 승인 기록"]',
 '{"percentage":100,"covered":"K8s 내 공용계정 패턴","not_covered":"사람 사용자 계정(외부 IdP)"}',
 true, null, '{"exception_namespaces":["kube-system","kube-public","kube-node-lease"]}', true, false),
('F-2.5.1-K8S-02', '2.5.1', '미사용(orphan) ServiceAccount 발견', 'potential_finding',
 'ServiceAccount {sa_total}개 중 {orphan_count}개가 어떤 RoleBinding/ClusterRoleBinding에도 연결되지 않음',
 'ServiceAccount',
 '["cluster_service_accounts","cluster_role_bindings","cluster_cluster_role_bindings"]',
 '{"operator":"orphan_serviceaccount"}',
 '[{"framework":"ISMS-P","item":"2.5.1","match_strength":"indirect"}]',
 '[{"case_number":null,"description":"불필요 계정 정기 점검/삭제 미흡","match":"partial"}]',
 '["이 SA들이 계획된 향후 사용을 위한 것인가","정기 점검 미실시로 잔존한 계정인가","회사의 계정 정기 점검 주기/기록 확인"]',
 '["계정 점검 절차서","최근 점검 기록"]',
 '{"percentage":80,"covered":"K8s SA 정리 상태","not_covered":"점검 절차 운영 여부"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.5.2 사용자 식별
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.5.2-K8S-01', '2.5.2', '추측 가능한 명칭의 ServiceAccount 발견', 'potential_finding',
 'SA {match_count}개의 이름이 추측 가능 패턴(admin/root/test/temp/guest)에 매칭. 목록: {sa_list}',
 'ServiceAccount',
 '["cluster_service_accounts.name"]',
 '{"operator":"regex_match","field":"name","pattern":"^(admin|root|test|temp|guest)(-.*)?$"}',
 '[{"framework":"ISMS-P","item":"2.5.2","match_strength":"direct"}]',
 '[{"case_number":null,"description":"admin, guest, test 등 추측 가능한 ID 운영","match":"direct"}]',
 '["해당 SA가 인증범위 내 자산인가","명명 자체보다 권한 범위 점검(F-2.5.5와 결합)","회사 명명 규칙 문서와 비교"]',
 '["계정 명명 규칙 문서"]',
 '{"percentage":80,"covered":"K8s SA 명명 점검","not_covered":"사람 사용자 ID 체계"}',
 true, null, null, true, false),
('F-2.5.2-K8S-02', '2.5.2', '일반 명명 패턴 ServiceAccount 발견', 'potential_finding',
 'user[0-9]+, account[0-9]+ 등 일반 명명 패턴 SA {match_count}개 발견',
 'ServiceAccount',
 '["cluster_service_accounts.name"]',
 '{"operator":"regex_match","field":"name","pattern":"^(user|account|sa)[0-9]+$"}',
 '[{"framework":"ISMS-P","item":"2.5.2","match_strength":"indirect"}]',
 '[]',
 '["용도가 의미적으로 식별 가능한가","운영 표준 명명 규칙과 일치하는가"]',
 '["계정 명명 규칙 문서"]',
 '{"percentage":80,"covered":"명명 규칙 점검만","not_covered":"실제 사용 패턴"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.5.5 특수 계정 및 권한 관리
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.5.5-K8S-01', '2.5.5', '클러스터 최고 권한 보유 SA 발견', 'potential_finding',
 '특수권한 보유 SA 발견 — cluster-admin 바인딩: {cluster_admin_sas}, 와일드카드 권한: {wildcard_sas}, 전체 Secret 접근: {secret_full_sas}',
 'ServiceAccount + RBAC chain',
 '["cluster_pods.service_account","cluster_role_bindings","cluster_cluster_role_bindings","cluster_roles","cluster_cluster_roles"]',
 '{"operator":"any_of","conditions":[{"binding_target":"cluster-admin"},{"rules_contain":{"verbs":["*"],"resources":["*"]}},{"cluster_scope_secret_access":["get","list","watch"]}]}',
 '[{"framework":"ISMS-P","item":"2.5.5","match_strength":"direct"},{"framework":"개인정보보호법","item":"안전성 확보조치 - 접근권한 차등 부여","match_strength":"direct"},{"framework":"ISO 27001","item":"A.9.2.3","match_strength":"indirect"}]',
 '[{"case_number":null,"description":"관리자 권한 일반 사용자에게 부여","match":"direct"}]',
 '["이 SA들이 회사의 특수권한자 목록에 등록되어 있는가","권한 부여 시 승인 결재 기록 확인","최근 권한 검토 기록(분기/반기) 확인","이 권한이 업무상 정말 필요한가(최소 권한 원칙)"]',
 '["특수권한자 목록","권한 부여 결재 기록","권한 검토 기록"]',
 '{"percentage":100,"covered":"특수권한 식별","not_covered":"승인/검토 절차 준수"}',
 true, null, '{"exception_namespaces":["kube-system"]}', true, false),
('F-2.5.5-K8S-02', '2.5.5', '위험 RBAC 권한 보유 SA 발견', 'potential_finding',
 '위험 권한 조합 보유 SA 발견 — {dangerous_pattern_summary}',
 'ServiceAccount + RBAC chain',
 '["cluster_role_bindings","cluster_cluster_role_bindings","cluster_roles","cluster_cluster_roles"]',
 '{"operator":"any_dangerous_verb","patterns":[{"name":"pod_exec","resource":"pods/exec","verbs":["create","*"]},{"name":"secret_write","resource":"secrets","verbs":["create","update","patch","*"]},{"name":"rbac_escalate","resource":"*","verbs":["escalate"]},{"name":"impersonate","resource":"users|groups|serviceaccounts","verbs":["impersonate"]}]}',
 '[{"framework":"ISMS-P","item":"2.5.5","match_strength":"direct"}]',
 '[]',
 '["각 권한이 회사 표준 RBAC 정책에 정의되어 있는가","권한 부여 사유와 승인 기록","권한 보유자 식별 가능성"]',
 '["RBAC 정책 문서","권한 부여 결재 기록"]',
 '{"percentage":100,"covered":"위험 권한 식별","not_covered":"정당성 평가"}',
 true, null, '{"exception_annotation":"rbac-exception/justification"}', true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.6.1 네트워크 접근
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.6.1-K8S-01', '2.6.1', 'NetworkPolicy 적용 현황', 'needs_review',
 '전체 namespace {ns_total}개 중 default-deny NetworkPolicy 적용 {applied_count}개 ({percentage}%). 미적용 namespace: {missing_ns_list}',
 'Namespace + NetworkPolicy',
 '["cluster_namespaces","cluster_network_policies"]',
 '{"operator":"default_deny_coverage_report"}',
 '[{"framework":"ISMS-P","item":"2.6.1","match_strength":"indirect"}]',
 '[{"case_number":null,"description":"서버팜과 사무망 미분리","match":"partial"}]',
 '["K8s NetworkPolicy 외 네트워크 분리 통제가 적용되어 있는가","미적용 namespace가 인증범위 내인가","운영망/개발망/DMZ 등 영역별 분리 설계"]',
 '["네트워크 분리 설계 문서","VPC/Subnet/Security Group 정책","사내망 IP 관리 대장"]',
 '{"percentage":40,"covered":"K8s NetworkPolicy 적용 현황","not_covered":"K8s 외 네트워크 통제, 사내망 단말 인증"}',
 true, '["VPC subnet 분리 + Security Group","Istio AuthorizationPolicy","Calico GlobalNetworkPolicy","별도 클러스터 운영"]', null, true, false),
('F-2.6.1-K8S-02', '2.6.1', 'CNI NetworkPolicy 강제 상태', 'needs_review',
 'kube-system namespace에서 NetworkPolicy 강제 CNI(Calico/Cilium) DaemonSet {found_status}',
 'Cluster Workload',
 '["cluster_workloads"]',
 '{"operator":"daemonset_exists","namespace":"kube-system","name_patterns":["calico-node","cilium","calico-kube-controllers"]}',
 '[{"framework":"ISMS-P","item":"2.6.1","match_strength":"indirect"}]',
 '[]',
 '["미발견 시 K8s NetworkPolicy 무효화 가능성 - 외부 통제로 분리 확인","발견 시 정책 강제 옵션 활성화 여부(도구는 옵션 미확인)"]',
 '["CNI 설정 문서","Network 강제 정책 운영 상태"]',
 '{"percentage":50,"covered":"CNI 배포 여부","not_covered":"정책 강제 옵션 활성화 상태"}',
 true, '["AWS VPC CNI + Security Group","Service Mesh","외부 NetFW"]', null, true, false),
('F-2.6.1-K8S-03', '2.6.1', 'Cross-namespace 통신 통제 현황', 'needs_review',
 'NetworkPolicy로 cross-namespace 통신 차단된 namespace {blocked_count}개, 차단 없음 {open_count}개',
 'NetworkPolicy + Namespace',
 '["cluster_network_policies","cluster_namespaces","cluster_pods"]',
 '{"operator":"cross_ns_traffic_control_report"}',
 '[{"framework":"ISMS-P","item":"2.6.1","match_strength":"indirect"}]',
 '[]',
 '["영역별 분리가 cluster 또는 VPC 분리로 이뤄지면 K8s 통제 불필요","단일 클러스터 내 영역 분리라면 K8s 통제 적용 권장"]',
 '["네트워크 분리 설계 문서","VPC 분리 정책"]',
 '{"percentage":50,"covered":"K8s NetworkPolicy 차원의 cross-ns 통제","not_covered":"VPC/Service Mesh 차원의 통제"}',
 true, '["VPC 라우팅","Service Mesh","별도 클러스터"]', null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.6.7 인터넷 접속 통제
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.6.7-K8S-01', '2.6.7', 'Pod egress 통제 현황', 'needs_review',
 '운영(env=prod 또는 production namespace) Pod 중 egress NetworkPolicy 미적용 {missing_count}개. 목록: {pod_list}',
 'Pod + NetworkPolicy',
 '["cluster_pods","cluster_network_policies"]',
 '{"operator":"egress_policy_applied"}',
 '[{"framework":"ISMS-P","item":"2.6.7","match_strength":"direct"}]',
 '[{"case_number":null,"description":"운영 서버에서 외부 인터넷 자유 접속","match":"direct"}]',
 '["K8s 외 VPC NAT Gateway 화이트리스트 적용 여부","프록시 서버를 통한 외부 접속 통제","발견된 Pod가 개인정보 처리 시스템인지"]',
 '["외부 접속 화이트리스트 정책","프록시 서버 운영 현황","VPC 라우팅 정책"]',
 '{"percentage":40,"covered":"K8s NetworkPolicy 기반 통제","not_covered":"VPC NAT, 프록시 등 외부 통제"}',
 true, '["VPC NAT Gateway 화이트리스트","프록시 서버(Squid 등)","Cilium FQDN policy","AWS Network Firewall"]', null, true, false),
('F-2.6.7-K8S-02', '2.6.7', '실제 외부 도메인 접속 관찰 (eBPF)', 'compliant_indicator',
 '최근 24h Pod별 외부 도메인 접속 Top {top_n}: {domain_distribution}',
 'eBPF DNS queries',
 '["ebpf_dns_queries","cluster_pods"]',
 '{"operator":"external_domain_traffic_report","time_window":"24h"}',
 '[{"framework":"ISMS-P","item":"2.6.7","match_strength":"supportive"}]',
 '[]',
 '["화이트리스트와 실제 접속 패턴 일치 여부","의심 도메인 접속이 있는가","개인정보 처리 Pod의 외부 접속 패턴 검토"]',
 '["외부 접속 화이트리스트","DNS 로그 분석 기록"]',
 '{"percentage":80,"covered":"실제 통신 패턴 관찰","not_covered":"통제 정책 자체"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.7.1 암호정책 적용
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred, deferred_reason) VALUES
('F-2.7.1-K8S-01', '2.7.1', 'Ingress TLS 적용 현황', 'potential_finding',
 'Ingress {total_count}개 중 TLS 설정 {tls_count}개, 미설정 {plaintext_count}개. 미설정 목록: {missing_list}',
 'Ingress',
 '["cluster_ingresses"]',
 '{"operator":"field_non_empty","field":"spec.tls"}',
 '[{"framework":"ISMS-P","item":"2.7.1","match_strength":"direct"},{"framework":"개인정보보호법","item":"안전성 확보조치 - 전송 시 암호화","match_strength":"direct"}]',
 '[{"case_number":null,"description":"외부 송수신 시 평문 전송","match":"direct"}]',
 '["미설정 Ingress가 외부 LB(CloudFront 등)에서 TLS 종료 후 평문 전달 구조인가","그렇다면 클러스터 내 통신 보호 별도 통제 필요(mTLS 등)","진짜 HTTP 평문이라면 즉시 시정"]',
 '["암호화 정책 문서","저장 데이터 암호화 적용","키 관리 정책/기록"]',
 '{"percentage":20,"covered":"Ingress 레벨 TLS","not_covered":"Secret etcd 암호화, ConfigMap 평문, KMS 키 관리"}',
 true, '["CloudFront/외부 LB TLS","외부 인증서 관리"]', null, true, false, 'AWS API 미접근으로 EKS describe/KMS/ALB 점검 불가')
ON CONFLICT (finding_id) DO NOTHING;

-- 2.8.3 시험과 운영 환경 분리
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.8.3-K8S-01', '2.8.3', '환경 라벨 적용 현황', 'additional_evidence',
 'Pod {total_count}개 중 env 라벨 적용 {applied_count}개 ({percentage}%). 미적용 namespace: {missing_ns}',
 'Pod',
 '["cluster_pods.labels"]',
 '{"operator":"label_value_in","field":"labels.env","values":["prod","stg","dev","test"]}',
 '[{"framework":"ISMS-P","item":"2.8.3","match_strength":"indirect"}]',
 '[]',
 '["회사가 env 라벨로 환경 구분 정책인가","별도 클러스터/VPC로 환경 분리되어 있는가","namespace 네이밍 컨벤션으로 식별되는가"]',
 '["환경 분리 정책 문서","클러스터/VPC 분리 설계"]',
 '{"percentage":0,"covered":"K8s 라벨 컨벤션 채택 시","not_covered":"클러스터/VPC 분리 점검"}',
 true, '["별도 클러스터","별도 VPC","namespace 네이밍 컨벤션"]', null, true, false),
('F-2.8.3-K8S-02', '2.8.3', '환경 혼재 namespace 발견', 'potential_finding',
 'namespace {mixed_count}개에서 env 라벨이 다른 워크로드 공존. 상세: {ns_env_distribution}',
 'Pod (cluster-wide)',
 '["cluster_pods.labels","cluster_namespaces"]',
 '{"operator":"namespace_env_homogeneous"}',
 '[{"framework":"ISMS-P","item":"2.8.3","match_strength":"direct"}]',
 '[{"case_number":null,"description":"동일 시스템에서 운영/개발 병행","match":"direct"}]',
 '["회사 환경 분리 정책이 namespace 단위인가 cluster 단위인가","namespace 분리 정책이면 결함 가능","cluster 분리 정책이면 namespace 내 혼재는 무관"]',
 '["환경 분리 정책 문서"]',
 '{"percentage":100,"covered":"env 라벨 부여 시 namespace 내 혼재 점검","not_covered":"라벨 미부여 시 점검 불가"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.10.3 공개서버 보안
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.10.3-K8S-03', '2.10.3', 'NodePort 노출 현황', 'needs_review',
 'type=NodePort Service {count}개 발견. 목록: {nodeport_list}',
 'Service',
 '["cluster_services"]',
 '{"operator":"field_equals","field":"spec.type","value":"NodePort"}',
 '[{"framework":"ISMS-P","item":"2.10.3","match_strength":"indirect"}]',
 '[]',
 '["발견된 NodePort가 의도된 공개인가","VPC SG에서 노드의 NodePort 차단되어 있는가"]',
 '["NodePort 사용 정책","VPC Security Group 설정"]',
 '{"percentage":50,"covered":"NodePort Service 식별","not_covered":"VPC SG 차단 여부"}',
 true, '["VPC Security Group","Network ACL"]', null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.10.5 정보전송 보안
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred) VALUES
('F-2.10.5-K8S-01', '2.10.5', '외부 공개 Ingress TLS 현황', 'potential_finding',
 '외부 공개 Ingress {total_count}개 중 TLS 미설정 {plaintext_count}개. 목록: {missing_list}',
 'Ingress',
 '["cluster_ingresses"]',
 '{"operator":"field_non_empty","field":"spec.tls","scope":"external_only"}',
 '[{"framework":"ISMS-P","item":"2.10.5","match_strength":"direct"},{"framework":"개인정보보호법","item":"안전성 확보조치 - 전송 시 암호화","match_strength":"direct"}]',
 '[{"case_number":null,"description":"HTTP 통신으로 개인정보 송수신","match":"direct"}]',
 '["미설정 Ingress가 개인정보/중요정보 송수신 경로인가","외부 LB에서 TLS 종료 + 클러스터 내 mTLS 구조인가"]',
 '["송수신 인터페이스 목록","개인정보 처리 시스템 흐름도"]',
 '{"percentage":40,"covered":"K8s Ingress TLS","not_covered":"mTLS, 외부 LB TLS"}',
 true, null, null, true, false),
('F-2.10.5-K8S-02', '2.10.5', 'ExternalName Service 평문 호출 발견', 'potential_finding',
 'ExternalName Service {total_count}개 중 http:// 시작 endpoint {plaintext_count}개. 목록: {list}',
 'Service',
 '["cluster_services"]',
 '{"operator":"all_of","conditions":[{"field":"spec.type","equals":"ExternalName"},{"field":"spec.externalName","regex_match":"^http://"}]}',
 '[{"framework":"ISMS-P","item":"2.10.5","match_strength":"direct"}]',
 '[{"case_number":null,"description":"외부 송수신 시 평문 전송","match":"direct"}]',
 '["평문 호출이 비중요 외부 서비스인가","중요 정보 송수신이면 https:// 변경 필요"]',
 '["외부 호출 인터페이스 목록","TLS 적용 정책"]',
 '{"percentage":100,"covered":"ExternalName http:// 점검","not_covered":"실제 호출되는 도메인의 정책"}',
 true, null, null, true, false)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.10.8 패치관리
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred, deferred_reason) VALUES
('F-2.10.8-K8S-01', '2.10.8', 'Node Kubernetes 버전 현황', 'potential_finding',
 'Node {total_count}개의 kubelet 버전 분포: {version_distribution}. EOL 버전 노드: {eol_count}개',
 'Node',
 '["cluster_nodes"]',
 '{"operator":"kubelet_version_check","min_supported":"current_stable - 2"}',
 '[{"framework":"ISMS-P","item":"2.10.8","match_strength":"direct"}]',
 '[{"case_number":null,"description":"EOL 시스템 운영","match":"direct"}]',
 '["EKS 지원 버전 정책과 비교","패치 일정 계획 확인"]',
 '["패치 정책 문서","정기 패치 적용 기록"]',
 '{"percentage":100,"covered":"K8s 자체 버전","not_covered":"제어 플레인(EKS 관리형), 노드 OS 버전"}',
 true, null, null, true, false, null),
('F-2.10.8-K8S-02', '2.10.8', '이미지 태그 안정성 현황', 'potential_finding',
 'Pod {total_count}개 중 mutable 태그(latest, stable 등) 사용 {mutable_count}개, 고정 태그 {fixed_count}개. 목록: {mutable_list}',
 'Pod',
 '["cluster_pods.containers[].image"]',
 '{"operator":"tag_mutable_check","mutable_patterns":["latest","stable","prod","main","master"]}',
 '[{"framework":"ISMS-P","item":"2.10.8","match_strength":"indirect"}]',
 '[]',
 '["mutable 태그 정책이 회사 표준에 부합하는가","패치 적용 시점 추적이 다른 방식으로 가능한가"]',
 '["이미지 태그 정책","CI/CD 빌드 추적 시스템"]',
 '{"percentage":100,"covered":"이미지 태그 안정성","not_covered":"실제 패치 적용 추적"}',
 true, null, null, true, false, null),
('F-2.10.8-K8S-03', '2.10.8', '이미지 디지스트 고정 현황', 'potential_finding',
 'Pod {total_count}개 중 image_digest 빈 값 {missing_count}개. 목록: {list}',
 'Pod',
 '["cluster_pods.containers[].image_digest"]',
 '{"operator":"digest_present"}',
 '[{"framework":"ISMS-P","item":"2.10.8","match_strength":"indirect"}]',
 '[]',
 '["digest 미고정이 회사 표준에 부합하는가","이미지 무결성을 다른 방식으로 보장하는가"]',
 '["이미지 무결성 정책","이미지 서명/검증 운영"]',
 '{"percentage":100,"covered":"디지스트 고정 여부","not_covered":"외부 스캐너 기반 취약점 점검"}',
 true, null, null, true, false, null),
('F-2.10.8-K8S-04', '2.10.8', '실행 중 이미지 알려진 취약점(CVE) 현황', 'potential_finding',
 '전체 이미지 중 {min_severity} 이상 CVE {matched_count}건. 상위: {top_list}',
 'Pod',
 '["cluster_pods.containers[].image_digest","image_vulnerabilities"]',
 '{"operator":"cve_vulnerability_check","min_severity":"HIGH"}',
 '[{"framework":"ISMS-P","item":"2.10.8","match_strength":"direct"}]',
 '[{"case_number":null,"description":"알려진 취약점 패치 미적용","match":"direct"}]',
 '["Trivy/Clair 등 이미지 스캔 도구 운영 여부","Critical CVE 긴급 패치 프로세스","취약점 관리 정책/기록"]',
 '["취약점 관리 정책","패치 적용 기록","이미지 스캔 운영 현황"]',
 '{"percentage":80,"covered":"Trivy 기반 CVE 스캔","not_covered":"OS 패치, 커스텀 취약점"}',
 true, null, null, true, false, null)
ON CONFLICT (finding_id) DO NOTHING;

-- 2.11.3 이상행위 분석 및 모니터링
INSERT INTO compliance_findings (finding_id, isms_p_item_id, title, verdict_type, observation_template, target_resource, required_data, condition, compliance_mappings, kisa_defect_case_refs, additional_review_items, manual_check_areas, automation_coverage, k8s_only_check, alternative_controls, exception_conditions, enabled, deferred, deferred_reason) VALUES
('F-2.11.3-K8S-01', '2.11.3', '운영 환경 Shell 활동 관찰 (eBPF)', 'potential_finding',
 'env=prod namespace Pod에서 shell exec 활동 {count}건 (24h 기준). 상세: {events}',
 'eBPF process events',
 '["ebpf_process_events","cluster_namespaces"]',
 '{"operator":"prod_shell_exec_detection","time_window":"24h","binary_patterns":["/bin/sh","/bin/bash","/usr/bin/sh","/usr/bin/bash","/bin/zsh"]}',
 '[{"framework":"ISMS-P","item":"2.11.3","match_strength":"indirect"}]',
 '[{"case_number":null,"description":"모니터링 사각지대 - 운영 중 비정상 활동 미감지","match":"partial"}]',
 '["발견된 shell exec이 인가된 운영 작업이었는가","kubectl exec 권한 보유 SA 식별","활동 시간대가 업무 시간 내인가","회사의 운영 접근 정책 확인"]',
 '["이상행위 탐지 도구 운영(Falco, Tetragon)","탐지 룰 정의 문서","이상행위 대응 절차","모니터링 로그 보관 정책"]',
 '{"percentage":30,"covered":"eBPF 기반 shell 활동","not_covered":"audit log 기반 비정상 활동(burst 요청, Forbidden 응답 등)"}',
 true, '["SSM Session Manager","Teleport","외부 PAM 도구"]', null, true, false, 'K8s audit log 미수집으로 burst/forbidden/unexpected_creator 룰 비활성')
ON CONFLICT (finding_id) DO NOTHING;
