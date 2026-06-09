-- ============================================================================
-- VARA RBAC Chain Analyzer - Rule Catalog
-- ============================================================================
--
-- 목적: rules/ 디렉토리의 룰 YAML 22종을 DB에서 조회 가능한 카탈로그로 적재.
--   - 룰의 의미(설명), 분류(category), 매칭 권한 조합, 그리고 fixpoint 엔진에
--     실제로 연결돼 있는지(engine_status)를 한 테이블에서 질의.
--
-- 설계 메모:
-- 1. 정적 참조 데이터(reference). 클러스터별이 아니라 룰셋 전역 1벌.
-- 2. severity 컬럼 없음 (의도). 위험도 대신 category + engine_status 로 표현.
-- 3. engine_status 의미:
--      'default' — pkg/fixpoint AllTransitions 에 등록, 기본 실행됨.
--      'opt-in'  — OptInTransitions. 플래그(opt_in_flag) 켜야 실행.
--      'unwired' — 룰 YAML 은 있으나 transition 미등록 → 현재 미탐지.
-- 4. transition_group: semantics.go 의 Group A/B/C/D/F/G 구분.
-- 5. match_kind/match_perms: 룰 YAML 의 match_any_of / match_all_of 를 그대로 반영.
--      any_of → 트리플 배열. all_of → 배열, OR 묶음은 {"any_of":[...]} 객체로.
-- ============================================================================

CREATE TABLE IF NOT EXISTS rbac_rule_catalog (
    rule_id          TEXT PRIMARY KEY,        -- "R-INDIRECT-01"
    category         TEXT NOT NULL,           -- direct | indirect | lateral
    schema_version   TEXT NOT NULL,           -- "0.1" | "1.0"
    title            TEXT NOT NULL,           -- 룰 YAML 원본 description
    summary_ko       TEXT NOT NULL,           -- 사람용 한글 설명
    match_kind       TEXT NOT NULL,           -- any_of | all_of
    match_perms      JSONB NOT NULL,          -- 매칭 권한 조합 (YAML 반영)
    engine_status    TEXT NOT NULL,           -- default | opt-in | unwired
    transition_group TEXT,                    -- A | B | C | D | F | G (nullable)
    opt_in_flag      TEXT,                    -- "include-eks-specific" 등 (nullable)
    sources          JSONB NOT NULL           -- [{type, name, url}]
);

CREATE INDEX IF NOT EXISTS idx_rule_catalog_category ON rbac_rule_catalog (category);
CREATE INDEX IF NOT EXISTS idx_rule_catalog_engine   ON rbac_rule_catalog (engine_status);


-- ============================================================================
-- 데이터 적재 (22종). 재실행 가능하도록 ON CONFLICT DO UPDATE.
-- ============================================================================

INSERT INTO rbac_rule_catalog
    (rule_id, category, schema_version, title, summary_ko, match_kind, match_perms, engine_status, transition_group, opt_in_flag, sources)
VALUES

-- ---- R-DIRECT (3) -------------------------------------------------------
('R-DIRECT-01', 'direct', '0.1',
 'roles/clusterroles에 escalate → K8s는 보통 자기가 안 가진 권한은 Role에 못 넣게 막지만, escalate가 있으면 그 제한이 풀려 자기 Role에 cluster-admin급 권한을 적어 넣어 스스로 부여.',
 '자기 권한을 스스로 더 높게 부여할 수 있음.',
 'any_of',
 '[{"api_group":"rbac.authorization.k8s.io","resource":"roles","verb":"escalate"},
   {"api_group":"rbac.authorization.k8s.io","resource":"clusterroles","verb":"escalate"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s RBAC - Privilege escalation prevention","url":"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"},
   {"type":"official","name":"K8s RBAC Good Practices - Escalate verb","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#escalate-verb"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - escalate_roles.rego","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/escalate_roles.rego"}]'::jsonb),

('R-DIRECT-02', 'direct', '0.1',
 'roles/clusterroles에 bind → 권한 연결(RoleBinding)은 원래 자기가 가진 범위 안에서만 되지만, bind가 있으면 제한 없이 강한 Role을 자기나 남에게 그대로 붙임.',
 '임의의 권한 묶음을 자기나 남에게 붙일 수 있음.',
 'any_of',
 '[{"api_group":"rbac.authorization.k8s.io","resource":"roles","verb":"bind"},
   {"api_group":"rbac.authorization.k8s.io","resource":"clusterroles","verb":"bind"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Privilege escalation prevention","url":"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"},
   {"type":"tool","name":"KubiScan","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane","url":"https://github.com/appvia/krane"},
   {"type":"tool","name":"rbac-police - bind_verb","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-DIRECT-03', 'direct', '0.1',
 'users/groups/serviceaccounts/uids에 impersonate → 요청을 보낼 때 다른 사람인 척 표시를 붙일 수 있음. 관리자 사용자·그룹으로 가장해 그 권한을 그대로 사용.',
 '다른 계정으로 위장해 그 권한을 그대로 사용.',
 'any_of',
 '[{"api_group":"","resource":"users","verb":"impersonate"},
   {"api_group":"","resource":"groups","verb":"impersonate"},
   {"api_group":"","resource":"serviceaccounts","verb":"impersonate"},
   {"api_group":"authentication.k8s.io","resource":"uids","verb":"impersonate"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - User Impersonation","url":"https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation"},
   {"type":"tool","name":"KubiScan","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane","url":"https://github.com/appvia/krane"},
   {"type":"tool","name":"rbac-police - user-impersonation","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

-- ---- R-INDIRECT (16) ----------------------------------------------------
('R-INDIRECT-01', 'indirect', '0.1',
 'pods에 create → Pod를 새로 만들 때 같은 네임스페이스의 권한 센 계정(SA)을 붙여 띄움. 그 Pod엔 계정 토큰이 자동으로 들어오니 안에서 꺼내 탈취.',
 '강한 계정을 단 Pod를 새로 띄워 그 토큰을 빼냄.',
 'any_of',
 '[{"api_group":"","resource":"pods","verb":"create"}]'::jsonb,
 'default', 'B', NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Workload creation","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation"},
   {"type":"tool","name":"KubiScan - Create Pod","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool - Create Workload","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane","url":"https://github.com/appvia/krane"},
   {"type":"tool","name":"rbac-police - assign_sa","url":"https://github.com/PaloAltoNetworks/rbac-police"},
   {"type":"writeup","name":"BishopFox - Bad Pods","url":"https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"}]'::jsonb),

('R-INDIRECT-02', 'indirect', '0.1',
 'pods/exec·pods/attach·pods/portforward에 create/get → 권한 센 계정으로 돌아가는 Pod에 원격 접속(exec)하거나 포트를 연결해, 그 안의 토큰 파일(/var/run/secrets/...)을 읽어 탈취.',
 '실행 중인 Pod에 접속(exec 등)해 그 안의 토큰을 탈취.',
 'any_of',
 '[{"api_group":"","resource":"pods/exec","verb":"create"},
   {"api_group":"","resource":"pods/exec","verb":"get"},
   {"api_group":"","resource":"pods/attach","verb":"create"},
   {"api_group":"","resource":"pods/attach","verb":"get"},
   {"api_group":"","resource":"pods/portforward","verb":"create"},
   {"api_group":"","resource":"pods/portforward","verb":"get"}]'::jsonb,
 'default', 'C', NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Workload creation (exec)","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation"},
   {"type":"tool","name":"KubiScan - Exec Into Pod / Attach","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool - Exec into Pod","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane","url":"https://github.com/appvia/krane"},
   {"type":"tool","name":"rbac-police - exec_into_pods","url":"https://github.com/PaloAltoNetworks/rbac-police"},
   {"type":"writeup","name":"BishopFox - Bad Pods","url":"https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"}]'::jsonb),

('R-INDIRECT-03', 'indirect', '0.1',
 'pods/ephemeralcontainers에 update/patch → 돌아가는 Pod에 임시 디버그 컨테이너를 하나 더 끼워넣어 같은 Pod의 토큰을 꺼냄. exec가 막혀 있어도 이 길로 우회.',
 '실행 중 Pod에 디버그 컨테이너를 끼워넣어 토큰을 빼냄.',
 'any_of',
 '[{"api_group":"","resource":"pods/ephemeralcontainers","verb":"update"},
   {"api_group":"","resource":"pods/ephemeralcontainers","verb":"patch"}]'::jsonb,
 'default', 'C', NULL,
 '[{"type":"official","name":"K8s - Ephemeral Containers","url":"https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/"},
   {"type":"official","name":"K8s - Debugging running Pods","url":"https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - inject_ephemeral_containers","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-04', 'indirect', '0.1',
 '워크로드 컨트롤러 7종(deployments/replicasets/statefulsets/daemonsets/jobs/cronjobs/replicationcontrollers)에 create/update/patch → Pod를 직접 못 만들어도 컨트롤러가 Pod를 찍어낼 때 쓰는 설계도(PodTemplateSpec)에 권한 센 계정을 적어두면 대신 만들어줌. 결국 R-INDIRECT-01과 같은 토큰 탈취.',
 'Pod를 직접 안 만들어도 Deployment 등 워크로드 설정을 바꿔 강한 계정 Pod가 생성되게 함.',
 'any_of',
 '[{"api_group":"apps","resource":"deployments","verb":"create"},
   {"api_group":"apps","resource":"deployments","verb":"update"},
   {"api_group":"apps","resource":"deployments","verb":"patch"},
   {"api_group":"apps","resource":"replicasets","verb":"create"},
   {"api_group":"apps","resource":"replicasets","verb":"update"},
   {"api_group":"apps","resource":"replicasets","verb":"patch"},
   {"api_group":"apps","resource":"statefulsets","verb":"create"},
   {"api_group":"apps","resource":"statefulsets","verb":"update"},
   {"api_group":"apps","resource":"statefulsets","verb":"patch"},
   {"api_group":"apps","resource":"daemonsets","verb":"create"},
   {"api_group":"apps","resource":"daemonsets","verb":"update"},
   {"api_group":"apps","resource":"daemonsets","verb":"patch"},
   {"api_group":"batch","resource":"jobs","verb":"create"},
   {"api_group":"batch","resource":"jobs","verb":"update"},
   {"api_group":"batch","resource":"jobs","verb":"patch"},
   {"api_group":"batch","resource":"cronjobs","verb":"create"},
   {"api_group":"batch","resource":"cronjobs","verb":"update"},
   {"api_group":"batch","resource":"cronjobs","verb":"patch"},
   {"api_group":"","resource":"replicationcontrollers","verb":"create"},
   {"api_group":"","resource":"replicationcontrollers","verb":"update"},
   {"api_group":"","resource":"replicationcontrollers","verb":"patch"}]'::jsonb,
 'default', 'B', NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Workload creation","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#workload-creation"},
   {"type":"official","name":"K8s - Workloads (controllers)","url":"https://kubernetes.io/docs/concepts/workloads/controllers/"},
   {"type":"tool","name":"KubiScan - workload controller create (6종)","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool - Create Workload","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane - risky create/update workloads (7종)","url":"https://github.com/appvia/krane/blob/master/config/rules.yaml"},
   {"type":"tool","name":"rbac-police - assign_sa","url":"https://github.com/PaloAltoNetworks/rbac-police"},
   {"type":"writeup","name":"BishopFox - Bad Pods","url":"https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"}]'::jsonb),

('R-INDIRECT-05', 'indirect', '0.1',
 'secrets에 get/list/watch → 비밀 저장소(Secret)를 직접 열람해 계정 토큰이나 DB 비밀번호 같은 민감정보를 그대로 가져감. (1.23 이하는 토큰이 Secret에 자동 저장돼 더 쉬움)',
 'Secret을 읽어 토큰·민감정보를 직접 획득.',
 'any_of',
 '[{"api_group":"","resource":"secrets","verb":"get"},
   {"api_group":"","resource":"secrets","verb":"list"},
   {"api_group":"","resource":"secrets","verb":"watch"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Listing secrets","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#listing-secrets"},
   {"type":"official","name":"K8s 1.24 - Bound Service Account Tokens","url":"https://kubernetes.io/blog/2022/04/13/bound-service-account-tokens/"},
   {"type":"tool","name":"KubiScan - Get/List Secrets","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool - Read Secrets","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"krane - risky get/list secrets","url":"https://github.com/appvia/krane/blob/master/config/rules.yaml"},
   {"type":"tool","name":"rbac-police - retrieve_token_secrets","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-06', 'indirect', '0.1',
 'serviceaccounts/token에 create → 정식 발급 기능(TokenRequest, 1.24+)으로 원하는 계정의 토큰을 그 자리에서 새로 받아 그 권한 사용.',
 '임의 계정의 토큰을 즉석에서 발급받음.',
 'any_of',
 '[{"api_group":"","resource":"serviceaccounts/token","verb":"create"}]'::jsonb,
 'default', 'B', NULL,
 '[{"type":"official","name":"K8s - TokenRequest API","url":"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens"},
   {"type":"official","name":"KEP-1205 - Bound Service Account Tokens","url":"https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/1205-bound-service-account-tokens"},
   {"type":"tool","name":"rbac-police - request_token_for_sas","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-07', 'indirect', '1.0',
 'certificatesigningrequests/approval에 update/patch 그리고 signers(kubernetes.io/kube-apiserver-client)에 approve — 둘 다 필요 → 인증서 발급 요청(CSR)을 자기가 올리고 자기가 승인해 최고 관리자 그룹(system:masters) 인증서를 발급받아 cluster-admin 도달.',
 '인증서 승인 권한으로 관리자급 인증서를 직접 발급해 클러스터 관리자에 도달.',
 'all_of',
 '[{"any_of":[{"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"update"},
               {"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"patch"}]},
   {"api_group":"certificates.k8s.io","resource":"signers","verb":"approve","resource_names":["kubernetes.io/kube-apiserver-client"]}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Certificate Signing Requests","url":"https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/"},
   {"type":"official","name":"K8s RBAC Good Practices: CSRs and certificate issuing","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#csrs-and-certificate-issuing"},
   {"type":"tool","name":"rbac-police - approve_csrs","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/approve_csrs.rego"}]'::jsonb),

('R-INDIRECT-08', 'indirect', '0.1',
 'validatingwebhookconfigurations/mutatingwebhookconfigurations에 create/update/patch → 클러스터로 들어오는 요청을 중간에서 가로채는 검문소(웹훅)를 등록. 지나가는 데이터에서 토큰을 빼내거나, 새로 만들어지는 Pod에 권한 센 계정을 강제로 붙임.',
 'Admission 웹훅을 등록해 오가는 요청에서 토큰을 가로채거나 강한 계정을 강제 주입.',
 'any_of',
 '[{"api_group":"admissionregistration.k8s.io","resource":"validatingwebhookconfigurations","verb":"create"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingwebhookconfigurations","verb":"update"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingwebhookconfigurations","verb":"patch"},
   {"api_group":"admissionregistration.k8s.io","resource":"mutatingwebhookconfigurations","verb":"create"},
   {"api_group":"admissionregistration.k8s.io","resource":"mutatingwebhookconfigurations","verb":"update"},
   {"api_group":"admissionregistration.k8s.io","resource":"mutatingwebhookconfigurations","verb":"patch"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Admission Webhooks","url":"https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/"},
   {"type":"official","name":"K8s RBAC Good Practices: Control admission webhooks","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#control-admission-webhooks"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - manage_webhooks","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-09', 'indirect', '0.1',
 'apiservices(aggregation layer)에 create/update/patch → 특정 API 처리를 공격자 서버가 대신 받도록 등록·변조. 그 API로 오가는 요청의 토큰과 응답을 가로채 조작.',
 'APIService를 조작해 집계 API를 가로채 토큰·응답을 변조.',
 'any_of',
 '[{"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"create"},
   {"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"update"},
   {"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"patch"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Configure the Aggregation Layer","url":"https://kubernetes.io/docs/tasks/extend-kubernetes/configure-aggregation-layer/"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-11","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-INDIRECT-11', 'indirect', '0.1',
 'nodes/proxy에 get/create → 권한을 검사하는 정문(API 서버)을 건너뛰고 노드의 관리 데몬(kubelet)에 바로 명령. 그 노드의 아무 Pod에나 들어가 토큰을 빼냄.',
 '노드 kubelet API에 직접 접근(RBAC 우회)해 Pod 안의 토큰을 빼냄.',
 'any_of',
 '[{"api_group":"","resource":"nodes/proxy","verb":"get"},
   {"api_group":"","resource":"nodes/proxy","verb":"create"}]'::jsonb,
 'default', 'D', NULL,
 '[{"type":"official","name":"K8s - Kubelet authentication/authorization","url":"https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/"},
   {"type":"official","name":"K8s RBAC Good Practices: proxy subresource of Nodes","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#proxy-subresource-of-nodes"},
   {"type":"tool","name":"KubiScan","url":"https://github.com/cyberark/KubiScan"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - kubelet API access","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-12', 'indirect', '0.1',
 'namespaces에 patch → 네임스페이스의 라벨(꼬리표)을 바꿈. 보안 등급(PodSecurity)을 낮춰 위험한 특권 Pod를 띄우거나, 통신 차단 규칙(NetworkPolicy)이 보는 라벨을 흔들어 격리를 빠져나감.',
 '네임스페이스 라벨을 바꿔 PodSecurity·NetworkPolicy를 우회.',
 'any_of',
 '[{"api_group":"","resource":"namespaces","verb":"patch"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices - Namespace modification","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#namespace-modification"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-11","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-INDIRECT-15', 'indirect', '0.1',
 'persistentvolumes에 create → 노드의 실제 디스크(예: /)를 그대로 가리키는 저장소(hostPath PV)를 만듦. 그걸 연결한 Pod로 같은 노드에 있는 다른 Pod의 토큰·kubelet 인증서를 읽어 탈취.',
 'hostPath 볼륨으로 노드 파일시스템을 마운트해 같은 노드의 토큰을 탈취.',
 'any_of',
 '[{"api_group":"","resource":"persistentvolumes","verb":"create"}]'::jsonb,
 'default', 'D', NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Persistent volume creation","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#persistent-volume-creation"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"}]'::jsonb),

('R-INDIRECT-16', 'indirect', '1.0',
 'kube-system의 aws-auth ConfigMap에 update/patch (EKS 전용) → EKS의 접근 권한 명단(aws-auth)에 자기 AWS 신원(IAM)을 최고 관리자(system:masters)로 추가해 EKS cluster-admin 획득.',
 'EKS 전용. aws-auth 설정에 자기 계정을 관리자로 추가. opt-in 플래그 필요.',
 'all_of',
 '[{"any_of":[{"api_group":"","resource":"configmaps","verb":"update","resource_names":["aws-auth"],"within_namespaces":["kube-system"]},
               {"api_group":"","resource":"configmaps","verb":"patch","resource_names":["aws-auth"],"within_namespaces":["kube-system"]}]}]'::jsonb,
 'opt-in', 'F', 'include-eks-specific',
 '[{"type":"tool","name":"rbac-police - eks_modify_aws_auth","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/eks_modify_aws_auth.rego"},
   {"type":"tool","name":"IceKube - UPDATE_AWS_AUTH","url":"https://github.com/ReversecLabs/IceKube"},
   {"type":"vendor","name":"AWS EKS - aws-auth ConfigMap","url":"https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html"}]'::jsonb),

('R-INDIRECT-17', 'indirect', '1.0',
 'secrets에 create/update/patch 그리고 secrets에 get — 둘 다 필요 → 계정 토큰용 Secret(type=kubernetes.io/service-account-token)을 만들면 시스템이 진짜 토큰을 자동으로 채워줌. 그걸 get으로 읽어 탈취(최신 1.24+에서도 통하는 수동 경로).',
 'Secret을 만들고 읽을 수 있어 계정 토큰 Secret을 발급해 탈취.',
 'all_of',
 '[{"any_of":[{"api_group":"","resource":"secrets","verb":"create"},
               {"api_group":"","resource":"secrets","verb":"update"},
               {"api_group":"","resource":"secrets","verb":"patch"}]},
   {"api_group":"","resource":"secrets","verb":"get"}]'::jsonb,
 'default', 'B', NULL,
 '[{"type":"tool","name":"rbac-police - issue_token_secrets","url":"https://github.com/PaloAltoNetworks/rbac-police"},
   {"type":"official","name":"K8s - Manually create a long-lived API token for a SA","url":"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#manually-create-a-long-lived-api-token-for-a-serviceaccount"},
   {"type":"official","name":"K8s 1.24 - 수동 token Secret 메커니즘 유지","url":"https://kubernetes.io/blog/2022/04/13/bound-service-account-tokens/"}]'::jsonb),

('R-INDIRECT-18', 'indirect', '0.1',
 'validatingadmissionpolicies/validatingadmissionpolicybindings에 create/update/patch → 요청을 자동 검사하는 보안 규칙(1.30+ CEL 기반 admission 정책)을 직접 만들고 고쳐, 검사를 무력화하거나 자기 요청만 통과하게 조작.',
 'Validating Admission Policy를 조작해 보안 검사 규칙을 변조.',
 'any_of',
 '[{"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"create"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"update"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"patch"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"create"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"update"},
   {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"patch"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Validating Admission Policy","url":"https://kubernetes.io/docs/reference/access-authn-authz/validating-admission-policy/"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"}]'::jsonb),

('R-INDIRECT-19', 'indirect', '1.0',
 'pods에 delete/deletecollection(또는 pods/eviction에 create) 그리고 nodes에 update/patch — 둘 다 필요 → 다른 노드를 Pod 배치 금지로 막고 권한 센 Pod를 쫓아냄. 그 Pod가 공격자 노드로 옮겨와 다시 뜨고, 거기서 토큰 흡수.',
 'Pod 삭제와 노드 조작 권한으로 강한 Pod를 자기 노드로 옮겨 토큰을 흡수.',
 'all_of',
 '[{"any_of":[{"api_group":"","resource":"pods","verb":"delete"},
               {"api_group":"","resource":"pods","verb":"deletecollection"},
               {"api_group":"","resource":"pods/eviction","verb":"create"}]},
   {"any_of":[{"api_group":"","resource":"nodes","verb":"update"},
               {"api_group":"","resource":"nodes","verb":"patch"}]}]'::jsonb,
 'default', 'G', NULL,
 '[{"type":"tool","name":"rbac-police - steal_pods","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/steal_pods.rego"}]'::jsonb),

-- ---- R-LATERAL (3) ------------------------------------------------------
('R-LATERAL-01', 'lateral', '0.1',
 'nodes/nodes-status에 update/patch → 노드 설정(taint/label)을 바꿔 어떤 Pod가 어디서 돌지 조정. 보안 감시 프로그램(DaemonSet)이 특정 노드를 피하게 만들어 감시를 회피. (권한상승 아님)',
 '노드 taint/label을 조작해 스케줄링을 바꾸고 보안 DaemonSet을 회피. 권한상승 아님.',
 'any_of',
 '[{"api_group":"","resource":"nodes","verb":"update"},
   {"api_group":"","resource":"nodes","verb":"patch"},
   {"api_group":"","resource":"nodes/status","verb":"update"},
   {"api_group":"","resource":"nodes/status","verb":"patch"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s - Taints and Tolerations","url":"https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/"},
   {"type":"tool","name":"rbac-police - modify_node_status (Low)","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-LATERAL-02', 'lateral', '0.1',
 'nodes에 delete → 보안 감시가 돌던 노드(서버)를 통째로 삭제해 사각지대를 만든 뒤 그쪽에서 들키지 않고 작업. (권한상승 아님)',
 '노드를 삭제해 보안 감시 사각지대를 만듦. 권한상승 아님.',
 'any_of',
 '[{"api_group":"","resource":"nodes","verb":"delete"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s - Nodes","url":"https://kubernetes.io/docs/concepts/architecture/nodes/"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-09","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-LATERAL-03', 'lateral', '0.1',
 'namespaces에 delete → 보안 도구가 들어있는 네임스페이스(kube-system, falco-system 등)를 통째로 삭제해 보안 장치 자체를 없앰. (권한상승 아님)',
 '보안 도구가 든 네임스페이스를 통째로 삭제. 권한상승 아님.',
 'any_of',
 '[{"api_group":"","resource":"namespaces","verb":"delete"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices - Namespace modification","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#namespace-modification"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-11","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb)

ON CONFLICT (rule_id) DO UPDATE SET
    category         = EXCLUDED.category,
    schema_version   = EXCLUDED.schema_version,
    title            = EXCLUDED.title,
    summary_ko       = EXCLUDED.summary_ko,
    match_kind       = EXCLUDED.match_kind,
    match_perms      = EXCLUDED.match_perms,
    engine_status    = EXCLUDED.engine_status,
    transition_group = EXCLUDED.transition_group,
    opt_in_flag      = EXCLUDED.opt_in_flag,
    sources          = EXCLUDED.sources;
