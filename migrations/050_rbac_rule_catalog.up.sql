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
 'escalate verb on roles/clusterroles -> arbitrary self-grant',
 'roles/clusterroles 에 escalate 권한. 본인에게 임의 권한을 직접 자가부여(self-grant).',
 'any_of',
 '[{"api_group":"rbac.authorization.k8s.io","resource":"roles","verb":"escalate"},
   {"api_group":"rbac.authorization.k8s.io","resource":"clusterroles","verb":"escalate"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s RBAC - Privilege escalation prevention","url":"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping"},
   {"type":"official","name":"K8s RBAC Good Practices - Escalate verb","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#escalate-verb"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - escalate_roles.rego","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/escalate_roles.rego"}]'::jsonb),

('R-DIRECT-02', 'direct', '0.1',
 'bind verb on roles/clusterroles -> 자기/타인에게 임의 (Cluster)Role 부착 가능',
 'roles/clusterroles 에 bind 권한. 자신이나 타인에게 임의의 (Cluster)Role 을 붙일 수 있음.',
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
 'impersonate verb on users/groups/serviceaccounts/uids -> 다른 신원으로 가장하여 그 권한 전체 사용 가능',
 'users/groups/serviceaccounts/uids 에 impersonate 권한. 다른 신원으로 가장해 그 권한을 전부 사용.',
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
 'create on pods -> spec.serviceAccountName으로 같은 NS 임의 SA를 마운트한 Pod 생성 가능',
 'pods create 로 같은 NS 의 강한 SA 를 마운트한 Pod 를 생성해 그 SA 토큰을 흡수.',
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
 'create/get on pods/exec|attach|portforward -> 실행 중 Pod 컨테이너에서 그 Pod SA 토큰 또는 동등 효과 획득',
 'pods/exec, attach, portforward 로 실행 중 Pod 에 들어가 그 Pod 의 SA 토큰을 탈취.',
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
 'update/patch on pods/ephemeralcontainers -> 실행 중 Pod에 디버그 컨테이너 주입, 그 Pod SA 토큰 획득',
 'pods/ephemeralcontainers update/patch 로 실행 중 Pod 에 디버그 컨테이너를 주입해 토큰 획득.',
 'any_of',
 '[{"api_group":"","resource":"pods/ephemeralcontainers","verb":"update"},
   {"api_group":"","resource":"pods/ephemeralcontainers","verb":"patch"}]'::jsonb,
 'default', 'C', NULL,
 '[{"type":"official","name":"K8s - Ephemeral Containers","url":"https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/"},
   {"type":"official","name":"K8s - Debugging running Pods","url":"https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"},
   {"type":"tool","name":"rbac-police - inject_ephemeral_containers","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-04', 'indirect', '0.1',
 'create/update/patch on workload controllers (7종) -> PodTemplateSpec으로 임의 SA 마운트 Pod 간접 생성',
 '워크로드 컨트롤러 7종(deployments/replicasets/statefulsets/daemonsets/jobs/cronjobs/replicationcontrollers)의 PodTemplateSpec 변조로 R-INDIRECT-01 을 간접 우회.',
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
 'get/list/watch on secrets -> 수동 또는 1.23 이하 자동 SA token Secret 직접 읽기 가능',
 'secrets get/list/watch 로 SA 토큰 Secret 이나 민감 데이터를 직접 읽음. (현재 엔진 미연결)',
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
 'create on serviceaccounts/token -> 임의 SA 토큰 즉석 발급 (TokenRequest API, K8s 1.24+ 정식 경로)',
 'serviceaccounts/token create 로 TokenRequest API 를 호출해 임의 SA 토큰을 즉석 발급.',
 'any_of',
 '[{"api_group":"","resource":"serviceaccounts/token","verb":"create"}]'::jsonb,
 'default', 'B', NULL,
 '[{"type":"official","name":"K8s - TokenRequest API","url":"https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/#bound-service-account-tokens"},
   {"type":"official","name":"KEP-1205 - Bound Service Account Tokens","url":"https://github.com/kubernetes/enhancements/tree/master/keps/sig-auth/1205-bound-service-account-tokens"},
   {"type":"tool","name":"rbac-police - request_token_for_sas","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-INDIRECT-07', 'indirect', '1.0',
 'csr/approval (update|patch) AND signers/kube-apiserver-client approve -> cluster-admin 인증서 발급',
 'csr/approval update|patch 와 kube-apiserver-client signer approve 를 함께 가지면 system:masters 인증서를 발급해 cluster-admin 도달.',
 'all_of',
 '[{"any_of":[{"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"update"},
               {"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"patch"}]},
   {"api_group":"certificates.k8s.io","resource":"signers","verb":"approve","resource_names":["kubernetes.io/kube-apiserver-client"]}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Certificate Signing Requests","url":"https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/"},
   {"type":"official","name":"K8s RBAC Good Practices: CSRs and certificate issuing","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#csrs-and-certificate-issuing"},
   {"type":"tool","name":"rbac-police - approve_csrs","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/approve_csrs.rego"}]'::jsonb),

('R-INDIRECT-08', 'indirect', '0.1',
 'create/update/patch on validating/mutating webhook configurations -> admission 가로채기로 token 훔침 또는 강제 SA 마운트',
 'validating/mutating webhook configuration 등록/수정으로 admission 을 가로채 토큰을 훔치거나 강제 SA 마운트.',
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
 'create/update/patch on apiservices -> aggregated API hijack (token/response tampering)',
 'apiservices 등록/수정으로 aggregated API 를 하이재킹해 토큰/응답을 변조. VARA 자체 룰(외부 도구 미커버).',
 'any_of',
 '[{"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"create"},
   {"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"update"},
   {"api_group":"apiregistration.k8s.io","resource":"apiservices","verb":"patch"}]'::jsonb,
 'default', 'A', NULL,
 '[{"type":"official","name":"K8s - Configure the Aggregation Layer","url":"https://kubernetes.io/docs/tasks/extend-kubernetes/configure-aggregation-layer/"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-11","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-INDIRECT-11', 'indirect', '0.1',
 'get/create on nodes/proxy -> kubelet API 직접 호출로 임의 Pod exec, 토큰 추출',
 'nodes/proxy get/create 로 kubelet API 를 직접 호출(RBAC 우회)해 임의 Pod exec, 토큰 추출.',
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
 'patch on namespaces -> label modification (PodSecurity bypass, NetworkPolicy bypass)',
 'namespaces patch 로 라벨을 변경해 PodSecurity/NetworkPolicy 를 우회. (현재 엔진 미연결)',
 'any_of',
 '[{"api_group":"","resource":"namespaces","verb":"patch"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices - Namespace modification","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#namespace-modification"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-11","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-INDIRECT-15', 'indirect', '0.1',
 'create on persistentvolumes -> hostPath PV로 host 파일시스템 마운트, 같은 노드 토큰 탈취',
 'persistentvolumes create 로 hostPath PV 를 만들어 호스트 파일시스템을 마운트, 같은 노드의 토큰 탈취.',
 'any_of',
 '[{"api_group":"","resource":"persistentvolumes","verb":"create"}]'::jsonb,
 'default', 'D', NULL,
 '[{"type":"official","name":"K8s RBAC Good Practices: Persistent volume creation","url":"https://kubernetes.io/docs/concepts/security/rbac-good-practices/#persistent-volume-creation"},
   {"type":"tool","name":"rbac-tool","url":"https://github.com/alcideio/rbac-tool"}]'::jsonb),

('R-INDIRECT-16', 'indirect', '1.0',
 'EKS kube-system/aws-auth ConfigMap update/patch -> system:masters mapping 추가 가능 -> cluster-admin',
 'EKS 전용. kube-system/aws-auth ConfigMap 의 mapRoles/mapUsers 에 system:masters 를 추가해 cluster-admin. opt-in 플래그 필요.',
 'all_of',
 '[{"any_of":[{"api_group":"","resource":"configmaps","verb":"update","resource_names":["aws-auth"],"within_namespaces":["kube-system"]},
               {"api_group":"","resource":"configmaps","verb":"patch","resource_names":["aws-auth"],"within_namespaces":["kube-system"]}]}]'::jsonb,
 'opt-in', 'F', 'include-eks-specific',
 '[{"type":"tool","name":"rbac-police - eks_modify_aws_auth","url":"https://github.com/PaloAltoNetworks/rbac-police/blob/main/lib/eks_modify_aws_auth.rego"},
   {"type":"tool","name":"IceKube - UPDATE_AWS_AUTH","url":"https://github.com/ReversecLabs/IceKube"},
   {"type":"vendor","name":"AWS EKS - aws-auth ConfigMap","url":"https://docs.aws.amazon.com/eks/latest/userguide/auth-configmap.html"}]'::jsonb),

('R-INDIRECT-17', 'indirect', '1.0',
 'secrets (create|update|patch) AND secrets get -> type=service-account-token Secret 발급 + 토큰 탈취 (1.24+ 우회)',
 'secrets create/update/patch 와 get 을 함께 가지면 service-account-token 타입 Secret 을 발급하고 그 토큰을 읽어 탈취.',
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
 'create/update/patch on validating admission policies/bindings -> CEL admission 정책 조작 (K8s 1.30+)',
 'validatingadmissionpolicies/bindings 조작으로 CEL 기반 admission 정책을 변조. K8s 1.30+ 메커니즘.',
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
 'delete/eviction pods + nodes update/patch -> Pod 이주로 다른 SA 토큰 흡수',
 'pods delete/eviction 와 nodes update/patch 를 함께 가지면 노드를 unschedulable 로 만들어 강한 Pod 을 본인 노드로 이주시켜 토큰 흡수.',
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
 'update/patch on nodes or nodes/status -> taints/labels 조작으로 스케줄링 변경, 보안 DaemonSet 회피',
 'nodes/nodes-status update/patch 로 taint/label 을 조작해 스케줄링을 바꾸고 보안 DaemonSet 을 회피. 권한상승 아님. (현재 엔진 미연결)',
 'any_of',
 '[{"api_group":"","resource":"nodes","verb":"update"},
   {"api_group":"","resource":"nodes","verb":"patch"},
   {"api_group":"","resource":"nodes/status","verb":"update"},
   {"api_group":"","resource":"nodes/status","verb":"patch"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s - Taints and Tolerations","url":"https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/"},
   {"type":"tool","name":"rbac-police - modify_node_status (Low)","url":"https://github.com/PaloAltoNetworks/rbac-police"}]'::jsonb),

('R-LATERAL-02', 'lateral', '0.1',
 'delete on nodes -> 보안 모니터링 노드 삭제, 회피 워크로드 운영',
 'nodes delete 로 보안 모니터링 노드를 삭제해 사각지대를 만듦. 권한상승 아님. VARA 자체 룰. (현재 엔진 미연결)',
 'any_of',
 '[{"api_group":"","resource":"nodes","verb":"delete"}]'::jsonb,
 'unwired', NULL, NULL,
 '[{"type":"official","name":"K8s - Nodes","url":"https://kubernetes.io/docs/concepts/architecture/nodes/"},
   {"type":"writeup","name":"VARA 5-source matrix analysis 2026-05-09","url":"https://www.notion.so/3593978ee48d81a4ad8dd3d77aaa095c"}]'::jsonb),

('R-LATERAL-03', 'lateral', '0.1',
 'delete on namespaces -> security-tool NS wipe (kube-system, falco-system, etc.)',
 'namespaces delete 로 보안 도구 네임스페이스(kube-system, falco-system 등)를 통째로 삭제. 권한상승 아님. VARA 자체 룰. (현재 엔진 미연결)',
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
