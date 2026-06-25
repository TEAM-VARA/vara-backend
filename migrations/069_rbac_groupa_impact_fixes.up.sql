-- ============================================================================
-- 056: Group A 영향도/트리거 정밀화 반영 (semantics.go 2026-06 패치 동기화)
-- ============================================================================
-- rbac_rule_catalog 는 참조(reference) 데이터로 엔진 탐지 동작과 무관하다.
-- 본 마이그레이션은 050 카탈로그를 fixpoint 전이/룰 YAML 변경에 맞춰 갱신한다.
--   - R-DIRECT-01/02: scope 인지(clusterroles/clusterrolebindings→cluster-admin,
--                     namespaced→namespace-admin). 02는 bind 단독→bind AND 바인딩생성.
--   - R-DIRECT-03   : groups(system:masters)→cluster-admin, serviceaccounts→SA 흡수,
--                     users→신원흡수(데이터 의존), uids 제거.
--   - R-INDIRECT-07 : CSR create+get 추가 (4요소 체인).
--   - R-INDIRECT-09 : unwire (apiservices 가로채기·직행 아님).
--   - R-INDIRECT-18 : unwire (VAP 검증 전용·방어약화) + delete/deletecollection verb.
-- ============================================================================

-- R-DIRECT-01: escalate. 트리거 동일, 영향도만 scope 인지(전이 레벨).
UPDATE rbac_rule_catalog SET
  summary_ko = 'escalate로 자기 Role에 임의 권한 부여. clusterroles면 cluster-admin, namespaced roles면 namespace-admin(전이가 scope 판별).'
WHERE rule_id = 'R-DIRECT-01';

-- R-DIRECT-02: bind 단독 → (bind) AND (create|update|patch on (cluster)rolebindings).
UPDATE rbac_rule_catalog SET
  schema_version = '1.0',
  match_kind     = 'all_of',
  match_perms    = '[{"any_of":[{"api_group":"rbac.authorization.k8s.io","resource":"roles","verb":"bind"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"clusterroles","verb":"bind"}]},
                     {"any_of":[{"api_group":"rbac.authorization.k8s.io","resource":"rolebindings","verb":"create"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"rolebindings","verb":"update"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"rolebindings","verb":"patch"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"clusterrolebindings","verb":"create"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"clusterrolebindings","verb":"update"},
                                 {"api_group":"rbac.authorization.k8s.io","resource":"clusterrolebindings","verb":"patch"}]}]'::jsonb,
  summary_ko     = 'bind과 (cluster)rolebindings 생성/수정을 함께 가지면 임의 Role 자가 바인딩. clusterscope면 cluster-admin, 아니면 namespace-admin.'
WHERE rule_id = 'R-DIRECT-02';

-- R-DIRECT-03: impersonate 대상별 분기 + uids 제거.
UPDATE rbac_rule_catalog SET
  schema_version = '1.0',
  match_perms    = '[{"api_group":"","resource":"users","verb":"impersonate"},
                     {"api_group":"","resource":"groups","verb":"impersonate","resource_names":["system:masters"]},
                     {"api_group":"","resource":"serviceaccounts","verb":"impersonate"}]'::jsonb,
  summary_ko     = 'impersonate: groups(system:masters)→cluster-admin, serviceaccounts→대상 SA 권한 흡수, users→신원 흡수(데이터 의존). uids 제거.'
WHERE rule_id = 'R-DIRECT-03';

-- R-INDIRECT-07: CSR 승인 체인 4요소화 (create + get 추가).
UPDATE rbac_rule_catalog SET
  title       = 'csr create+get AND csr/approval (update|patch) AND signers/kube-apiserver-client approve -> cluster-admin 인증서 발급',
  match_perms = '[{"api_group":"certificates.k8s.io","resource":"certificatesigningrequests","verb":"create"},
                  {"api_group":"certificates.k8s.io","resource":"certificatesigningrequests","verb":"get"},
                  {"any_of":[{"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"update"},
                              {"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"patch"}]},
                  {"api_group":"certificates.k8s.io","resource":"signers","verb":"approve","resource_names":["kubernetes.io/kube-apiserver-client"]}]'::jsonb,
  summary_ko  = 'CSR 생성·회수·승인·서명자승인 4요소를 모두 가지면 system:masters 인증서 발급으로 cluster-admin.'
WHERE rule_id = 'R-INDIRECT-07';

-- R-INDIRECT-09: apiservices unwire.
UPDATE rbac_rule_catalog SET
  engine_status    = 'unwired',
  transition_group = NULL,
  summary_ko       = '[unwired] APIService 가로채기는 신원헤더 기반이라 직접 cluster-admin 경로가 약함. 카탈로그 보존, 엔진 미구동.'
WHERE rule_id = 'R-INDIRECT-09';

-- R-INDIRECT-18: VAP unwire + delete/deletecollection verb 추가.
UPDATE rbac_rule_catalog SET
  engine_status    = 'unwired',
  transition_group = NULL,
  match_perms      = '[{"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"create"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"update"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"patch"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"delete"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"deletecollection"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"create"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"update"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"patch"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"delete"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"deletecollection"}]'::jsonb,
  summary_ko       = '[unwired] VAP는 검증 전용(mutate 불가) → admission 가드레일 약화일 뿐 직접 cluster-admin 아님. delete=가드레일 제거 벡터.'
WHERE rule_id = 'R-INDIRECT-18';
