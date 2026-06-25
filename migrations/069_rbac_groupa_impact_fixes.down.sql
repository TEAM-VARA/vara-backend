-- ============================================================================
-- 056 down: 050 카탈로그 원본 값으로 복원
-- ============================================================================

UPDATE rbac_rule_catalog SET
  summary_ko = '자기 권한을 스스로 더 높게 부여할 수 있음.'
WHERE rule_id = 'R-DIRECT-01';

UPDATE rbac_rule_catalog SET
  schema_version = '0.1',
  match_kind     = 'any_of',
  match_perms    = '[{"api_group":"rbac.authorization.k8s.io","resource":"roles","verb":"bind"},
                     {"api_group":"rbac.authorization.k8s.io","resource":"clusterroles","verb":"bind"}]'::jsonb,
  summary_ko     = '임의의 권한 묶음을 자기나 남에게 붙일 수 있음.'
WHERE rule_id = 'R-DIRECT-02';

UPDATE rbac_rule_catalog SET
  schema_version = '0.1',
  match_perms    = '[{"api_group":"","resource":"users","verb":"impersonate"},
                     {"api_group":"","resource":"groups","verb":"impersonate"},
                     {"api_group":"","resource":"serviceaccounts","verb":"impersonate"},
                     {"api_group":"authentication.k8s.io","resource":"uids","verb":"impersonate"}]'::jsonb,
  summary_ko     = '다른 계정으로 위장해 그 권한을 그대로 사용.'
WHERE rule_id = 'R-DIRECT-03';

UPDATE rbac_rule_catalog SET
  title       = 'certificatesigningrequests/approval에 update/patch 그리고 signers(kubernetes.io/kube-apiserver-client)에 approve — 둘 다 필요 → 인증서 발급 요청(CSR)을 자기가 올리고 자기가 승인해 최고 관리자 그룹(system:masters) 인증서를 발급받아 cluster-admin 도달.',
  match_perms = '[{"any_of":[{"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"update"},
                              {"api_group":"certificates.k8s.io","resource":"certificatesigningrequests/approval","verb":"patch"}]},
                  {"api_group":"certificates.k8s.io","resource":"signers","verb":"approve","resource_names":["kubernetes.io/kube-apiserver-client"]}]'::jsonb,
  summary_ko  = '인증서 승인 권한으로 관리자급 인증서를 직접 발급해 클러스터 관리자에 도달.'
WHERE rule_id = 'R-INDIRECT-07';

UPDATE rbac_rule_catalog SET
  engine_status    = 'default',
  transition_group = 'A',
  summary_ko       = 'APIService를 조작해 집계 API를 가로채 토큰·응답을 변조.'
WHERE rule_id = 'R-INDIRECT-09';

UPDATE rbac_rule_catalog SET
  engine_status    = 'default',
  transition_group = 'A',
  match_perms      = '[{"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"create"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"update"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicies","verb":"patch"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"create"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"update"},
                       {"api_group":"admissionregistration.k8s.io","resource":"validatingadmissionpolicybindings","verb":"patch"}]'::jsonb,
  summary_ko       = 'Validating Admission Policy를 조작해 보안 검사 규칙을 변조.'
WHERE rule_id = 'R-INDIRECT-18';
