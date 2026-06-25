-- ============================================================================
-- 058 down: 050 카탈로그 원본 값으로 복원
-- ============================================================================

UPDATE rbac_rule_catalog SET
  title       = 'pods에 delete/deletecollection(또는 pods/eviction에 create) 그리고 nodes에 update/patch — 둘 다 필요 → 다른 노드를 Pod 배치 금지로 막고 권한 센 Pod를 쫓아냄. 그 Pod가 공격자 노드로 옮겨와 다시 뜨고, 거기서 토큰 흡수.',
  match_perms = '[{"any_of":[{"api_group":"","resource":"pods","verb":"delete"},
                              {"api_group":"","resource":"pods","verb":"deletecollection"},
                              {"api_group":"","resource":"pods/eviction","verb":"create"}]},
                  {"any_of":[{"api_group":"","resource":"nodes","verb":"update"},
                              {"api_group":"","resource":"nodes","verb":"patch"}]}]'::jsonb,
  summary_ko  = 'Pod 삭제와 노드 조작 권한으로 강한 Pod를 자기 노드로 옮겨 토큰을 흡수.'
WHERE rule_id = 'R-INDIRECT-19';

UPDATE rbac_rule_catalog SET
  schema_version = '0.1',
  match_kind     = 'any_of',
  title          = 'persistentvolumes에 create → 노드의 실제 디스크(예: /)를 그대로 가리키는 저장소(hostPath PV)를 만듦. 그걸 연결한 Pod로 같은 노드에 있는 다른 Pod의 토큰·kubelet 인증서를 읽어 탈취.',
  match_perms    = '[{"api_group":"","resource":"persistentvolumes","verb":"create"}]'::jsonb,
  summary_ko     = 'hostPath 볼륨으로 노드 파일시스템을 마운트해 같은 노드의 토큰을 탈취.'
WHERE rule_id = 'R-INDIRECT-15';
