-- ============================================================================
-- 058: 그룹 G/15 정밀화 동기화 (2026-06 패치)
-- ============================================================================
-- 엔진 전이 무수정 — YAML match_all 변경만:
--   R-INDIRECT-19: 제거벡터 완전화(pods update/patch·pods/status·nodes delete) +
--     unschedulable에 nodes/status + 노드-읽기 발판(nodes/proxy|pods create) 게이트 추가.
--     (TransitionRIndirect19는 matchGroup[0]=제거 perm만 읽어 무수정.)
--   R-INDIRECT-15: PV create 단독 → match_all(PV create AND pods create 발판).
--     (makeAllPodsTransition이 match_all 그대로 처리.)
-- ============================================================================

UPDATE rbac_rule_catalog SET
  title       = '(pod 제거) AND (nodes unschedulable) AND (노드-읽기 발판) -> Pod 이주로 co-located SA 토큰 흡수',
  match_perms = '[{"any_of":[{"api_group":"","resource":"pods","verb":"delete"},
                              {"api_group":"","resource":"pods","verb":"deletecollection"},
                              {"api_group":"","resource":"pods/eviction","verb":"create"},
                              {"api_group":"","resource":"pods","verb":"update"},
                              {"api_group":"","resource":"pods","verb":"patch"},
                              {"api_group":"","resource":"pods/status","verb":"update"},
                              {"api_group":"","resource":"pods/status","verb":"patch"},
                              {"api_group":"","resource":"nodes","verb":"delete"},
                              {"api_group":"","resource":"nodes","verb":"update"},
                              {"api_group":"","resource":"nodes","verb":"patch"}]},
                  {"any_of":[{"api_group":"","resource":"nodes","verb":"update"},
                              {"api_group":"","resource":"nodes","verb":"patch"},
                              {"api_group":"","resource":"nodes/status","verb":"update"},
                              {"api_group":"","resource":"nodes/status","verb":"patch"}]},
                  {"any_of":[{"api_group":"","resource":"nodes/proxy","verb":"get"},
                              {"api_group":"","resource":"nodes/proxy","verb":"create"},
                              {"api_group":"","resource":"pods","verb":"create"}]}]'::jsonb,
  summary_ko  = 'Pod 제거+노드 unschedulable+노드-읽기 발판을 모두 가지면 강한 Pod를 발판 노드로 이주시켜 그 SA 토큰 흡수. 발판 게이트로 "이주는 시키나 못 읽는" 경우 제외.'
WHERE rule_id = 'R-INDIRECT-19';

UPDATE rbac_rule_catalog SET
  schema_version = '1.0',
  match_kind     = 'all_of',
  title          = 'create persistentvolumes AND create pods(발판) -> hostPath PV로 노드 파일시스템 마운트, 같은 노드 토큰 탈취',
  match_perms    = '[{"api_group":"","resource":"persistentvolumes","verb":"create"},
                     {"api_group":"","resource":"pods","verb":"create"}]'::jsonb,
  summary_ko     = 'hostPath PV 생성 + 마운트할 Pod 생성(발판)을 함께 가져야 노드 파일시스템→같은 노드 토큰 탈취. PV create 단독은 미완성이라 제외.'
WHERE rule_id = 'R-INDIRECT-15';
