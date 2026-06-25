-- ============================================================================
-- 057 down: 050 카탈로그 원본 값으로 복원 (R-INDIRECT-02 portforward 포함 6트리플)
-- ============================================================================

UPDATE rbac_rule_catalog SET
  title       = 'pods/exec·pods/attach·pods/portforward에 create/get → 권한 센 계정으로 돌아가는 Pod에 원격 접속(exec)하거나 포트를 연결해, 그 안의 토큰 파일(/var/run/secrets/...)을 읽어 탈취.',
  match_perms = '[{"api_group":"","resource":"pods/exec","verb":"create"},
                  {"api_group":"","resource":"pods/exec","verb":"get"},
                  {"api_group":"","resource":"pods/attach","verb":"create"},
                  {"api_group":"","resource":"pods/attach","verb":"get"},
                  {"api_group":"","resource":"pods/portforward","verb":"create"},
                  {"api_group":"","resource":"pods/portforward","verb":"get"}]'::jsonb,
  summary_ko  = '실행 중인 Pod에 접속(exec 등)해 그 안의 토큰을 탈취.'
WHERE rule_id = 'R-INDIRECT-02';

UPDATE rbac_rule_catalog SET
  summary_ko = '실행 중 Pod에 디버그 컨테이너를 끼워넣어 토큰을 빼냄.'
WHERE rule_id = 'R-INDIRECT-03';
