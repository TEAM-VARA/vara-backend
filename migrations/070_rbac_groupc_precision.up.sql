-- ============================================================================
-- 057: 그룹 C 정밀화 동기화 (semantics.go/R-INDIRECT-02.yaml 2026-06 패치)
-- ============================================================================
-- 엔진 변경:
--   - makePodInstanceTransition(02·03 공유)이 triggeringPerm.ResourceName 으로 대상 Pod 를
--     좁혀 흡수(resourceNames 좁힘 시 그 Pod 만). 전이 레벨이라 match_perms 와 무관.
--   - R-INDIRECT-02.yaml 에서 pods/portforward 트리플 제거(토큰 직접 탈취 벡터 아님).
-- 카탈로그(참조 데이터)는 02 의 match_perms(portforward 제거)만 반영 + summary 보강.
-- ============================================================================

UPDATE rbac_rule_catalog SET
  title       = 'create/get on pods/exec|attach -> 실행 중 Pod 컨테이너에서 그 Pod SA 토큰 획득',
  match_perms = '[{"api_group":"","resource":"pods/exec","verb":"create"},
                  {"api_group":"","resource":"pods/exec","verb":"get"},
                  {"api_group":"","resource":"pods/attach","verb":"create"},
                  {"api_group":"","resource":"pods/attach","verb":"get"}]'::jsonb,
  summary_ko  = '실행 중 Pod에 exec/attach로 들어가 그 Pod SA 토큰 탈취. resourceNames로 좁히면 그 Pod만 흡수(엔진). portforward는 토큰 직접 탈취가 아니라 제외.'
WHERE rule_id = 'R-INDIRECT-02';

-- R-INDIRECT-03: match_perms 불변(ephemeralcontainers update/patch). resourceName-narrow 는
-- 전이 레벨이라 카탈로그 영향 없음. summary 만 보강.
UPDATE rbac_rule_catalog SET
  summary_ko = '실행 중 Pod에 ephemeral container를 주입해 그 Pod SA 토큰 탈취. resourceNames로 좁히면 그 Pod만 흡수(엔진).'
WHERE rule_id = 'R-INDIRECT-03';
