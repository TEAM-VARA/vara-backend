# ISMS-P 룰 픽스처 JSON

`go test` 골든 테스트(`internal/service.TestRuleFixturesGolden`)가 이 디렉터리를 사용합니다.

## 환경 변수

| 변수 | 설명 |
|------|------|
| `RULE_FIXTURE_DIR` | 픽스처 디렉터리 절대/상대 경로. 미설정 시 저장소 루트의 이 폴더를 사용합니다. |
| `RULE_FIXTURE_ALL` | `1`이면 디렉터리 내 **모든** `*.json`에 대해 검증합니다. 기본은 승인된 룰 ID만 검사합니다(아래 목록). |

## 구조화 룰 + 정규화

아래 룰은 `rulesets/*.json`의 `structured_match`와 픽스처 `data`가 맞도록 `NormalizeRuleFixtureEvidence`로 파생 필드를 채웁니다.

- `R-2.2.1-07` — EKS audit / retention / dashboard
- `R-2.2.5-03`, `R-2.2.5-05` — 퇴직·직무변경 감사
- `R-1.3.1-02` — ArgoCD Synced+Healthy
- `R-2.2.6-04` — 위반 증거 채널·타임라인
- `R-1.2.1-02` — 자산 인벤토리 diff
- `R-1.1.4-11`, `R-1.1.4-12` — eBPF DNS Shadow IT, Kyverno 태깅

나머지 룰을 골든에 포함하려면 동일 패턴으로 정규화 함수와 룰셋 필드를 추가한 뒤 `goldenApprovedFixtures`에 ID를 넣거나 `RULE_FIXTURE_ALL=1`로 전체 실행 후 실패를 줄여 나가면 됩니다.

## 테스트에서 단일 룰 평가

HTTP 엔드포인트는 없습니다. `go test ./internal/service/...`에서 `EvaluateRuleWithEvidence`를 호출합니다(예: `TestRuleFixturesGolden`).
