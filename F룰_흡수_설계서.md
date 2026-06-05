# F-rule 흡수 / F 레이어 폐지 — 설계서 (Claude Code 핸드오프용)

> 목적: `F-` 룰 타입(extraction_method=`manual`)을 폐지하고, F가 들고 있던 수동점검 메타데이터를 짝 R룰의 출력으로 흡수한다. 결과 레이어를 **R(실측) · GL(정책) · 리포트** 3개로 단순화한다.
> 작성 시점 상태: **Stage 1(JSON 룰셋 변환) 적용·검증 완료**, **Stage 2(Go 엔진) 미적용**.
> 이 문서는 빌드 가능한 환경의 Claude Code가 Stage 2를 구현하고 전체를 검증하기 위한 명세다.

---

## 0. ⚠️ 선행 필수 — 작업트리 손상 복구

현재 작업트리(working tree)는 광범위하게 손상돼 있다. 이전 세션이 파일들을 **CRLF로 재저장하다 꼬리가 잘린(truncated)** 상태로 보인다.

- 수정된 추적 파일 264개 중 .go 182개.
  - 167개: **CRLF만** 바뀜 (내용은 HEAD와 글자까지 동일 → 무해, 선택적 정규화)
  - **15개: 잘림 (truncated)** — HEAD의 앞부분만 남고 끝부분 소실 → **컴파일 불가**
- 룰셋 JSON 18개도 동일하게 손상됐었고, 이미 HEAD에서 복구 후 Stage 1을 적용함.

**증거:** `grc.VerdictMET / VerdictNOT_MET / VerdictNEEDS_REVIEW / LayerR / LayerF / LayerGL` 상수가 `internal/domain/grc/models.go` 끝(HEAD 470~483줄)에 정의돼 있는데, 작업트리 models.go는 그 블록이 통째로 잘려 나가 미선언 상태 → 빌드 깨짐.

### 복구 대상 (HEAD에서 되돌릴 것)

```
internal/domain/grc/models.go                       (-2751B)
internal/service/grc_service.go                     (-7621B)
internal/service/pod_graph_evaluator.go             (-3438B)
internal/service/grc_ruleset.go                     (-241B)
internal/service/finding_evaluator.go               (-697B)
internal/service/grc_rule_evaluate.go               (-227B)
internal/service/grc_embedding_eval.go              (-453B)
internal/service/grc_llm_eval.go                    (-1254B)
internal/repository/postgres/grc_repo.go            (-4010B)
internal/repository/postgres/edges_repo.go          (-957B)
internal/repository/postgres/cluster_reader_repo.go (-620B, tail 잘림)
internal/handler/grc_handler.go                     (-265B)
internal/server/router.go                           (-177B)
internal/server/server.go                           (-80B)
internal/domain/agent/cluster_reader.go             (-55B)
```

```bash
# 빌드 가능한 로컬(=git lock 정상)에서:
git checkout HEAD -- \
  internal/domain/grc/models.go \
  internal/service/grc_service.go \
  internal/service/pod_graph_evaluator.go \
  internal/service/grc_ruleset.go \
  internal/service/finding_evaluator.go \
  internal/service/grc_rule_evaluate.go \
  internal/service/grc_embedding_eval.go \
  internal/service/grc_llm_eval.go \
  internal/repository/postgres/grc_repo.go \
  internal/repository/postgres/edges_repo.go \
  internal/repository/postgres/cluster_reader_repo.go \
  internal/handler/grc_handler.go \
  internal/server/router.go \
  internal/server/server.go \
  internal/domain/agent/cluster_reader.go

# (선택) CRLF-only 167개 노이즈 정규화는 .gitattributes(* text=auto eol=lf) + renormalize 권장
go build ./...   # 복구 후 클린 빌드 확인 — 이게 Stage 2의 baseline
```

> ⚠️ 검증 메모: 위 손상 분석은 "working == HEAD 앞부분 prefix"로 판정한 것. cluster_reader_repo.go는 diff상 마지막 줄 처리 때문에 "other"로 분류됐으나 실제로는 tail 잘림. 복구 전 `git diff --stat HEAD`로 재확인할 것.

---

## 1. 설계 결정 요약

- **F는 별도 rule type일 이유가 없다.** F가 들고 있던 값(`manual_check_areas`, `additional_review_items`, `alternative_controls`, `kisa_defect_case_refs`, `compliance_mappings`, `offcluster_satisfaction_conditions`)은 룰이 아니라 **R룰 판정 결과에 딸린 출력 메타데이터**다. `grc_rule_results` 스키마에 이 컬럼들이 이미 존재한다(아래 §5).
- **verdict_type도 별도 type을 정당화 못 한다:**
  - `potential_finding` = R의 FAIL + 사람이 볼 맥락
  - `needs_review` = 3-state의 확인불가(합격률 분모 제외)
  - `compliant_indicator` / `additional_evidence` = verdict가 아니라 방증/리포트 출력
- **COV(`automation_coverage`)는 흡수하지 않는다.** 도구 자기평가 메타스탯이지 "외부 확인 내용"이 아님.
- **KDC(`kisa_defect_case_refs`)는 유지한다.** ARI/MCA에 섞지 않고 전용 컬럼으로. 결함사례 추적 태그라 성격이 다르고, 컬럼이 이미 있어 비용 0.

---

## 2. 27개 F룰 처리 분류

| 처리 | 개수 | 방법 |
|---|---|---|
| **R에 흡수** | 19 | 짝 R룰 결과에 `manual_check_output`(ARI/MCA/AC/KDC 등) 부착. F룰 삭제 |
| **R로 승격** | 2 | 자동화 가능한데 F에 묻힘(orphan SA, CVE). 신규 R룰화 |
| **리포트 재분류** | 4 | verdict 없는 인벤토리/방증 출력. 합격/불합격 없음 |
| **deferred R 보관** | 2 | 행위관측(eBPF), 데이터 미수집. `deferred=true` R룰 |

### 2-1. 흡수 매핑 (19개 F → 짝 R)

범례: ARI=additional_review_items · MCA=manual_check_areas · AC=alternative_controls · KDC=kisa_defect_case_refs · `applies_when`=출력 노출 조건

| F룰 | → 짝 R룰 | applies_when | 외부 확인 내용(흡수 필드) | scope 주의 |
|---|---|---|---|---|
| F-2.1.3-01 | R-2.1.3-01 | always | ARI, MCA, AC(외부CMDB/ITSM) | |
| F-2.5.1-01 | R-2.5.1-01 | fail | ARI, MCA, KDC(공용계정), exception_ns | |
| F-2.5.2-01 | R-2.5.2-01 | fail | ARI, KDC | |
| F-2.5.2-02 | R-2.5.2-02 | fail | ARI | |
| F-2.5.5-01 | R-2.5.5-01 | fail | MCA(특수권한 결재기록) | |
| F-2.5.5-02 | R-2.5.5-02 | fail | MCA(RBAC정책/결재) | |
| F-2.6.1-01 | R-2.6.1-02 | always | ARI, MCA(망분리설계), AC(VPC/Istio/Calico/별도클러스터), KDC | ★ cluster-level 관측 |
| F-2.6.1-02 | R-2.6.1-03 | always | ARI, MCA(CNI설정), AC | |
| F-2.6.1-03 | R-2.6.1-04 | always | ARI, MCA, AC | ★ ns쌍(cluster-level) |
| F-2.6.7-01 | R-2.6.7-01 | always | ARI, MCA(화이트리스트/프록시), AC(NAT/Squid/Cilium FQDN/NetFW), KDC | |
| F-2.7.1-01 | R-2.7.1-03 | fail | ARI, MCA, AC, KDC | |
| F-2.8.3-01 | R-2.8.3-01 | always | ARI, MCA, AC(별도클러스터/VPC/ns네이밍) | |
| F-2.8.3-02 | R-2.8.3-02 | fail | ARI, KDC | ★ namespace(cluster-level) |
| F-2.10.3-03 | R-2.10.3-03 | always | ARI, MCA(NodePort정책), AC(VPC SG/Network ACL) | ★ Service(cluster-level) |
| F-2.10.5-01 | R-2.10.5-01 | fail | ARI, MCA(송수신목록/흐름도), KDC | |
| F-2.10.5-02 | R-2.10.5-03 | fail | ARI, MCA, KDC | |
| F-2.10.8-01 | R-2.10.8-01 | fail | ARI, KDC(EOL) | |
| F-2.10.8-02 | R-2.10.8-02 | fail | ARI, MCA(태그정책/CICD) | |
| F-2.10.8-03 | R-2.10.8-03 | fail | ARI, MCA(무결성/서명) | |

> `applies_when` = `potential_finding` → **fail**(R이 미준수일 때만 노출), `needs_review`/`additional_evidence` → **always**(항상 노출).
> ★ **scope 주의 4건**(F-2.6.1-01, F-2.6.1-03, F-2.8.3-02, F-2.10.3-03): 짝 R은 per-Pod verdict인데 F 관측은 cluster/namespace 단위. verdict(Pod 단위)와 **별도로** 항목 레벨 부속관측으로 내보내고, **합격률 분모엔 넣지 않는다.**

### 2-2. R 승격 (2개)

| F룰 | → 신규 R룰 | operator | 자동화 근거 |
|---|---|---|---|
| F-2.5.1-02 | R-2.5.1-04 | `orphan_serviceaccount` | orphan SA = SA − bindings 로 계산 가능 |
| F-2.10.8-04 | R-2.10.8-04 | `cve_vulnerability_check` | `cluster_pods.image_digest ⋈ cves` 테이블 이미 존재 |

### 2-3. 리포트 재분류 (4개) — verdict 없음, 합격률 제외

| F룰 | → R룰 | operator |
|---|---|---|
| F-1.2.1-01 | R-1.2.1-02 | `inventory_report` (클러스터 자산 인벤토리) |
| F-1.2.2-01 | R-1.2.2-03 | `traffic_graph_report` (통신 관계) |
| F-1.2.2-02 | R-1.2.2-04 | `external_dependency_report` (외부 의존성) |
| F-2.1.3-02 | R-2.1.3-03 | `change_activity_report` (변경 활동) |

### 2-4. deferred R 보관 (2개) — eBPF 파이프라인 연동 후 활성

| F룰 | → R룰 | operator | deferred_reason |
|---|---|---|---|
| F-2.6.7-02 | R-2.6.7-02 | `external_domain_traffic_report` | 외부 도메인 트래픽. eBPF/DNS 로그 파이프라인 연동 후 활성 |
| F-2.11.3-01 | R-2.11.3-02 | `prod_shell_exec_detection` | 운영 shell exec. eBPF(Falco/Tetragon) 연동 후 활성 |

---

## 3. `manual_check_output` 스키마 (JSON, R룰에 부착)

흡수된 R룰에 추가되는 객체. **F의 `manual_meta`를 그대로 쓰지 않는다** — `manual_meta`를 R룰에 붙이면 `IsManual()`/조건평가가 오작동할 수 있으므로 별도 필드로 분리한다.

```jsonc
"manual_check_output": {
  "applies_when": "fail" | "always",       // 출력 노출 조건
  "absorbed_from": "F-2.10.8-01",           // 추적용
  "additional_review_items": [ "..." ],     // ARI
  "manual_check_areas": [ "..." ],          // MCA
  "alternative_controls": [ "..." ],        // AC (없으면 생략)
  "kisa_defect_case_refs": [ {"case_number": null, "description": "...", "match": "direct"} ],
  "compliance_mappings": [ {"framework": "ISMS-P", "item": "2.10.8", "match_strength": "direct"} ],
  "offcluster_satisfaction_conditions": [ "..." ],
  "exception_namespaces": [ "kube-system", ... ]   // F-2.5.1-01 한정
}
// 주: automation_coverage(COV)는 흡수하지 않음
```

---

## 4. Stage 1 — JSON 룰셋 변환 (✅ 적용·검증 완료)

`rulesets/isms_p_*.json` 18개에 다음을 적용했다.

- 흡수 19: 짝 R룰에 `manual_check_output` 부착(F의 실제 ARI/MCA/AC/KDC/compliance_mappings/offcluster/exception_ns를 그대로 이전, COV 드롭), 해당 F룰 **삭제**.
- 승격 2 / 리포트 4 / deferred 2: `rule_id`를 신규 R-id로 **개명**, 출처 플래그(`promoted_from`/`reclassified_from`/`deferred_from`) 추가, deferred는 `manual_meta.deferred=true`+`deferred_reason`, 리포트는 `output_type:"report"`. operator/`manual_meta`는 보존(아직 manual 평가기로 실행되게).

**검증 결과:**
- 18개 전부 JSON 파싱 OK
- 잔존 `F-` 룰: **0**
- `manual_check_output` 부착: **27**
- 중복 rule_id: 없음
- 기대 신규/타깃 id 전부 존재

**재현 스크립트:** `scripts/transform_f_absorption.py` (이 설계서와 함께 제공). 멱등(idempotent)하지 않으니 **HEAD 복구 후 1회만** 실행하거나, 현재 적용본을 그대로 검증만 할 것.

> ⚠️ Claude Code 주의: Stage 1은 **이미 적용됨**. 다시 돌리지 말고 위 검증 4항목으로 상태만 확인. (rulesets는 HEAD에서 복구된 깨끗한 상태 위에 변환됨 → §0 복구 대상에 rulesets 미포함.)

---

## 5. `grc_rule_results` 출력 컬럼 (기존, 변경 없음)

`internal/repository/postgres/grc_repo.go` INSERT가 이미 아래 컬럼을 씀 → R룰 결과도 채우기만 하면 됨:

```
judgment_mode, verdict_type, matched, observation, evidence_json,
affected_resources, manual_check_areas, additional_review_items,
automation_coverage, alternative_controls, compliance_mappings,
kisa_defect_case_refs, ...
```

`grc.RuleResult`(`internal/domain/grc/models.go`)에도 대응 필드가 전부 존재:
`ManualCheckAreas, AdditionalReviewItems, AlternativeControls, ComplianceMappings, KisaDefectCaseRefs, OffclusterSatisfactionConditions, VerdictType, Layer, Matched, Deferred, DeferredReason`.

---

## 6. Stage 2 — Go 엔진 변경 명세 (미적용, Claude Code가 구현)

현재 디스패치: `Rule.IsManual()` = `extraction_method=="manual"` → `EvaluateManualRules`(`finding_evaluator.go`), 그 외 → R 경로(`pod_graph_evaluator.go`). 두 결과는 `GRCService.EvaluateClusterCompliance`(`grc_service.go`)에서 item 단위로 병합됨.

### 6-1. `Rule`에 `ManualCheckOutput` 추가 — `internal/service/grc_ruleset.go`

```go
// ManualCheckOutput: R룰 결과에 딸려 나가는 수동점검 출력(흡수된 F 메타데이터).
type ManualCheckOutput struct {
    AppliesWhen                      string          `json:"applies_when,omitempty"` // "fail" | "always"
    AbsorbedFrom                     string          `json:"absorbed_from,omitempty"`
    AdditionalReviewItems            []string        `json:"additional_review_items,omitempty"`
    ManualCheckAreas                 []string        `json:"manual_check_areas,omitempty"`
    AlternativeControls              []string        `json:"alternative_controls,omitempty"`
    KisaDefectCaseRefs               json.RawMessage `json:"kisa_defect_case_refs,omitempty"`
    ComplianceMappings               json.RawMessage `json:"compliance_mappings,omitempty"`
    OffclusterSatisfactionConditions []string        `json:"offcluster_satisfaction_conditions,omitempty"`
    ExceptionNamespaces              []string        `json:"exception_namespaces,omitempty"`
}

// Rule struct에 필드 추가:
//   ManualCheckOutput *ManualCheckOutput `json:"manual_check_output,omitempty"`
//
// 신규 분류 플래그(개명된 룰):
//   PromotedFrom     string `json:"promoted_from,omitempty"`
//   ReclassifiedFrom string `json:"reclassified_from,omitempty"`
//   DeferredFrom     string `json:"deferred_from,omitempty"`
//   OutputType       string `json:"output_type,omitempty"` // "report"
```

### 6-2. R 경로 결과에 흡수 필드 주입 — `grc_service.go : EvaluateClusterCompliance`

R룰 루프에서 `PodRuleResult`(`rr`) → `grc.RuleResult`(`grr`) 변환 직후, 룰 정의를 찾아 `manual_check_output`을 주입한다.

```go
// 루프 진입 전 1회: 룰 정의 맵
ruleDef := map[string]*Rule{}
for _, rs := range s.rulesetStore.LoadAll() {
    for i := range rs.Rules { ruleDef[rs.Rules[i].RuleID] = &rs.Rules[i] }
}

// grr 빌드 후, append 전:
if def, ok := ruleDef[rr.RuleID]; ok {
    enrichManualOutput(&grr, def)
}

// helper (finding_evaluator.go의 toRawJSON 재사용)
func enrichManualOutput(grr *grc.RuleResult, def *Rule) {
    mco := def.ManualCheckOutput
    if mco == nil { return }
    isFail := grr.Verdict == grc.VerdictNOT_MET || grr.Verdict == "미준수"
    if mco.AppliesWhen == "fail" && !isFail { return } // fail형은 미준수일 때만 노출
    if len(mco.AdditionalReviewItems) > 0 { grr.AdditionalReviewItems = toRawJSON(mco.AdditionalReviewItems) }
    if len(mco.ManualCheckAreas) > 0     { grr.ManualCheckAreas      = toRawJSON(mco.ManualCheckAreas) }
    if len(mco.AlternativeControls) > 0  { grr.AlternativeControls   = toRawJSON(mco.AlternativeControls) }
    if len(mco.OffclusterSatisfactionConditions) > 0 { grr.OffclusterSatisfactionConditions = toRawJSON(mco.OffclusterSatisfactionConditions) }
    if len(mco.KisaDefectCaseRefs) > 0   { grr.KisaDefectCaseRefs    = mco.KisaDefectCaseRefs }
    if len(mco.ComplianceMappings) > 0   { grr.ComplianceMappings    = mco.ComplianceMappings }
    // exception_namespaces: 평가 로직에서 이미 예외 처리되면 출력은 참고용으로만.
}
```

> 다른 진입점도 동일 주입 필요: `EvaluateClusterFindings`/`EvaluateCluster`(같은 파일) 등 R 결과를 만드는 모든 경로. 공통 helper로 한곳에서 적용 권장.

### 6-3. 승격 2건 (orphan SA, CVE) — **완전 이식 (결정됨)**

operator 2개를 **R 평가 경로로 완전 이식**한다. manual 평가기 재사용(임시)이 아니라, R로 정식 통합.

1. **JSON**: R-2.5.1-04 / R-2.10.8-04 의 `extraction_method`를 `"manual"` → `"api"`로 변경(→ `IsManual()=false` → R 경로로 디스패치). `verdict_type`는 제거하고 R룰 표준 형태(`compliance_indicators` + `judgment_logic`)로 정규화하거나, operator 전용 R 평가 분기를 둔다.
2. **operator 이식**: `finding_evaluator.go`의 `evalOrphanServiceAccount`, `evalCVEVulnerabilityCheck` 로직을 R 평가 경로(cluster-level R 평가기)로 옮긴다.
   - orphan SA: `SA − (RoleBinding/ClusterRoleBinding subjects)` 차집합. 결과는 cluster-level R룰(per-SA 위반자산).
   - CVE: `cluster_pods.image_digest ⋈ cves`. Critical/High → 미충족.
   - 이 둘은 per-Pod가 아니라 cluster/SA 단위이므로, R 경로에 **cluster-level R 평가 분기**가 없으면 신설(`EvaluateClusterCompliance` 안에서 pod 루프와 별개로 cluster R룰을 1회 평가).
3. **분류/집계**: 결과 `Layer = grc.LayerR`, **합격률 분모 포함**(미충족이면 위반).
4. **manual 평가기에서 제거**: 이식 후 `finding_evaluator.go`의 두 operator 분기 및 dispatch는 dead-path가 되므로 정리(또는 deferred/리포트 외 manual 룰이 없으면 manual 평가기 자체를 축소).
5. `manual_check_output`(ARI/MCA/KDC)은 R 결과에 §6-2 helper로 동일하게 부착(applies_when="fail").

### 6-4. 리포트 4건 — **새 '리포트' 그룹으로 분리 (결정됨)**

verdict가 없는 인벤토리/방증 출력. **F 레이어 대신 리포트로 분리**한다.

- `output_type:"report"` 플래그로 식별. 이미 `finding_evaluator.go`의 `reportOperators`가 verdict=MET(정보제공)로 처리하니 로직은 유지하되,
- **레이어/그룹 표기**: `grc`에 신규 상수 `LayerReport = "REPORT"`(또는 결과 그룹핑 키)를 추가하고 이 4룰 결과의 `Layer`를 그것으로 세팅.
- **합격률 분모 제외** 보장(충족/미충족/확인불가 어디에도 안 들어감 → 별도 "리포트" 섹션으로만 노출).

### 6-5. deferred 2건 — **R 레이어 + 보류 (결정됨)**

- `Layer = grc.LayerR`, `manual_meta.deferred=true` → 기존 코드가 `verdict="skipped"` 처리 → **합격률 분모 제외**, UI엔 "보류"로 표시.
- eBPF/DNS·shell 파이프라인 연동되면 `deferred=false`로 전환 → 그때부터 정식 R룰로 분모 포함.

### 6-6. verdict / 합격률 정책 (★ 결정 반영)

R룰 결과 구조:
```
verdict (충족/미충족/확인불가)            ← 합격률 분모(충족·미충족만)
+ manual_check_output(ARI/MCA/AC)         ← applies_when 규칙대로 노출
```

흡수 룰 **출신별 정책** (origin = `manual_check_output.absorbed_from`의 verdict_type):

| 출신 | 개수 | applies_when | 합격률 처리 |
|---|---|---|---|
| potential_finding | 12 | fail | R verdict 그대로, **분모 포함**. 미충족이면 manual 노출 |
| needs_review | 5 | always | **'확인불가'로 분리 · 분모 제외**(R 미충족이어도 위양성 방지). R 측정은 참고 표시, manual 항상 노출 |
| additional_evidence | 2 | always | verdict 없이 **방증만 출력**, 분모 무관 |

> needs_review(5): F-2.6.1-01→R-2.6.1-02, F-2.6.1-02→R-2.6.1-03, F-2.6.1-03→R-2.6.1-04, F-2.6.7-01→R-2.6.7-01, F-2.10.3-03→R-2.10.3-03.
> additional_evidence(2): F-2.1.3-01→R-2.1.3-01, F-2.8.3-01→R-2.8.3-01.
> 구현: needs_review 출신은 enrich 시 `grr.Verdict`를 `VerdictNEEDS_REVIEW`로 세팅(또는 합격률 집계에서 `absorbed_from`이 needs_review면 분모 제외 처리). 둘 중 집계 단계 제외가 더 안전.
>
> **scope 주의 4건**(F-2.6.1-01, F-2.6.1-03, F-2.8.3-02, F-2.10.3-03): per-Pod R verdict는 그대로 산출하되, cluster/namespace 부속관측은 항목 레벨에 **별도 부착 + 분모 제외**.
> 합격률 분모 = R 충족/미충족만. 확인불가·리포트·deferred·방증 제외.

---

## 7. 검증 계획 (Claude Code)

1. `git checkout HEAD -- <§0 15개 파일>` 후 `go build ./...` → **baseline 그린** 확인.
2. Stage 2 코드 적용 → `go build ./...`.
3. `go vet ./internal/service/...`.
4. 단위테스트: `go test ./internal/service/... ./internal/domain/grc/...` (기존 `grc_evidence_test.go` 등 회귀 확인).
5. 룰셋 검증(이미 통과, 재확인): `python3 - <<'PY' ...` 로 18개 파싱 + F-룰 0 + manual_check_output 27 + 중복 id 없음.
6. 통합(가능 시): 스냅샷 있는 클러스터로 `EvaluateClusterCompliance` 호출 → R룰 결과에 `manual_check_output` 필드가 `applies_when` 규칙대로 채워지는지, 합격률 분모에 확인불가/리포트/deferred가 빠지는지 확인.
7. `test_all_endpoints.sh` 회귀.

---

## 8. 결정사항 (확정)

1. **승격 operator** → **완전 이식** (§6-3). manual 평가기 재사용 아님. 두 operator를 R 경로로 옮기고, JSON `extraction_method`를 `api`로, 분모 포함.
2. **확인불가 verdict** → **출신별 정책** (§6-6). potential_finding(12)=분모 포함 / needs_review(5)=확인불가·분모 제외 / additional_evidence(2)=방증만. R 측정값은 살리되 needs_review 출신은 집계 단계에서 분모 제외.
3. **CRLF-only 167개** → **정규화** (§0). `.gitattributes`(`* text=auto`, `*.go eol=lf` 등) 추가 완료. 손상 파일 복구 후 `git add --renormalize . && git commit`으로 일괄 정리.
4. **리포트/deferred 레이어** → 리포트는 **신규 `LayerReport`(REPORT) 그룹**으로 분리(분모 제외), deferred는 **`LayerR` + `deferred=true` 보류**(분모 제외). 최종 레이어: **R / GL / REPORT** (+ deferred는 R의 보류 상태). F 상수 제거.

---

## 부록 A. 처리 대상 27 F룰 전체 목록

흡수(19): F-2.1.3-01, F-2.5.1-01, F-2.5.2-01, F-2.5.2-02, F-2.5.5-01, F-2.5.5-02, F-2.6.1-01, F-2.6.1-02, F-2.6.1-03, F-2.6.7-01, F-2.7.1-01, F-2.8.3-01, F-2.8.3-02, F-2.10.3-03, F-2.10.5-01, F-2.10.5-02, F-2.10.8-01, F-2.10.8-02, F-2.10.8-03
승격(2): F-2.5.1-02, F-2.10.8-04
리포트(4): F-1.2.1-01, F-1.2.2-01, F-1.2.2-02, F-2.1.3-02
deferred(2): F-2.6.7-02, F-2.11.3-01
