package service

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/domain/scoring"
)

// ─────────────────────────────────────────────────────────────
// ISMS-P 미준수 → Risk 가산
//
// 정책(확정):
//   - FinalScore는 "높을수록 위험"이므로 미준수는 점수를 *더한다*(가산).
//   - severity(상/중/하)는 실제 보안 도구(Kubescape baseScore / AWS Security Hub /
//     Trivy CVSS / Kyverno)에서 도출한 것만 사용. 자체룰·best-practice(도구 severity
//     없음)와 etcd(R-2.7.1-01, 확인불가-prone)는 제외 → 21개 룰.
//   - 가중치: 상 3 / 중 2 / 하 1.
//   - "미준수(NOT_MET)"에만 가산. 준수·해당없음(N/A)·NO_DATA·검토필요는 제외.
//   - rule_id당 1회(같은 룰이 여러 자산에서 걸려도 그 pod엔 1회).
//   - per-pod 점수는 도구 severity를 가진 21개 룰을 모두 반영한다(ismspRiskSeverity).
//   - SG·CloudTrail·KMS 등 계정 스코프 룰도 ProjectInheritedFindings로 pod에 투영해 가산한다.
//
// 기존 스코어링 로직(ComputeFinalScore/classifyLevel/roundTo2 등)은 수정하지 않고
// 재사용만 한다. (이 파일은 package service)
// ─────────────────────────────────────────────────────────────

// ismspRiskSeverity: per-pod risk score에 반영하는 룰 — 도구 severity 보유 21개 전부.
// severity 출처: Kubescape baseScore(7-8→상 / 5-6→중) · AWS Security Hub(High~Critical→상 / Medium→중)
//   · Trivy CVSS(HIGH+→상) · Kyverno(medium→중).
var ismspRiskSeverity = map[string]string{
	// 상 (가중치 3) — Kubescape baseScore 7-8 / AWS SecHub High~Critical / Trivy HIGH+
	"R-2.5.5-01": "상", "R-2.5.5-02": "상", "R-2.6.1-01": "상",
	"R-2.7.1-02": "상", "R-2.10.2-08": "상",
	"R-2.10.3-SG01": "상", "R-2.6.6-01": "상", "R-2.6.1-SG01": "상", "R-2.9.4-01": "상",
	"R-2.10.8-04": "상",
	// 중 (가중치 2) — Kubescape baseScore 5-6 / AWS SecHub Medium / Kyverno medium
	"R-2.5.1-01": "중", "R-2.6.3-01": "중",
	"R-2.6.1-02": "중", "R-2.6.1-03": "중", "R-2.6.1-04": "중", "R-2.6.7-01": "중",
	"R-2.7.1-04": "중",
	"R-2.11.3-01": "중", "R-2.11.3-02": "중",
	"R-2.10.8-02": "중", "R-2.10.8-03": "중",
}

func ismspSeverityWeight(sev string) float64 {
	switch sev {
	case "상":
		return 3
	case "중":
		return 2
	case "하":
		return 1
	default:
		return 0
	}
}

// ISMSPRiskRuleHit: 가산에 기여한 개별 룰.
type ISMSPRiskRuleHit struct {
	RuleID    string  `json:"rule_id"`
	Severity  string  `json:"severity"`  // 상/중/하
	Weight    float64 `json:"weight"`    // 3/2/1
	Inherited bool    `json:"inherited"` // 클러스터/계정 공통 결함(상속)
}

// ISMSPRiskBreakdown: FinalScore에 더할 ISMS-P 위험 가산 내역.
type ISMSPRiskBreakdown struct {
	Addend      float64            `json:"addend"`       // FinalScore에 더할 합(상3+중2+하1)
	CountHigh   int                `json:"count_high"`   // 상 건수
	CountMedium int                `json:"count_medium"` // 중 건수
	CountLow    int                `json:"count_low"`    // 하 건수
	Rules       []ISMSPRiskRuleHit `json:"rules"`        // 가산된 룰 목록
}

// normalizeISMSPRuleID: -POD- 변형(R-2.5.5-POD-01)을 표준 rule_id(R-2.5.5-01)로.
func normalizeISMSPRuleID(id string) string {
	return strings.Replace(id, "-POD-", "-", 1)
}

// accumulateISMSPRisk: 미준수 + severity맵 보유 + rule_id당 1회일 때만 가산한다.
func accumulateISMSPRisk(b *ISMSPRiskBreakdown, seen map[string]bool, ruleIDRaw, verdict string, inherited bool) {
	if grc.NormalizeVerdict(verdict) != grc.VerdictNOT_MET {
		return // 미준수에만 가산 (준수/해당없음/NO_DATA/검토필요 제외)
	}
	rid := normalizeISMSPRuleID(ruleIDRaw)
	sev, ok := ismspRiskSeverity[rid]
	if !ok {
		return // 도구 severity 없는 룰(자체·best-practice·etcd 등)은 점수 제외
	}
	if seen[rid] {
		return // rule_id당 1회
	}
	seen[rid] = true
	w := ismspSeverityWeight(sev)
	b.Addend += w
	switch sev {
	case "상":
		b.CountHigh++
	case "중":
		b.CountMedium++
	case "하":
		b.CountLow++
	}
	b.Rules = append(b.Rules, ISMSPRiskRuleHit{RuleID: rid, Severity: sev, Weight: w, Inherited: inherited})
}

// ComputePodISMSPAddend: pod의 ISMS-P 미준수(직접 + 상속)를 3/2/1로 합산한다.
// 결과의 Addend를 FinalScore에 더하면 된다(ApplyISMSPToFinalScore 참고).
// 평가 결과가 없으면 빈 Breakdown(Addend=0)을 반환한다(기존 동작 불변).
func (s *GRCService) ComputePodISMSPAddend(ctx context.Context, companyID, clusterName, namespace, podName string) *ISMSPRiskBreakdown {
	b := &ISMSPRiskBreakdown{Rules: []ISMSPRiskRuleHit{}}
	seen := map[string]bool{}

	// 1) pod-local 평가 결과(직접 결함) — GetPodViolations와 동일 경로
	if evalItem, err := s.repo.GetLatestPodGraphEvalByPod(ctx, companyID, clusterName, namespace, podName); err == nil {
		if _, raw, err2 := s.repo.GetPodGraphEvaluation(ctx, evalItem.ID); err2 == nil {
			var rrs []PodRuleResult
			if json.Unmarshal(raw, &rrs) == nil {
				for _, rr := range rrs {
					accumulateISMSPRisk(b, seen, rr.RuleID, rr.Verdict, false)
				}
			}
		}
	}

	// 2) 계정/클러스터 스코프 결함 투영(상속) — SG·CloudTrail·KMS 등 계정 룰도 pod에 가산한다.
	if inh, err := s.ProjectInheritedFindings(ctx, companyID, clusterName); err == nil {
		for _, rr := range inh {
			accumulateISMSPRisk(b, seen, rr.RuleID, rr.Verdict, true)
		}
	}

	return b
}

// ApplyISMSPToFinalScore: 기존 FinalScore에 ISMS-P 가산을 더하고 RiskLevel을 재분류한다.
// FinalScore는 0~100 스케일이라 100에서 상한 처리한다.
// 기존 classifyLevel/roundTo2(package service)를 재사용하며 코어 로직은 수정하지 않는다.
func ApplyISMSPToFinalScore(result *scoring.Result, addend float64) {
	if addend <= 0 {
		return
	}
	score := result.FinalScore + addend
	if score > 100 {
		score = 100
	}
	result.FinalScore = roundTo2(score)
	result.RiskLevel = classifyLevel(result.FinalScore)
}
