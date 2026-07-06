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
//     없음)와 etcd(R-2.7.1-01, 확인불가-prone)는 제외 → 18개 룰.
//   - 가중치: 상 3 / 중 2 / 하 1.
//   - "미준수(NOT_MET)"에만 가산. 준수·해당없음(N/A)·NO_DATA·검토필요는 제외.
//   - rule_id당 1회(같은 룰이 여러 자산에서 걸려도 그 pod엔 1회).
//   - per-pod 점수는 도구 severity를 가진 18개 룰을 모두 반영한다(ismspRiskSeverity).
//   - SG·CloudTrail·KMS 등 계정 스코프 룰도 ProjectInheritedFindings로 pod에 투영해 가산한다.
//
// 기존 스코어링 로직(ComputeFinalScore/classifyLevel/roundTo2 등)은 수정하지 않고
// 재사용만 한다. (이 파일은 package service)
// ─────────────────────────────────────────────────────────────

// ismspRiskSeverity: per-pod risk score에 반영하는 룰 — 도구 severity 보유 18개 전부.
// severity 출처: Kubescape baseScore(7-8→상 / 5-6→중) · AWS Security Hub(High~Critical→상 / Medium→중)
//   · Trivy CVSS(HIGH+→상) · Kyverno(medium→중).
var ismspRiskSeverity = map[string]string{
	// 상 (가중치 3) — Kubescape baseScore 7-8 / AWS SecHub High~Critical / Trivy HIGH+
	"R-2.5.5-01": "상", "R-2.5.5-02": "상", "R-2.10.2-01": "상",
	"R-2.10.3-SG01": "상", "R-2.6.6-01": "상", "R-2.6.1-SG01": "상", "R-2.9.4-01": "상",
	"R-2.10.8-04": "상",
	// 중 (가중치 2) — Kubescape baseScore 5-6 / AWS SecHub Medium / Kyverno medium
	"R-2.5.1-01": "중", "R-2.6.3-01": "중",
	"R-2.6.1-02": "중", "R-2.6.1-03": "중", "R-2.6.1-04": "중", "R-2.6.7-01": "중",
	"R-2.7.1-04": "중",
	"R-2.11.3-01": "중",
	"R-2.10.8-02": "중", "R-2.10.8-03": "중",
}

// ismspRuleMeta: 점수에 반영되는 각 룰의 표시용 메타(이름·ISMS-P 항목).
// 위반 룰을 프런트에서 사람이 읽을 수 있게 노출하기 위한 단일 출처다.
// (pod-local 결과엔 PodRuleResult.Name이 있으나, 상속 결함 grc.RuleResult엔
//  이름이 없어 pod-local/상속 표기를 통일하려고 여기서 일괄 제공한다.)
var ismspRuleMeta = map[string]struct{ Name, ItemID, ItemName string }{
	"R-2.5.5-01":    {"ServiceAccount 특수 권한 점검", "2.5.5", "특수 계정 및 권한 관리"},
	"R-2.5.5-02":    {"위험 RBAC verb 조합 점검", "2.5.5", "특수 계정 및 권한 관리"},
	"R-2.10.2-01":   {"호스트 네임스페이스 격리(hostNetwork/PID/IPC) 점검", "2.10.2", "클라우드 보안"},
	"R-2.10.3-SG01": {"Security Group 민감·관리 포트 외부 노출 (공개서버 강화)", "2.10.3", "공개서버 보안"},
	"R-2.6.6-01":    {"Security Group 원격 관리 포트(SSH·RDP) 전체 개방", "2.6.6", "원격접근 통제"},
	"R-2.6.1-SG01":  {"Security Group 인바운드 전체 개방 (영역 분리·비인가 접근)", "2.6.1", "네트워크 접근"},
	"R-2.9.4-01":    {"CloudTrail 감사로그 활성·보호 점검", "2.9.4", "로그 및 접속기록 관리"},
	"R-2.10.8-04":   {"실행 중 이미지 알려진 취약점(CVE) 현황", "2.10.8", "패치관리"},
	"R-2.5.1-01":    {"default ServiceAccount 사용", "2.5.1", "사용자 계정 관리"},
	"R-2.6.3-01":    {"워크로드 생성 권한 최소화 (pods/워크로드 create)", "2.6.3", "응용프로그램 접근"},
	"R-2.6.1-02":    {"NetworkPolicy 적용 점검", "2.6.1", "네트워크 접근"},
	"R-2.6.1-03":    {"CNI NetworkPolicy 강제 지원 점검", "2.6.1", "네트워크 접근"},
	"R-2.6.1-04":    {"cross-namespace 통신 통제 부재", "2.6.1", "네트워크 접근"},
	"R-2.6.7-01":    {"egress NetworkPolicy 미적용", "2.6.7", "인터넷 접속 통제"},
	"R-2.7.1-04":    {"KMS 키 로테이션 및 상태 점검", "2.7.1", "암호정책 적용"},
	"R-2.11.3-01":   {"prod 환경 shell exec 활동", "2.11.3", "이상행위 분석 및 모니터링"},
	"R-2.10.8-02":   {"이미지 태그 mutable", "2.10.8", "패치관리"},
	"R-2.10.8-03":   {"이미지 digest 미고정", "2.10.8", "패치관리"},
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
	Name      string  `json:"name"`      // 사람이 읽는 룰 이름(표시용)
	ItemID    string  `json:"item_id"`   // ISMS-P 항목 번호(예: 2.5.5)
	ItemName  string  `json:"item_name"` // ISMS-P 항목명(예: 특수 계정 및 권한 관리)
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

// ToDomain은 저장·조회용 도메인 사본(scoring.ISMSPRisk)으로 변환한다(nil-safe).
// postgres 레이어는 service를 import하지 않으므로, handler가 저장 직전 이 메서드로
// 도메인 타입으로 변환해 SaveScoring에 넘긴다. json 태그가 동일해 왕복 시 형상이 보존된다.
func (b *ISMSPRiskBreakdown) ToDomain() *scoring.ISMSPRisk {
	if b == nil {
		return nil
	}
	rules := make([]scoring.ISMSPRiskRule, 0, len(b.Rules))
	for _, r := range b.Rules {
		rules = append(rules, scoring.ISMSPRiskRule{
			RuleID:    r.RuleID,
			Name:      r.Name,
			ItemID:    r.ItemID,
			ItemName:  r.ItemName,
			Severity:  r.Severity,
			Weight:    r.Weight,
			Inherited: r.Inherited,
		})
	}
	return &scoring.ISMSPRisk{
		Addend:      b.Addend,
		CountHigh:   b.CountHigh,
		CountMedium: b.CountMedium,
		CountLow:    b.CountLow,
		Rules:       rules,
	}
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
	meta := ismspRuleMeta[rid]
	b.Rules = append(b.Rules, ISMSPRiskRuleHit{
		RuleID: rid, Name: meta.Name, ItemID: meta.ItemID, ItemName: meta.ItemName,
		Severity: sev, Weight: w, Inherited: inherited,
	})
}

// ComputePodISMSPAddend: pod의 ISMS-P 미준수(직접 + 상속)를 3/2/1로 합산한다.
// 결과의 Addend를 FinalScore에 더하면 된다(ApplyISMSPToFinalScore 참고).
// 평가 결과가 없으면 빈 Breakdown(Addend=0)을 반환한다(기존 동작 불변).
func (s *GRCService) ComputePodISMSPAddend(ctx context.Context, companyID, clusterName, namespace, podName string) *ISMSPRiskBreakdown {
	// 계정/클러스터 스코프 결함(상속)을 1회 투영해 위임한다.
	inherited, _ := s.ProjectInheritedFindings(ctx, companyID, clusterName)
	return s.ComputePodISMSPAddendWithInherited(ctx, companyID, clusterName, namespace, podName, inherited)
}

// ComputePodISMSPAddendWithInherited는 미리 1회 투영한 inherited findings를 재사용해
// pod별 가산을 계산한다. 배치(클러스터 전체 재계산)에서 pod마다 ProjectInheritedFindings를
// 반복 조회하지 않으려는 용도다. inherited가 nil/빈 슬라이스면 pod-local 결함만 가산한다.
func (s *GRCService) ComputePodISMSPAddendWithInherited(ctx context.Context, companyID, clusterName, namespace, podName string, inherited []grc.RuleResult) *ISMSPRiskBreakdown {
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
	for _, rr := range inherited {
		accumulateISMSPRisk(b, seen, rr.RuleID, rr.Verdict, true)
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
