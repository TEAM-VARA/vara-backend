package scoring

import "time"

// ─────────────────────────────────────────
// Toxic Combination (작업 B-4)
// ─────────────────────────────────────────
//
// 단일로는 평범하지만 조합되면 위험이 폭발하는 패턴을 탐지하여
// Final Score에 multiplier를 곱합니다.
//
// 매칭 시:
//   Final = (0.7 × Global + 0.3 × Exposure) × multiplier
//   multiplier ∈ [1.0, 1.5]

// ─────────────────────────────────────────
// 신호 (Pod 단위 boolean/숫자 신호)
// ─────────────────────────────────────────

// ToxicSignals는 한 Pod에 대해 평가된 모든 boolean 신호 모음입니다.
// 각 신호는 다양한 데이터 소스에서 추출됩니다 (exposure_scores, attack_path_scores,
// cve_global_scores, cluster_pods 등).
type ToxicSignals struct {
	// exposure_scores
	ExternallyExposed bool `json:"externally_exposed"`

	// attack_path_scores 기반
	ClusterAdmin    bool `json:"cluster_admin"`     // role_severity = cluster-admin
	SecretAccess    bool `json:"secret_access"`     // secret-access scope
	NoNetworkPolicy bool `json:"no_network_policy"` // network_score = 30

	// cluster_pods.containers 기반
	Privileged       bool `json:"privileged"`         // 컨테이너 중 하나라도 privileged
	HostNetwork      bool `json:"host_network"`       // hostNetwork: true
	NoResourceLimits bool `json:"no_resource_limits"` // resources.limits 없음

	// image_global_scores + cve_global_scores 기반
	HasKEVCVE      bool `json:"has_kev_cve"`     // 매칭된 이미지에 KEV CVE 있음
	HasCriticalCVE bool `json:"has_critical_cve"` // critical_count > 0
	HasHighCVE     bool `json:"has_high_cve"`    // high_count > 0
	HasActiveOrPOC bool `json:"has_active_or_poc"` // KEV 또는 ExploitDB
}

// ─────────────────────────────────────────
// 룰 정의 (코드에 하드코딩)
// ─────────────────────────────────────────
//
// DB의 toxic_rules는 사람이 보기 위한 메타데이터이고,
// 실제 매칭 로직은 여기 코드에 있습니다. (성능, 명확성, 테스트 용이성)

// ToxicRule은 한 토픽 룰 정의입니다.
type ToxicRule struct {
	RuleID      string  `json:"rule_id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`   // Critical/High/Medium
	Multiplier  float64 `json:"multiplier"` // 1.2 ~ 1.5

	// Match는 신호를 보고 매칭 여부를 판단합니다.
	Match func(s ToxicSignals) bool `json:"-"`

	// Reason은 매칭된 신호들을 사람이 읽는 형태로 설명합니다.
	Reason func(s ToxicSignals) string `json:"-"`
}

// AllToxicRules는 모든 토픽 룰 목록입니다.
//
// 순서: severity 높은 순. 매칭은 모든 룰에 대해 평가하고
// 그 중 가장 큰 multiplier를 사용합니다.
var AllToxicRules = []ToxicRule{
	// ── Critical (1.5x) ──
	{
		RuleID: "TOXIC-001", Name: "외부 노출 + 클러스터 최고 권한",
		Description: "외부에서 접근 가능한 Pod이 cluster-admin 권한 → 외부 침입 시 클러스터 전체 장악",
		Severity:    "Critical", Multiplier: 1.5,
		Match:  func(s ToxicSignals) bool { return s.ExternallyExposed && s.ClusterAdmin },
		Reason: func(s ToxicSignals) string { return "externally_exposed=true AND cluster_admin=true" },
	},
	{
		RuleID: "TOXIC-002", Name: "외부 노출 + KEV (실제 악용 중인 CVE)",
		Description: "외부 노출 + 실제 야생에서 악용되고 있는 CVE → 즉시 침해 가능",
		Severity:    "Critical", Multiplier: 1.5,
		Match:  func(s ToxicSignals) bool { return s.ExternallyExposed && s.HasKEVCVE },
		Reason: func(s ToxicSignals) string { return "externally_exposed=true AND has_kev_cve=true" },
	},
	{
		RuleID: "TOXIC-003", Name: "Privileged + HostNetwork + Secret",
		Description: "컨테이너 탈출 + 호스트 네트워크 + 인증정보 → 호스트 침해 → 측면 이동",
		Severity:    "Critical", Multiplier: 1.5,
		Match:  func(s ToxicSignals) bool { return s.Privileged && s.HostNetwork && s.SecretAccess },
		Reason: func(s ToxicSignals) string { return "privileged=true AND host_network=true AND secret_access=true" },
	},

	// ── High (1.3x) ──
	{
		RuleID: "TOXIC-004", Name: "최고 권한 + KEV",
		Description: "cluster-admin + 실제 악용 중인 CVE → 침해 시 영향력 최대",
		Severity:    "High", Multiplier: 1.3,
		Match:  func(s ToxicSignals) bool { return s.ClusterAdmin && s.HasKEVCVE },
		Reason: func(s ToxicSignals) string { return "cluster_admin=true AND has_kev_cve=true" },
	},
	{
		RuleID: "TOXIC-005", Name: "Privileged + Critical CVE",
		Description: "privileged 컨테이너 + Critical 등급 CVE → 호스트 escape 위험",
		Severity:    "High", Multiplier: 1.3,
		Match:  func(s ToxicSignals) bool { return s.Privileged && s.HasCriticalCVE },
		Reason: func(s ToxicSignals) string { return "privileged=true AND has_critical_cve=true" },
	},
	{
		RuleID: "TOXIC-006", Name: "외부 노출 + High CVE + Secret",
		Description: "외부 노출 + 위험 CVE + 인증정보 접근 → 광범위한 자격증명 탈취",
		Severity:    "High", Multiplier: 1.3,
		Match:  func(s ToxicSignals) bool { return s.ExternallyExposed && s.HasHighCVE && s.SecretAccess },
		Reason: func(s ToxicSignals) string {
			return "externally_exposed=true AND has_high_cve=true AND secret_access=true"
		},
	},
	{
		RuleID: "TOXIC-007", Name: "NetworkPolicy 없음 + 최고 권한",
		Description: "네트워크 격리 없음 + cluster-admin → 어떤 Pod와도 통신 가능",
		Severity:    "High", Multiplier: 1.3,
		Match:  func(s ToxicSignals) bool { return s.NoNetworkPolicy && s.ClusterAdmin },
		Reason: func(s ToxicSignals) string { return "no_network_policy=true AND cluster_admin=true" },
	},

	// ── Medium (1.2x) ──
	{
		RuleID: "TOXIC-008", Name: "외부 노출 + High CVE",
		Description: "외부 노출 + 위험 등급 CVE → 직접 침해 경로",
		Severity:    "Medium", Multiplier: 1.2,
		Match:  func(s ToxicSignals) bool { return s.ExternallyExposed && s.HasHighCVE },
		Reason: func(s ToxicSignals) string { return "externally_exposed=true AND has_high_cve=true" },
	},
	{
		RuleID: "TOXIC-009", Name: "Secret 접근 + 악용 가능",
		Description: "인증정보 접근 권한 + 공개 exploit 또는 KEV",
		Severity:    "Medium", Multiplier: 1.2,
		Match:  func(s ToxicSignals) bool { return s.SecretAccess && s.HasActiveOrPOC },
		Reason: func(s ToxicSignals) string { return "secret_access=true AND has_active_or_poc=true" },
	},
	{
		RuleID: "TOXIC-010", Name: "최고 권한 + 리소스 무제한",
		Description: "cluster-admin + 리소스 limit 없음 → 자원 고갈 공격",
		Severity:    "Medium", Multiplier: 1.2,
		Match:  func(s ToxicSignals) bool { return s.ClusterAdmin && s.NoResourceLimits },
		Reason: func(s ToxicSignals) string { return "cluster_admin=true AND no_resource_limits=true" },
	},
}

// ─────────────────────────────────────────
// 평가 결과
// ─────────────────────────────────────────

// MatchedRule은 한 Pod에 매칭된 룰입니다.
type MatchedRule struct {
	RuleID     string  `json:"rule_id"`
	Name       string  `json:"name"`
	Severity   string  `json:"severity"`
	Multiplier float64 `json:"multiplier"`
	Reason     string  `json:"reason"`
}

// ToxicResult는 한 Pod의 토픽 평가 결과입니다.
type ToxicResult struct {
	ClusterName  string `json:"cluster_name"`
	PodUID       string `json:"pod_uid"`
	PodName      string `json:"pod_name"`
	PodNamespace string `json:"pod_namespace"`

	Multiplier   float64       `json:"multiplier"`     // 매칭된 룰 중 max
	MatchedRules []MatchedRule `json:"matched_rules"` // 매칭된 모든 룰
	Signals      ToxicSignals  `json:"signals"`       // 감지된 신호

	SnapshotAt time.Time `json:"snapshot_at"`
	ComputedAt time.Time `json:"computed_at"`
}

// ─────────────────────────────────────────
// 평가 함수
// ─────────────────────────────────────────

// EvaluateToxic는 주어진 신호에 대해 모든 룰을 평가합니다.
// 매칭된 룰 목록 + 최대 multiplier를 반환합니다.
//
// 매칭이 없으면 multiplier=1.0 (Final Score에 영향 없음).
func EvaluateToxic(signals ToxicSignals) (multiplier float64, matched []MatchedRule) {
	multiplier = 1.0
	matched = []MatchedRule{}

	for _, rule := range AllToxicRules {
		if rule.Match(signals) {
			matched = append(matched, MatchedRule{
				RuleID:     rule.RuleID,
				Name:       rule.Name,
				Severity:   rule.Severity,
				Multiplier: rule.Multiplier,
				Reason:     rule.Reason(signals),
			})
			if rule.Multiplier > multiplier {
				multiplier = rule.Multiplier
			}
		}
	}

	return
}

// ─────────────────────────────────────────
// API DTO
// ─────────────────────────────────────────

// ToxicComputeRequest는 클러스터 단위 평가 요청입니다.
type ToxicComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// ToxicComputeResponse는 일괄 평가 결과 요약입니다.
type ToxicComputeResponse struct {
	ClusterName string        `json:"cluster_name"`
	SnapshotAt  time.Time     `json:"snapshot_at"`
	Computed    int           `json:"computed"`

	MatchedTotal int `json:"matched_total"`  // multiplier > 1.0 인 Pod 수
	CriticalHits int `json:"critical_hits"`  // 1.5x 매칭
	HighHits     int `json:"high_hits"`      // 1.3x 매칭
	MediumHits   int `json:"medium_hits"`    // 1.2x 매칭

	Details []ToxicResult `json:"details"`
}
