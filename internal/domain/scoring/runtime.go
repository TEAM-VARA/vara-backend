package scoring

import "time"

// ────────────────────────────────────────────────────
// Runtime Scoring (eBPF 기반 동적 분석)
// ────────────────────────────────────────────────────
//
// eBPF Agent가 수집한 데이터로 기존 정적 점수를 보강한다.
// 모든 필드는 forward-compatible:
//   - 데이터 없으면 zero value 또는 nil
//   - 데이터 있으면 정상 분석 결과
//
// 결과 저장:
//   attack_path_scores.runtime_network_score 등
//   exposure_scores.runtime_actually_accessed 등
// ────────────────────────────────────────────────────

// RuntimeNetworkDetails — 실제 통신 그래프 분석 결과
type RuntimeNetworkDetails struct {
	ActualTargetsCount   int      `json:"actual_targets_count"`
	InternalTargets      []string `json:"internal_targets"`       // dst pod_uid 목록
	ExternalTargetsCount int      `json:"external_targets_count"`
	ExternalIPs          []string `json:"external_ips"`
	DiversityScore       float64  `json:"diversity_score"` // 0~1, 통신 대상 다양성
	WindowHours          int      `json:"window_hours"`
	FlowCount            int      `json:"flow_count"`
	DataAvailable        bool     `json:"data_available"` // false면 ebpf 데이터 없음
}

// RuntimeExposureDetails — 실제 외부 접근 검증 결과
type RuntimeExposureDetails struct {
	ExternalSourceIPs   []string   `json:"external_source_ips"`
	InternalSourceIPs   []string   `json:"internal_source_ips"`
	FirstExternalAccess *time.Time `json:"first_external_access,omitempty"`
	LastExternalAccess  *time.Time `json:"last_external_access,omitempty"`
	WindowHours         int        `json:"window_hours"`
	DataAvailable       bool       `json:"data_available"`
}

// OvergrantPermissions — RBAC 권한 과다 부여 분석 결과
type OvergrantPermissions struct {
	DefinedVerbs            []string       `json:"defined_verbs"`
	RBACSummary             RBACSummary    `json:"rbac_summary"`
	BindingCount            int            `json:"binding_count"`
	HighPrivilegeResources  []string       `json:"high_privilege_resources"`
	OvergrantRatio          float64        `json:"overgrant_ratio"` // 0.0~1.0
}

// RBACSummary — RBAC 정의된 권한 요약
type RBACSummary struct {
	HasWildcardVerbs   bool `json:"has_wildcard_verbs"`   // verbs=["*"]
	HasWildcardResources bool `json:"has_wildcard_resources"` // resources=["*"]
	HasSecretAccess    bool `json:"has_secret_access"`
	HasConfigMapAccess bool `json:"has_configmap_access"`
	HasNodeAccess      bool `json:"has_node_access"`
	HasPodExec         bool `json:"has_pod_exec"`
	VerbCount          int  `json:"verb_count"`
	ResourceCount      int  `json:"resource_count"`
}

// ────────────────────────────────────────────────────
// 분석 설정 (config로 조정)
// ────────────────────────────────────────────────────

// RuntimeAnalysisConfig — 런타임 분석 옵션
type RuntimeAnalysisConfig struct {
	// 분석 시간 윈도우 (기본 1시간)
	WindowHours int

	// 분석에서 제외할 Pod 패턴 (자기 자신 등)
	// 예: "default/vara-ebpf-agent-*", "default/vara-cluster-agent-*"
	ExcludePodPatterns []string
}

// DefaultRuntimeConfig — 기본 설정
func DefaultRuntimeConfig() RuntimeAnalysisConfig {
	return RuntimeAnalysisConfig{
		WindowHours: 1,
		ExcludePodPatterns: []string{
			"default/vara-ebpf-agent-",
			"default/vara-cluster-agent-",
		},
	}
}

// ────────────────────────────────────────────────────
// 보정 가중치 (network_score)
// ────────────────────────────────────────────────────
//
// 정적 network_score (NetworkPolicy 있나/없나) 위에
// 실제 통신 활성도를 곱해서 보정한다.
//
//   runtime_network_score = static_network_score × activity_factor
//
//   activity_factor 결정:
//     - 데이터 없음                 → 1.0 (보정 없음, 정적 그대로)
//     - 통신 0건                    → 0.3 (격리됨 가능성, 위험도 낮춤)
//     - 통신 1~5건                  → 0.7 (제한된 통신)
//     - 통신 6~20건                 → 1.0 (정상 범위)
//     - 통신 20건 이상              → 1.2 (활발한 통신, 위험도 약간 상승)
//     - 외부 IP 통신 있음           → 추가 +0.2
// ────────────────────────────────────────────────────

const (
	// 통신 활성도 임계값
	ThresholdLowComm    = 5
	ThresholdNormalComm = 20

	// 활성도 계수
	FactorNoData       = 1.0
	FactorIsolated     = 0.3
	FactorLowComm      = 0.7
	FactorNormalComm   = 1.0
	FactorActiveComm   = 1.2
	FactorExternalBoost = 0.2
)

// CalculateActivityFactor — 통신 패턴에 따른 위험도 계수
func CalculateActivityFactor(details RuntimeNetworkDetails) float64 {
	if !details.DataAvailable {
		return FactorNoData
	}

	totalComm := details.ActualTargetsCount + details.ExternalTargetsCount

	var base float64
	switch {
	case totalComm == 0:
		base = FactorIsolated
	case totalComm <= ThresholdLowComm:
		base = FactorLowComm
	case totalComm <= ThresholdNormalComm:
		base = FactorNormalComm
	default:
		base = FactorActiveComm
	}

	if details.ExternalTargetsCount > 0 {
		base += FactorExternalBoost
	}

	// 최대 1.5로 clamp
	if base > 1.5 {
		base = 1.5
	}

	return base
}

// ────────────────────────────────────────────────────
// 외부 IP 판별
// ────────────────────────────────────────────────────
//
// 다음 대역은 내부 (Pod 또는 사설망):
//   - 10.0.0.0/8
//   - 172.16.0.0/12
//   - 192.168.0.0/16
//   - 127.0.0.0/8 (loopback)
//   - 169.254.0.0/16 (link-local)
//   - K8s Service CIDR (예: 10.96.0.0/12, 클러스터별 다름)
//
// 그 외 IP는 외부로 간주.
// ────────────────────────────────────────────────────

// IsInternalIP — IP가 내부 대역인지 판별
func IsInternalIP(ip string) bool {
	if ip == "" {
		return false
	}
	// 단순 prefix 매칭 (정밀 분석 시 net.ParseIP + CIDR 사용 권장)
	internalPrefixes := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"169.254.",
	}
	for _, prefix := range internalPrefixes {
		if len(ip) >= len(prefix) && ip[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
