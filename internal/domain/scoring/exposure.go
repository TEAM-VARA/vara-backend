// Package scoring contains domain models for risk scoring calculations.
//
// 이 패키지는 Risk Scoring의 각 항목(EPSS, CVSS, SSVC, Internet Exposure,
// Attack Path, Toxic Combination)에 대한 도메인 모델을 정의합니다.
//
// 인터넷 노출(Internet Exposure)은 Pod이 외부에서 도달 가능한지 판단하는
// 항목으로, 다음 단계로 진화합니다:
//   - Phase 1: K8s 정의 기반 (LoadBalancer/NodePort/Ingress 매핑)
//   - Phase 2: AWS Security Group/Load Balancer 통합
//   - Phase 3: NetworkPolicy 정밀 평가 + eBPF 실제 통신
package scoring

import "time"

// 노출 점수 가중치 (Risk Scoring 최종 공식에서 사용)
const (
	// ExposureScoreExposed: 노출됨 → 20점
	ExposureScoreExposed = 20

	// ExposureScoreNotExposed: 노출 안 됨 → 0점
	ExposureScoreNotExposed = 0
)

// PodLabels는 Pod의 라벨 집합입니다.
// Service selector와 매칭 시 사용됩니다.
type PodLabels map[string]string

// ServiceSelector는 Service가 매칭할 Pod의 조건입니다.
// K8s 의미론: Service.selector의 모든 key/value가 Pod.labels에 포함되어야 매칭.
type ServiceSelector map[string]string

// ExposureResult는 단일 Pod의 인터넷 노출 판정 결과입니다.
type ExposureResult struct {
	ClusterName      string           `json:"cluster_name"`
	PodUID           string           `json:"pod_uid"`
	PodName          string           `json:"pod_name"`
	PodNamespace     string           `json:"pod_namespace"`
	Exposed          bool             `json:"exposed"`
	Score            int              `json:"score"`
	MatchedServices  []MatchedService `json:"matched_services"`
	MatchedIngresses []MatchedIngress `json:"matched_ingresses"`
	SnapshotAt       time.Time        `json:"snapshot_at"`
	ComputedAt       time.Time        `json:"computed_at"`

	// ─── Runtime 분석 (eBPF 기반, nullable) ───
	RuntimeActuallyAccessed     *bool                   `json:"runtime_actually_accessed,omitempty"`
	RuntimeExternalTrafficCount *int                    `json:"runtime_external_traffic_count,omitempty"`
	RuntimeDetails              *RuntimeExposureDetails `json:"runtime_details,omitempty"`
}

// MatchedService는 Pod에 매핑된 Service 정보입니다.
type MatchedService struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Type      string `json:"type"` // LoadBalancer, NodePort, ClusterIP, ExternalName
	// 외부 노출 트리거 여부 (Type이 LoadBalancer/NodePort인 경우)
	ExternallyExposed bool `json:"externally_exposed"`
}

// MatchedIngress는 Pod에 매핑된 Ingress 정보입니다.
//
// Ingress는 Service를 통해 간접적으로 Pod와 연결됩니다:
//   Ingress → Service.name → Service.selector → Pod.labels
type MatchedIngress struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	// Ingress가 해당 Pod의 어떤 Service로 라우팅하는지
	ViaServiceName string `json:"via_service_name"`
	// Ingress rule의 host (있으면)
	Host string `json:"host,omitempty"`
}

// ComputeRequest는 클러스터 단위 일괄 계산 요청입니다.
type ComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// ComputeResponse는 일괄 계산 결과 요약입니다.
type ComputeResponse struct {
	ClusterName string           `json:"cluster_name"`
	SnapshotAt  time.Time        `json:"snapshot_at"`
	Computed    int              `json:"computed"`    // 계산된 Pod 수
	Exposed     int              `json:"exposed"`     // 노출된 Pod 수
	NotExposed  int              `json:"not_exposed"` // 노출 안 된 Pod 수
	Details     []ExposureResult `json:"details"`     // 각 Pod별 결과
}

// SelectorMatches는 Pod의 라벨이 Service selector를 만족하는지 판단합니다.
//
// K8s의 Service.selector 의미론을 따릅니다:
//   - selector의 모든 key/value가 pod labels에 존재해야 매칭
//   - selector가 비어있으면 매칭 안 됨 (K8s 동작: 어떤 Pod도 선택 안 함)
//   - pod labels에 추가 키가 있어도 OK (subset 관계)
//
// 예시:
//   selector={app: nginx}, labels={app: nginx, tier: web} → match
//   selector={app: nginx, tier: web}, labels={app: nginx} → no match (tier 없음)
//   selector={}, labels={app: nginx} → no match (빈 selector)
func SelectorMatches(podLabels PodLabels, selector ServiceSelector) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// IsExternallyExposedServiceType는 Service.type이 외부 노출을 트리거하는지 판단합니다.
//
// 외부 노출 타입:
//   - LoadBalancer: 클라우드 LB로 외부 IP 할당
//   - NodePort: 모든 노드의 특정 포트로 접근 가능
//
// 외부 노출 아님:
//   - ClusterIP: 클러스터 내부만
//   - ExternalName: DNS 별칭 (역방향 매핑)
func IsExternallyExposedServiceType(serviceType string) bool {
	return serviceType == "LoadBalancer" || serviceType == "NodePort"
}
