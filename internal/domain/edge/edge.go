package edge

import (
	"fmt"
	"time"
)

// ────────────────────────────────────────────────────
// Edge — Pod 간 통신 관계 (Blast Radius 그래프 단위)
//
// 한 Edge = (Cluster, Source Pod, Target Pod, Layer) 조합
// 같은 (src, dst) 쌍의 여러 통신은 weight로 집계.
// ────────────────────────────────────────────────────

// Layer 정의
const (
	LayerNetwork     = "network"
	LayerIdentity    = "identity"
	LayerSupplyChain = "supply_chain"
	LayerHost        = "host" // 사용 안 함 (정의만)
)

// Layer별 가중치
const (
	WeightNetwork     = 0.8
	WeightIdentity    = 0.7
	WeightSupplyChain = 0.6
	WeightHost        = 0.5
)

// LayerWeight — layer 이름으로 가중치 조회
func LayerWeight(layer string) float64 {
	switch layer {
	case LayerNetwork:
		return WeightNetwork
	case LayerIdentity:
		return WeightIdentity
	case LayerSupplyChain:
		return WeightSupplyChain
	case LayerHost:
		return WeightHost
	default:
		return 0.0
	}
}

// Edge — Pod-to-Pod 통신 관계
// Edge — Pod-to-Pod 또는 Pod-to-SA/Role/Service 등 관계
type Edge struct {
	ID          int64  `json:"-"`  // DB ID (내부용)
	DisplayID   string `json:"id"` // API 응답용 ("e_001" 형식)
	ClusterName string `json:"-"`  // 내부용

	// 식별 (source/target uid 또는 가상 ID)
	Source string `json:"source"` // pod_uid 또는 "sa:ns/name", "role:ns/name", "crole:name"
	Target string `json:"target"` // 동일. NULL이면 빈 문자열
	Layer  string `json:"layer"`

	// 통신 메타
	Weight        int     `json:"weight"`
	TrafficWeight float64 `json:"trafficWeight"`

	// 표시용
	SourceName      string `json:"sourceName,omitempty"`
	SourceNamespace string `json:"sourceNamespace,omitempty"`
	TargetName      string `json:"targetName,omitempty"`
	TargetNamespace string `json:"targetNamespace,omitempty"`

	// Migration 017로 추가된 새 필드들
	SourceKind        string `json:"sourceKind,omitempty"` // pod / service_account / role / cluster_role
	TargetKind        string `json:"targetKind,omitempty"`
	TargetType        string `json:"targetType,omitempty"`        // pod / external_ip / service / service_account
	TargetServiceName string `json:"targetServiceName,omitempty"` // 가상 ID (sa:..., crole:..., role:...)
	EdgeType          string `json:"edgeType,omitempty"`          // can_reach / assumes / binds / shares_image 등
	Mode              string `json:"mode,omitempty"`              // declared / observed / anomaly
	TotalBytes        int64  `json:"totalBytes,omitempty"`        // 트래픽 양 (network observed 전용)

	// 시점
	FirstSeenAt *time.Time `json:"firstSeenAt,omitempty"`
	LastSeenAt  *time.Time `json:"lastSeenAt,omitempty"`
	SnapshotAt  time.Time  `json:"-"`
	ComputedAt  time.Time  `json:"-"`
}

// FormatDisplayID — DB ID를 "e_001" 형식으로
func FormatDisplayID(dbID int64) string {
	return fmt.Sprintf("e_%03d", dbID)
}

// ────────────────────────────────────────────────────
// 분석 설정
// ────────────────────────────────────────────────────

// AnalysisConfig — Edge 계산 옵션
type AnalysisConfig struct {
	// 시간 윈도우 (분)
	WindowMinutes int

	// 분석 제외 Pod 패턴 (자기 자신 제외)
	ExcludePodPatterns []string
}

// DefaultConfig — 기본 설정
//
// 5분 윈도우, vara-ebpf-agent / vara-cluster-agent 제외
func DefaultConfig() AnalysisConfig {
	return AnalysisConfig{
		WindowMinutes: 5,
		ExcludePodPatterns: []string{
			"default/vara-ebpf-agent-",
			"default/vara-cluster-agent-",
		},
	}
}

// ────────────────────────────────────────────────────
// ComputeResponse — 계산 결과 응답
// ────────────────────────────────────────────────────

type ComputeResponse struct {
	ClusterName    string    `json:"cluster_name"`
	Computed       int       `json:"computed"`        // 생성된 edge 수
	ProcessedFlows int       `json:"processed_flows"` // 처리한 ebpf_network_flows 수
	SkippedFlows   int       `json:"skipped_flows"`   // 매칭 실패/제외된 수
	SnapshotAt     time.Time `json:"snapshot_at"`
	ComputedAt     time.Time `json:"computed_at"`
}

// ────────────────────────────────────────────────────
// 응답 보강 타입 (Blast Radius PDF 5.1~5.4)
// ────────────────────────────────────────────────────

// NodeView — 그래프 노드 (Pod 단위 risk 정보 포함) [P0 5.1]
type NodeView struct {
	ID             string  `json:"id"`   // pod_uid
	Type           string  `json:"type"` // "Pod" (v1.0은 Pod만)
	Name           string  `json:"name"`
	Namespace      string  `json:"namespace"`
	RiskScore      float64 `json:"riskScore"` // final_scores.final_score
	RiskLevel      string  `json:"riskLevel"` // safe / caution / warning / emergency
	IsExposed      bool    `json:"isExposed"` // exposure_scores.exposed
	ServiceAccount string  `json:"serviceAccount"`
}

// EdgesMeta — 응답 메타데이터 [P0 5.2]
type EdgesMeta struct {
	Cluster         string    `json:"cluster"`
	SnapshotAt      time.Time `json:"snapshotAt"`
	ComputedAt      time.Time `json:"computedAt"`
	BuildDurationMs int64     `json:"buildDurationMs"`
	NodeCount       int       `json:"nodeCount"`
	EdgeCount       int       `json:"edgeCount"`
}

// EdgesSummary — 4단계 risk_level 카운트 [P0 5.3]
type EdgesSummary struct {
	Emergency int `json:"emergency"`
	Warning   int `json:"warning"`
	Caution   int `json:"caution"`
	Safe      int `json:"safe"`
	Total     int `json:"total"`
}

// ToxicCombination — Toxic Combination (layer 조합 분석) [P1 5.4]
// PM 정의: 여러 layer가 조합된 위험 시나리오 (단일 Pod의 시그널이 아님)
type ToxicCombination struct {
	ID       string   `json:"id"`       // 예: "tc_toxic_001"
	RuleID   string   `json:"ruleId"`   // 예: "TOXIC-001"
	Title    string   `json:"title"`    // toxic_rules.name (한국어 제목)
	PodIDs   []string `json:"podIds"`   // 매칭된 Pod uid 배열
	Severity string   `json:"severity"` // emergency/warning/caution
	Reason   string   `json:"reason"`   // toxic_rules.description
	Layers   []string `json:"layers"`   // ["network", "identity"] 등 자동 추출
}

// EdgeListResponse — 클러스터 edges 응답 (보강된 버전)
type EdgeListResponse struct {
	Total             int                `json:"total"`
	Edges             []Edge             `json:"edges"`
	Nodes             []NodeView         `json:"nodes"`             // [P0 5.1]
	Meta              *EdgesMeta         `json:"meta"`              // [P0 5.2]
	Summary           *EdgesSummary      `json:"summary"`           // [P0 5.3]
	ToxicCombinations []ToxicCombination `json:"toxicCombinations"` // [P1 5.4]
}

type IdentityComputeResult struct {
	ClusterName string    `json:"clusterName"`
	Assumes     int       `json:"assumes"`    // Pod → SA edges 수
	BindsRole   int       `json:"bindsRole"`  // SA → Role edges 수
	BindsCRole  int       `json:"bindsCRole"` // SA → ClusterRole edges 수
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshotAt"`
	ComputedAt  time.Time `json:"computedAt"`
	DurationMs  int64     `json:"durationMs"`
}

// ────────────────────────────────────────────────────
// Supply Chain Layer 적재 응답 (Day 3)
// ────────────────────────────────────────────────────

type SupplyChainComputeResult struct {
	ClusterName string    `json:"clusterName"`
	SharesImage int       `json:"sharesImage"` // 같은 image_digest edges
	SharesCVE   int       `json:"sharesCve"`   // 같은 CVE (KEV, cross-image) edges
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshotAt"`
	ComputedAt  time.Time `json:"computedAt"`
	DurationMs  int64     `json:"durationMs"`
}

// ────────────────────────────────────────────────────
// Network Layer 적재 응답 (Day 4)
// ────────────────────────────────────────────────────

type NetworkComputeResult struct {
	ClusterName string    `json:"clusterName"`
	SelectedBy  int       `json:"selectedBy"`
	Allows      int       `json:"allows"`
	RoutedBy    int       `json:"routedBy"`
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshotAt"`
	ComputedAt  time.Time `json:"computedAt"`
	DurationMs  int64     `json:"durationMs"`
}

// ────────────────────────────────────────────────────
// Topology API 응답 (PM 명세서 v1.0 호환)
// ────────────────────────────────────────────────────

type TopologyResponse struct {
	Cluster string         `json:"cluster"`
	Nodes   []TopologyNode `json:"nodes"`
	Edges   []TopologyEdge `json:"edges"`
	Meta    TopologyMeta   `json:"meta"`
}

type TopologyNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Label     string `json:"label"`
	Namespace string `json:"namespace,omitempty"`

	// Pod 전용
	ServiceAccount string  `json:"serviceAccount,omitempty"`
	ImageTag       string  `json:"imageTag,omitempty"`
	ImageDigest    string  `json:"imageDigest,omitempty"`
	RiskScore      float64 `json:"riskScore"`
	RiskLevel      string  `json:"riskLevel,omitempty"`
	TopCVE         string  `json:"topCve,omitempty"`
	IsExposed      bool    `json:"isExposed,omitempty"`
}

type TopologyEdge struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	Target        string  `json:"target"`
	Layer         string  `json:"layer"`
	EdgeType      string  `json:"edgeType"`
	Mode          string  `json:"mode"`
	Weight        float64 `json:"weight"`
	TrafficWeight float64 `json:"trafficWeight,omitempty"`
}

type TopologyMeta struct {
	NodeCount  int       `json:"nodeCount"`
	EdgeCount  int       `json:"edgeCount"`
	SnapshotAt time.Time `json:"snapshotAt,omitempty"`
	BuildMs    int64     `json:"buildMs"`
}

// ────────────────────────────────────────────────────
// Blast Radius API 응답 (PM 명세서 B-2)
// ────────────────────────────────────────────────────

type BlastRadiusResponse struct {
	Source     string          `json:"source"`
	Hops       int             `json:"hops"`
	BlastScore float64         `json:"blastScore"`
	OutOf      float64         `json:"outOf"`
	Reachable  []ReachableNode `json:"reachable"`
	TotalCount int             `json:"totalCount"`
	ByLayer    map[string]int  `json:"byLayer"`
	BuildMs    int64           `json:"buildMs"`
}

type ReachableNode struct {
	NodeID   string `json:"nodeId"`
	NodeKind string `json:"nodeKind"`
	NodeName string `json:"nodeName"`
	Hop      int    `json:"hop"`
	Layer    string `json:"layer"`
}

// ────────────────────────────────────────────────────
// Criticality API (PageRank)
// ────────────────────────────────────────────────────

type CriticalityResponse struct {
	Cluster   string            `json:"cluster"`
	TopN      int               `json:"topN"`
	Nodes     []NodeCriticality `json:"nodes"`
	Algorithm string            `json:"algorithm"`
	BuildMs   int64             `json:"buildMs"`
}

type NodeCriticality struct {
	NodeID    string  `json:"nodeId"`
	NodeKind  string  `json:"nodeKind"`
	NodeName  string  `json:"nodeName"`
	Namespace string  `json:"namespace,omitempty"`
	Score     float64 `json:"score"`
	Rank      int     `json:"rank"`
}

// ────────────────────────────────────────────────────
// Image/CVE Clusters API (Union-Find)
// ────────────────────────────────────────────────────

type ClustersResponse struct {
	Cluster        string     `json:"cluster"`
	GroupBy        string     `json:"groupBy"` // "image" 또는 "cve"
	TotalGroups    int        `json:"totalGroups"`
	TotalPods      int        `json:"totalPods"`
	LargestGroup   int        `json:"largestGroup"`
	SingletonCount int        `json:"singletonCount"`
	Groups         []PodGroup `json:"groups"`
	BuildMs        int64      `json:"buildMs"`
}

type PodGroup struct {
	GroupID   int      `json:"groupId"`
	Size      int      `json:"size"`
	PodIDs    []string `json:"podIds"`
	PodLabels []string `json:"podLabels"`
	SharedKey string   `json:"sharedKey,omitempty"` // 공유 이미지 digest 또는 CVE ID
}
