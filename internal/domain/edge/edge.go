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
	TrafficWeight float64 `json:"traffic_weight"`

	// 표시용
	SourceName      string `json:"source_name,omitempty"`
	SourceNamespace string `json:"source_namespace,omitempty"`
	TargetName      string `json:"target_name,omitempty"`
	TargetNamespace string `json:"target_namespace,omitempty"`

	// Migration 017로 추가된 새 필드들
	SourceKind        string `json:"source_kind,omitempty"` // pod / service_account / role / cluster_role
	TargetKind        string `json:"target_kind,omitempty"`
	TargetType        string `json:"target_type,omitempty"`        // pod / external_ip / service / service_account
	TargetServiceName string `json:"target_service_name,omitempty"` // 가상 ID (sa:..., crole:..., role:...)
	EdgeType          string `json:"edge_type,omitempty"`          // can_reach / assumes / binds / shares_image 등
	Mode              string `json:"mode,omitempty"`              // declared / observed / anomaly
	TotalBytes        int64  `json:"total_bytes,omitempty"`        // 트래픽 양 (network observed 전용)

	// 시점
	FirstSeenAt *time.Time `json:"first_seen_at,omitempty"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
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
	RiskScore      float64 `json:"risk_score"` // final_scores.final_score
	RiskLevel      string  `json:"risk_level"` // safe / caution / warning / emergency
	IsExposed      bool    `json:"is_exposed"` // exposure_scores.exposed
	ServiceAccount string  `json:"service_account"`
}

// EdgesMeta — 응답 메타데이터 [P0 5.2]
type EdgesMeta struct {
	Cluster         string    `json:"cluster"`
	SnapshotAt      time.Time `json:"snapshot_at"`
	ComputedAt      time.Time `json:"computed_at"`
	BuildDurationMs int64     `json:"build_duration_ms"`
	NodeCount       int       `json:"node_count"`
	EdgeCount       int       `json:"edge_count"`
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
	RuleID   string   `json:"rule_id"`   // 예: "TOXIC-001"
	Title    string   `json:"title"`    // toxic_rules.name (한국어 제목)
	PodIDs   []string `json:"pod_ids"`   // 매칭된 Pod uid 배열
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
	ToxicCombinations []ToxicCombination `json:"toxic_combinations"` // [P1 5.4]
}

type IdentityComputeResult struct {
	ClusterName string    `json:"cluster_name"`
	Assumes     int       `json:"assumes"`    // Pod → SA edges 수
	BindsRole   int       `json:"binds_role"`  // SA → Role edges 수
	BindsCRole  int       `json:"binds_cluster_role"` // SA → ClusterRole edges 수
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	ComputedAt  time.Time `json:"computed_at"`
	DurationMs  int64     `json:"duration_ms"`
}

// ────────────────────────────────────────────────────
// Supply Chain Layer 적재 응답 (Day 3)
// ────────────────────────────────────────────────────

type SupplyChainComputeResult struct {
	ClusterName string    `json:"cluster_name"`
	SharesImage int       `json:"shares_image"` // 같은 image_digest edges
	SharesCVE   int       `json:"shares_cve"`   // 같은 CVE (KEV, cross-image) edges
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	ComputedAt  time.Time `json:"computed_at"`
	DurationMs  int64     `json:"duration_ms"`
}

// ────────────────────────────────────────────────────
// Network Layer 적재 응답 (Day 4)
// ────────────────────────────────────────────────────

type NetworkComputeResult struct {
	ClusterName string    `json:"cluster_name"`
	SelectedBy  int       `json:"selected_by"`
	Allows      int       `json:"allows"`
	RoutedBy    int       `json:"routed_by"`
	ConnectsTo  int       `json:"connects_to"`
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	ComputedAt  time.Time `json:"computed_at"`
	DurationMs  int64     `json:"duration_ms"`
}

type HostComputeResult struct {
	ClusterName string    `json:"cluster_name"`
	RunsOn      int       `json:"runs_on"`
	EscapePath  int       `json:"escape_path"`
	Total       int       `json:"total"`
	SnapshotAt  time.Time `json:"snapshot_at"`
	ComputedAt  time.Time `json:"computed_at"`
	DurationMs  int64     `json:"duration_ms"`
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
	NodeType  string `json:"node_type"`
	Label     string `json:"label"`
	Namespace string `json:"namespace,omitempty"`

	// Pod 전용
	ServiceAccount string  `json:"service_account,omitempty"`
	ImageTag       string  `json:"image_tag,omitempty"`
	ImageDigest    string  `json:"image_digest,omitempty"`
	RiskScore      float64 `json:"risk_score"`
	RiskLevel      string  `json:"risk_level,omitempty"`
	TopCVE         string  `json:"top_cve,omitempty"`
	IsExposed      bool    `json:"is_exposed,omitempty"`
}

type TopologyEdge struct {
	ID            string  `json:"id"`
	Source        string  `json:"source"`
	Target        string  `json:"target"`
	Layer         string  `json:"layer"`
	EdgeType      string  `json:"edge_type"`
	Mode          string  `json:"mode"`
	Weight        float64 `json:"weight"`
	TrafficWeight float64 `json:"traffic_weight,omitempty"`
}

type TopologyMeta struct {
	NodeCount  int       `json:"node_count"`
	EdgeCount  int       `json:"edge_count"`
	SnapshotAt time.Time `json:"snapshot_at,omitempty"`
	BuildMs    int64     `json:"build_ms"`
}

// ────────────────────────────────────────────────────
// Blast Radius API 응답 (PM 명세서 B-2)
// ────────────────────────────────────────────────────

type BlastRadiusResponse struct {
	Source     string          `json:"source"`
	Hops       int             `json:"hops"`
	BlastScore float64         `json:"blast_score"`
	OutOf      float64         `json:"out_of"`
	Reachable  []ReachableNode `json:"reachable"`
	TotalCount int             `json:"total_count"`
	ByLayer    map[string]int  `json:"by_layer"`
	BuildMs    int64           `json:"build_ms"`
}

type ReachableNode struct {
	NodeID   string `json:"node_id"`
	NodeKind string `json:"node_kind"`
	NodeName string `json:"node_name"`
	Hop      int    `json:"hop"`
	Layer    string `json:"layer"`
}

// ────────────────────────────────────────────────────
// Blast Radius Simulate API (패치탭 반응형: 보안 적용 → 재계산)
// DESIGN-patch-tab-blast-radius-reactive.md 참고
// ────────────────────────────────────────────────────

// AppliedMitigation — 적용된 보안 1건 (시나리오 탭 보안 카드)
// predicate로 "제거할 엣지"를 선택한다 (DESIGN §3).
type AppliedMitigation struct {
	Layer  string `json:"layer"`            // supply_chain / network / identity / host
	Kind   string `json:"kind"`             // cve_image / cve_id / netpol_denyall / netpol_peer / rbac_revoke / mount_remove
	Target string `json:"target,omitempty"` // image_digest / cve_id / peer_uid / "sa: ns/name" 등 (kind에 따라)
}

// SimulateBlastRequest — POST /scoring/blast-radius/simulate body
type SimulateBlastRequest struct {
	Cluster string              `json:"cluster" binding:"required"`
	Source  string              `json:"source" binding:"required"`
	Hops    int                 `json:"hops,omitempty"`    // 기본 3
	Applied []AppliedMitigation `json:"applied,omitempty"` // 빈 배열이면 baseline만
}

// SimulateBlastResponse — 재계산 결과 (per-source blast graph diff)
type SimulateBlastResponse struct {
	Source        string         `json:"source"`
	Hops          int            `json:"hops"`
	OutOf         float64        `json:"out_of"`
	BaselineScore float64        `json:"baseline_score"`
	BlastScore    float64        `json:"blast_score"` // 적용 후
	Delta         float64        `json:"delta"`       // baseline - blast_score
	ByLayer       map[string]int `json:"by_layer"`    // 적용 후 reachable layer 분포
	Nodes         []SimNode      `json:"nodes"`
	EdgesRemoved  []RemovedEdge  `json:"edges_removed"`
	BuildMs       int64          `json:"build_ms"`
}

// SimNode — 적용 후 노드 상태 (FE 노드 색칠 기준)
type SimNode struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Reachable    bool    `json:"reachable"`     // 적용 후 도달 여부
	Hop          *int    `json:"hop"`           // 미도달이면 null
	Layer        *string `json:"layer"`         // 미도달이면 null
	Criticality  float64 `json:"criticality"`   // 정규화 PageRank (평균=1)
	Contribution float64 `json:"contribution"`  // 적용 후 blast 기여도
	ColorLevel   string  `json:"color_level"`   // removed/safe/caution/warning/emergency
	Dropped      bool    `json:"dropped"`       // baseline엔 닿았으나 적용 후 끊김

	// RiskBefore/RiskAfter — 이 노드를 risk_score(final_score, 0~100) 스케일로 색칠하기 위한 값.
	// FE가 0~25 blast 스케일을 환산하지 않고 헤더 위험도와 같은 등급컷으로 바로 재색칠하게 한다.
	//   RiskBefore = 이 노드의 final_score (오비탈 노드 원래 색과 동일한 값)
	//   RiskAfter  = RiskBefore × (적용후 기여도 / 적용전 기여도)  ("전파 약화분"을 노드 위험에 투영)
	// 보장: RiskAfter ≤ RiskBefore (클램프), dropped/미도달 노드는 RiskAfter=0, applied 비면 RiskAfter==RiskBefore.
	RiskBefore float64 `json:"risk_before"`
	RiskAfter  float64 `json:"risk_after"`
}

// RemovedEdge — 적용으로 제거된 엣지 (FE 페이드아웃용)
type RemovedEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Layer  string `json:"layer"`
}

// ────────────────────────────────────────────────────
// Criticality API (PageRank)
// ────────────────────────────────────────────────────

type CriticalityResponse struct {
	Cluster   string            `json:"cluster"`
	TopN      int               `json:"top_n"`
	Nodes     []NodeCriticality `json:"nodes"`
	Algorithm string            `json:"algorithm"`
	BuildMs   int64             `json:"build_ms"`
}

type NodeCriticality struct {
	NodeID    string  `json:"node_id"`
	NodeKind  string  `json:"node_kind"`
	NodeName  string  `json:"node_name"`
	Namespace string  `json:"namespace,omitempty"`
	Score     float64 `json:"score"`
	Rank      int     `json:"rank"`
}

// ────────────────────────────────────────────────────
// Image/CVE Clusters API (Union-Find)
// ────────────────────────────────────────────────────

type ClustersResponse struct {
	Cluster        string     `json:"cluster"`
	GroupBy        string     `json:"group_by"` // "image" 또는 "cve"
	TotalGroups    int        `json:"total_groups"`
	TotalPods      int        `json:"total_pods"`
	LargestGroup   int        `json:"largest_group"`
	SingletonCount int        `json:"singleton_count"`
	Groups         []PodGroup `json:"groups"`
	BuildMs        int64      `json:"build_ms"`
}

type PodGroup struct {
	GroupID   int      `json:"group_id"`
	Size      int      `json:"size"`
	PodIDs    []string `json:"pod_ids"`
	PodLabels []string `json:"pod_labels"`
	SharedKey string   `json:"shared_key,omitempty"` // 공유 이미지 digest 또는 CVE ID
}
