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
type Edge struct {
	ID          int64  `json:"-"`            // DB ID (내부용)
	DisplayID   string `json:"id"`           // API 응답용 ("e_001" 형식)
	ClusterName string `json:"-"`            // 내부용 (FE 응답에 보통 X)
	
	// 식별 (source/target Pod uid)
	Source string `json:"source"` // pod_uid
	Target string `json:"target"`
	Layer  string `json:"layer"`
	
	// 통신 메타
	Weight        int     `json:"weight"`        // 통신 횟수
	TrafficWeight float64 `json:"trafficWeight"` // layer 가중치
	
	// 표시용
	SourceName      string `json:"sourceName,omitempty"`
	SourceNamespace string `json:"sourceNamespace,omitempty"`
	TargetName      string `json:"targetName,omitempty"`
	TargetNamespace string `json:"targetNamespace,omitempty"`
	
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

// EdgeListResponse — 클러스터 edges 응답
type EdgeListResponse struct {
	Total int    `json:"total"`
	Edges []Edge `json:"edges"`
}
