package service

import (
	"gonum.org/v1/gonum/graph/network"
	"gonum.org/v1/gonum/graph/path"
)

// ─────────────────────────────────────────
// Betweenness Centrality — "방어 길목" 식별
//
// 많은 최단 경로가 통과하는 노드 = 차단 시 가장 효과적인 방어 지점
// gonum network.Betweenness 사용
// ─────────────────────────────────────────

// computeBetweenness는 모든 노드의 betweenness centrality를 계산합니다.
// 반환: node string ID → betweenness 점수
func computeBetweenness(bg *BlastGraph) map[string]float64 {
	g := bg.GonumGraph()

	// gonum betweenness (int64 nodeID → score)
	scores := network.Betweenness(g)

	rev := bg.ReverseNodeMap()
	results := make(map[string]float64, len(scores))
	for nodeID, score := range scores {
		if strID, ok := rev[nodeID]; ok {
			results[strID] = score
		}
	}
	return results
}

// ─────────────────────────────────────────
// Dijkstra 최단 경로 — "가장 쉬운 공격 경로"
//
// cost = 1/layer_weight (이미 BlastGraph에 설정됨)
// cost 최소 = 통과하기 가장 쉬운 경로
// gonum path.DijkstraFrom 사용
// ─────────────────────────────────────────

// DijkstraPath는 단일 source→target 최단 경로 결과입니다.
type DijkstraPath struct {
	SourceID  string
	TargetID  string
	Nodes     []string // 경로 노드 ID 시퀀스
	Labels    []string // 사용자 친화 이름
	Layers    []string // 각 hop의 layer
	TotalCost float64  // 누적 cost (낮을수록 쉬운 경로)
	Hops      int
}

// dijkstraShortestPath는 source에서 target까지 최소 cost 경로를 찾습니다.
// 경로가 없으면 (nil, false) 반환.
func dijkstraShortestPath(bg *BlastGraph, sourceID, targetID string) (*DijkstraPath, bool) {
	src := bg.NodeByID(sourceID)
	tgt := bg.NodeByID(targetID)
	if src == nil || tgt == nil {
		return nil, false
	}

	g := bg.GonumGraph()

	// gonum Dijkstra (WeightedDirectedGraph라 weight 자동 사용)
	shortest := path.DijkstraFrom(src, g)

	nodesPath, cost := shortest.To(tgt.ID())
	if len(nodesPath) < 2 {
		return nil, false // 경로 없음 (도달 불가)
	}

	// gonum node → 우리 string ID + label
	nodes := make([]string, len(nodesPath))
	labels := make([]string, len(nodesPath))
	for i, n := range nodesPath {
		id := bg.IDByNode(n)
		nodes[i] = id
		lbl := bg.Label(id)
		if lbl == "" {
			lbl = id
		}
		labels[i] = lbl
	}

	// 각 hop의 layer 추출
	layers := make([]string, len(nodes)-1)
	for i := 0; i < len(nodes)-1; i++ {
		layers[i] = bg.EdgeLayer(nodes[i], nodes[i+1])
	}

	return &DijkstraPath{
		SourceID:  sourceID,
		TargetID:  targetID,
		Nodes:     nodes,
		Labels:    labels,
		Layers:    layers,
		TotalCost: cost,
		Hops:      len(nodes) - 1,
	}, true
}

// dijkstraToCriticalAssets는 한 source에서 여러 critical asset까지의
// 최단 경로들을 계산합니다 (사전계산용).
func dijkstraToCriticalAssets(bg *BlastGraph, sourceID string, targetIDs []string) []*DijkstraPath {
	src := bg.NodeByID(sourceID)
	if src == nil {
		return nil
	}

	g := bg.GonumGraph()
	// 한 번의 DijkstraFrom으로 모든 target까지 최단경로 계산 (효율적)
	shortest := path.DijkstraFrom(src, g)

	var results []*DijkstraPath
	for _, targetID := range targetIDs {
		tgt := bg.NodeByID(targetID)
		if tgt == nil {
			continue
		}

		nodesPath, cost := shortest.To(tgt.ID())
		if len(nodesPath) < 2 {
			continue // 도달 불가
		}

		nodes := make([]string, len(nodesPath))
		labels := make([]string, len(nodesPath))
		for i, n := range nodesPath {
			id := bg.IDByNode(n)
			nodes[i] = id
			lbl := bg.Label(id)
			if lbl == "" {
				lbl = id
			}
			labels[i] = lbl
		}

		layers := make([]string, len(nodes)-1)
		for i := 0; i < len(nodes)-1; i++ {
			layers[i] = bg.EdgeLayer(nodes[i], nodes[i+1])
		}

		results = append(results, &DijkstraPath{
			SourceID:  sourceID,
			TargetID:  targetID,
			Nodes:     nodes,
			Labels:    labels,
			Layers:    layers,
			TotalCost: cost,
			Hops:      len(nodes) - 1,
		})
	}

	return results
}
