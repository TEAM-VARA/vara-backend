package service

import (
	"math"

	"github.com/vara/backend/internal/domain/edge"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/simple"
)

// GraphLayerWeight — PM 명세서의 레이어별 가중치
var GraphLayerWeight = map[string]float64{
	"network":      1.0,
	"identity":     0.85,
	"supply_chain": 0.7,
	"host":         0.5,
}

// EdgeMetadata — gonum graph의 edge에 부착할 메타 정보
type EdgeMetadata struct {
	Layer    string
	EdgeType string
	Mode     string
	Source   string // 원본 source ID
	Target   string // 원본 target ID
}

// BlastGraph — gonum 기반 in-memory graph
type BlastGraph struct {
	g              *simple.WeightedDirectedGraph
	nodes          map[string]graph.Node // pod_uid → gonum node
	reverseNodeMap map[int64]string      // gonum nodeID → pod_uid
	edges          map[string]EdgeMetadata // "from->to" → metadata
	nodeLabels     map[string]string
	nodeKinds      map[string]string
}

// BuildBlastGraph — TopologyResponse로부터 gonum 그래프 빌드
func BuildBlastGraph(topo *edge.TopologyResponse) *BlastGraph {
	g := simple.NewWeightedDirectedGraph(0, math.Inf(1))
	nodes := make(map[string]graph.Node)
	reverse := make(map[int64]string)
	edgeMeta := make(map[string]EdgeMetadata)
	nodeLabels := make(map[string]string)
	nodeKinds := make(map[string]string)

	// 노드 등록
	var nodeID int64 = 0
	for _, n := range topo.Nodes {
		if _, ok := nodes[n.ID]; !ok {
			node := simple.Node(nodeID)
			g.AddNode(node)
			nodes[n.ID] = node
			reverse[nodeID] = n.ID
			nodeLabels[n.ID] = n.Label
			nodeKinds[n.ID] = n.Kind
			nodeID++
		}
	}

	// 누락된 source/target 노드 추가 (edges에만 있고 topo.Nodes에 없는 경우)
	for _, e := range topo.Edges {
		for _, id := range []string{e.Source, e.Target} {
			if _, ok := nodes[id]; !ok {
				node := simple.Node(nodeID)
				g.AddNode(node)
				nodes[id] = node
				reverse[nodeID] = id
				nodeLabels[id] = id // fallback to ID
				nodeKinds[id] = "unknown"
				nodeID++
			}
		}
	}

// edges 등록 (bidirectional: shares_cve/shares_image 등 양방향 의미 edge 처리)
for _, e := range topo.Edges {
    from := nodes[e.Source]
    to := nodes[e.Target]

    lw, ok := GraphLayerWeight[e.Layer]
    if !ok {
        lw = 0.5
    }
    cost := 1.0 / lw

    // 양방향 등록 (supply_chain.shares_* 같은 대칭 edge)
    // identity.assumes 같은 방향성 edge도 traversal 위해 양방향 처리
    addOrUpdateEdge := func(src, dst graph.Node, c float64) {
        if existing := g.WeightedEdge(src.ID(), dst.ID()); existing != nil {
            if existing.Weight() <= c {
                return
            }
            g.RemoveEdge(src.ID(), dst.ID())
        }
        wedge := g.NewWeightedEdge(src, dst, c)
        g.SetWeightedEdge(wedge)
    }

    addOrUpdateEdge(from, to, cost)
    addOrUpdateEdge(to, from, cost)

    edgeMeta[e.Source+"->"+e.Target] = EdgeMetadata{
        Layer: e.Layer, EdgeType: e.EdgeType, Mode: e.Mode,
        Source: e.Source, Target: e.Target,
    }
    edgeMeta[e.Target+"->"+e.Source] = EdgeMetadata{
        Layer: e.Layer, EdgeType: e.EdgeType, Mode: e.Mode,
        Source: e.Target, Target: e.Source,
    }
}

	return &BlastGraph{
		g:              g,
		nodes:          nodes,
		reverseNodeMap: reverse,
		edges:          edgeMeta,
		nodeLabels:     nodeLabels,
		nodeKinds:      nodeKinds,
	}
}

// Accessors
func (bg *BlastGraph) NodeByID(id string) graph.Node {
	return bg.nodes[id]
}

func (bg *BlastGraph) IDByNode(node graph.Node) string {
	if node == nil {
		return ""
	}
	return bg.reverseNodeMap[node.ID()]
}

func (bg *BlastGraph) Label(id string) string {
	return bg.nodeLabels[id]
}

func (bg *BlastGraph) Kind(id string) string {
	return bg.nodeKinds[id]
}

func (bg *BlastGraph) EdgeLayer(from, to string) string {
	if meta, ok := bg.edges[from+"->"+to]; ok {
		return meta.Layer
	}
	return ""
}

func (bg *BlastGraph) GonumGraph() *simple.WeightedDirectedGraph {
	return bg.g
}

func (bg *BlastGraph) NodeCount() int {
	return len(bg.nodes)
}

// graph_builder.go 끝에 추가
func (bg *BlastGraph) ReverseNodeMap() map[int64]string {
	return bg.reverseNodeMap
}