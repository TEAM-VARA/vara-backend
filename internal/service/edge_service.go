package service

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"gonum.org/v1/gonum/graph/network"

	"github.com/vara/backend/internal/domain/edge"
	"github.com/vara/backend/internal/repository/postgres"
)

// ────────────────────────────────────────────────────
// EdgeService — Pod 간 통신 그래프 (Blast Radius) 계산
//
// 흐름:
//   1. ebpf_network_flows에서 최근 N분 데이터 수집
//   2. cluster_pods JOIN으로 src/dst Pod 정보 매핑
//   3. GROUP BY로 (src, dst) 쌍별 통신 횟수 집계
//   4. edges 테이블 upsert
//
// 현재: network layer만 지원
// 추후: identity, supply_chain 추가 예정
// ────────────────────────────────────────────────────

type EdgeService struct {
	repo   *postgres.EdgesRepo
	config edge.AnalysisConfig
}

// NewEdgeService — 기본 설정으로 생성 (5분 윈도우, vara-* 제외)
func NewEdgeService(repo *postgres.EdgesRepo) *EdgeService {
	return &EdgeService{
		repo:   repo,
		config: edge.DefaultConfig(),
	}
}

// ComputeForCluster — 클러스터의 network layer edges 계산
//
// 진행:
//  1. snapshot_at 결정 = 현재 시각
//  2. AggregateFromEBPFFlows로 ebpf 데이터 집계
//  3. UpsertEdges로 결과 저장
//  4. ComputeResponse 반환
//
// 데이터 없을 때 (network_flows 0건):
//   - aggregated 빈 slice
//   - upsert 안 함 (UpsertEdges가 빈 리스트는 즉시 return)
//   - response의 computed = 0
func (s *EdgeService) ComputeForCluster(
	ctx context.Context,
	clusterName string,
) (*edge.ComputeResponse, error) {
	now := time.Now()

	// 1. ebpf_network_flows 집계
	aggregated, processed, skipped, err := s.repo.AggregateFromEBPFFlows(
		ctx, clusterName, s.config.WindowMinutes, s.config.ExcludePodPatterns,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregate flows: %w", err)
	}

	fmt.Printf("info: edges compute for %s — aggregated=%d, processed=%d, skipped=%d\n",
		clusterName, len(aggregated), processed, skipped)

	// 2. edges 저장 (현재 network layer만)
	if len(aggregated) > 0 {
		if err := s.repo.UpsertEdges(ctx, clusterName, edge.LayerNetwork, now, aggregated); err != nil {
			return nil, fmt.Errorf("upsert edges: %w", err)
		}
	}

	return &edge.ComputeResponse{
		ClusterName:    clusterName,
		Computed:       len(aggregated),
		ProcessedFlows: processed,
		SkippedFlows:   skipped,
		SnapshotAt:     now,
		ComputedAt:     now,
	}, nil
}

// ListByCluster는 클러스터의 edges + nodes + meta + summary + toxicCombinations를 반환합니다.
// 보강된 응답 형식 (Blast Radius PDF 5.1~5.4 반영).
func (s *EdgeService) ListByCluster(ctx context.Context, clusterName string) (*edge.EdgeListResponse, error) {
	start := time.Now()

	// 1. edges (기존)
	edges, err := s.repo.ListByCluster(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("list edges: %w", err)
	}

	// 2. nodes (보강) — 실패해도 응답 계속, 빈 배열로 처리
	nodes, err := s.repo.ListNodes(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: list nodes failed: %v\n", err)
		nodes = []edge.NodeView{}
	}

	// 3. summary (보강)
	summary, err := s.repo.ComputeSummary(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: compute summary failed: %v\n", err)
		summary = &edge.EdgesSummary{}
	}

	// 4. toxic combinations (보강)
	toxics, err := s.repo.ListToxicCombinations(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: list toxic combinations failed: %v\n", err)
		toxics = []edge.ToxicCombination{}
	}

	// snapshot_at: 가장 최근 edge 또는 현재 시간
	snapAt := time.Now()
	if len(edges) > 0 {
		snapAt = edges[0].SnapshotAt
	}

	if nodes == nil {
		nodes = []edge.NodeView{}
	}
	if toxics == nil {
		toxics = []edge.ToxicCombination{}
	}

	return &edge.EdgeListResponse{
		Total: len(edges),
		Edges: edges,
		Nodes: nodes,
		Meta: &edge.EdgesMeta{
			Cluster:         clusterName,
			SnapshotAt:      snapAt,
			ComputedAt:      time.Now(),
			BuildDurationMs: time.Since(start).Milliseconds(),
			NodeCount:       len(nodes),
			EdgeCount:       len(edges),
		},
		Summary:           summary,
		ToxicCombinations: toxics,
	}, nil
}

// ListByPod — 특정 Pod 관련 edges (source 또는 target)
//
// 사용처:
//   - 특정 Pod 클릭 시 연결된 통신 관계만 표시 (focus view)
func (s *EdgeService) ListByPod(ctx context.Context, clusterName, podUID string) (*edge.EdgeListResponse, error) {
	edges, err := s.repo.ListByPod(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("list edges by pod: %w", err)
	}
	return &edge.EdgeListResponse{
		Total: len(edges),
		Edges: edges,
	}, nil
}

// ComputeIdentity는 클러스터의 RBAC 정보로 identity layer edges를 적재합니다.
func (s *EdgeService) ComputeIdentity(ctx context.Context, clusterName string) (*edge.IdentityComputeResult, error) {
	return s.repo.ComputeIdentityEdges(ctx, clusterName)
}

// ComputeSupplyChain은 SBOM/CVE 정보로 supply_chain layer edges를 적재합니다.
func (s *EdgeService) ComputeSupplyChain(ctx context.Context, clusterName string) (*edge.SupplyChainComputeResult, error) {
	return s.repo.ComputeSupplyChainEdges(ctx, clusterName)
}

// ComputeNetwork는 network layer edges (selected_by, allows, routed_by, namespace_cross) 적재
func (s *EdgeService) ComputeNetwork(ctx context.Context, clusterName string) (*edge.NetworkComputeResult, error) {
	return s.repo.ComputeNetworkEdges(ctx, clusterName)
}

// BuildTopology — PM 명세서 B-1 (/api/v1/topology)
func (s *EdgeService) BuildTopology(ctx context.Context, cluster string) (*edge.TopologyResponse, error) {
	return s.repo.BuildTopology(ctx, cluster)
}

// ────────────────────────────────────────────────────
// Blast Radius (BFS K-Hop) — PM 명세서 B-2
// ────────────────────────────────────────────────────

// 레이어별 가중치 (PM 명세서)
var layerWeight = map[string]float64{
	"network":      1.0,
	"identity":     0.85,
	"supply_chain": 0.7,
	"host":         0.5,
}

// 인접 리스트 edge
type adjEdge struct {
	target string
	layer  string
}

// buildAdjacency: topology edges로부터 인접 리스트 구축
func buildAdjacency(edges []edge.TopologyEdge) map[string][]adjEdge {
	adj := make(map[string][]adjEdge)
	for _, e := range edges {
		adj[e.Source] = append(adj[e.Source], adjEdge{
			target: e.Target,
			layer:  e.Layer,
		})
		// 양방향 traversal (supply_chain 같은 양방향 edge 고려)
		adj[e.Target] = append(adj[e.Target], adjEdge{
			target: e.Source,
			layer:  e.Layer,
		})
	}
	return adj
}

// bfsKHop: source에서 maxHops 내 도달 가능한 모든 노드 + 첫 hop의 layer
func bfsKHop(adj map[string][]adjEdge, source string, maxHops int) []edge.ReachableNode {
	type visitInfo struct {
		hop   int
		layer string
	}
	visited := map[string]visitInfo{source: {hop: 0, layer: ""}}
	queue := []string{source}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentHop := visited[current].hop
		if currentHop >= maxHops {
			continue
		}

		for _, e := range adj[current] {
			if _, ok := visited[e.target]; !ok {
				visited[e.target] = visitInfo{
					hop:   currentHop + 1,
					layer: e.layer,
				}
				queue = append(queue, e.target)
			}
		}
	}

	reachable := make([]edge.ReachableNode, 0, len(visited)-1)
	for nodeID, info := range visited {
		if info.hop == 0 {
			continue // source 자기 자신 제외
		}
		reachable = append(reachable, edge.ReachableNode{
			NodeID: nodeID,
			Hop:    info.hop,
			Layer:  info.layer,
		})
	}

	// hop 오름차순, 같은 hop이면 layer 알파벳순
	sort.Slice(reachable, func(i, j int) bool {
		if reachable[i].Hop != reachable[j].Hop {
			return reachable[i].Hop < reachable[j].Hop
		}
		return reachable[i].Layer < reachable[j].Layer
	})

	return reachable
}

// computeBlastScore: Σ (0.6^(hop-1) × layerWeight × criticality)
func computeBlastScore(reachable []edge.ReachableNode) float64 {
	score := 0.0
	for _, r := range reachable {
		decay := math.Pow(0.6, float64(r.Hop-1))
		lw, ok := layerWeight[r.Layer]
		if !ok {
			lw = 0.5 // 미지정 layer 기본값
		}
		crit := 1.0 // 기본 criticality (현재 데이터에 criticality 없음)
		score += decay * lw * crit
	}
	return math.Min(25.0, score)
}

// BuildBlastRadius: source Pod에서 maxHops 내 영향 범위 계산
func (s *EdgeService) BuildBlastRadius(ctx context.Context, cluster, source string, hops int) (*edge.BlastRadiusResponse, error) {
	start := time.Now()

	// 1. topology 데이터 가져오기
	topo, err := s.repo.BuildTopology(ctx, cluster)
	if err != nil {
		return nil, err
	}

	// 2. 인접 리스트 빌드
	adj := buildAdjacency(topo.Edges)

	// 3. BFS K-hop
	reachable := bfsKHop(adj, source, hops)

	// 4. 노드 이름/종류 매핑
	nameMap := make(map[string]string, len(topo.Nodes))
	kindMap := make(map[string]string, len(topo.Nodes))
	for _, n := range topo.Nodes {
		nameMap[n.ID] = n.Label
		kindMap[n.ID] = n.Kind
	}
	for i := range reachable {
		reachable[i].NodeName = nameMap[reachable[i].NodeID]
		reachable[i].NodeKind = kindMap[reachable[i].NodeID]
	}

	// 5. Blast score
	score := computeBlastScore(reachable)

	// 6. by_layer 카운트
	byLayer := make(map[string]int)
	for _, r := range reachable {
		byLayer[r.Layer]++
	}

	return &edge.BlastRadiusResponse{
		Source:     source,
		Hops:       hops,
		BlastScore: score,
		OutOf:      25.0,
		Reachable:  reachable,
		TotalCount: len(reachable),
		ByLayer:    byLayer,
		BuildMs:    time.Since(start).Milliseconds(),
	}, nil
}

// computePageRank: gonum의 진짜 PageRank 알고리즘 사용
func computePageRank(bg *BlastGraph) map[string]float64 {
	g := bg.GonumGraph()

	// 표준 PageRank: damp=0.85, tol=1e-6
	scores := network.PageRank(g, 0.85, 1e-6)

	// gonum int64 nodeID → 우리 string ID
	results := make(map[string]float64, len(scores))
	for nodeID, score := range scores {
		results[bg.reverseNodeMap[nodeID]] = score
	}
	return results
}

// BuildCriticality: PageRank로 노드 중요도 계산 + Top N 반환
func (s *EdgeService) BuildCriticality(ctx context.Context, cluster string, topN int) (*edge.CriticalityResponse, error) {
	start := time.Now()

	topo, err := s.repo.BuildTopology(ctx, cluster)
	if err != nil {
		return nil, err
	}

	bg := BuildBlastGraph(topo)
	scores := computePageRank(bg)

	// 노드별 메타데이터 매핑
	namespaceMap := make(map[string]string, len(topo.Nodes))
	for _, n := range topo.Nodes {
		namespaceMap[n.ID] = n.Namespace
	}

	// 점수 순으로 정렬
	criticalities := make([]edge.NodeCriticality, 0, len(scores))
	for nodeID, score := range scores {
		label := bg.Label(nodeID)
		if label == "" {
			label = nodeID
		}
		criticalities = append(criticalities, edge.NodeCriticality{
			NodeID:    nodeID,
			NodeKind:  bg.Kind(nodeID),
			NodeName:  label,
			Namespace: namespaceMap[nodeID],
			Score:     score,
		})
	}

	sort.Slice(criticalities, func(i, j int) bool {
		return criticalities[i].Score > criticalities[j].Score
	})

	// Rank 부여
	for i := range criticalities {
		criticalities[i].Rank = i + 1
	}

	// Top N만 반환
	if topN > 0 && topN < len(criticalities) {
		criticalities = criticalities[:topN]
	}

	return &edge.CriticalityResponse{
		Cluster:   cluster,
		TopN:      topN,
		Nodes:     criticalities,
		Algorithm: "pagerank (damp=0.85, tol=1e-6)",
		BuildMs:   time.Since(start).Milliseconds(),
	}, nil
}

// ────────────────────────────────────────────────────
// Union-Find (자체 구현, path compression + union by rank)
// ────────────────────────────────────────────────────

type UnionFind struct {
	parent map[string]string
	rank   map[string]int
}

func NewUnionFind() *UnionFind {
	return &UnionFind{
		parent: make(map[string]string),
		rank:   make(map[string]int),
	}
}

// MakeSet: 새 요소 추가
func (uf *UnionFind) MakeSet(x string) {
	if _, exists := uf.parent[x]; exists {
		return
	}
	uf.parent[x] = x
	uf.rank[x] = 0
}

// Find: 루트 찾기 (path compression)
func (uf *UnionFind) Find(x string) string {
	if uf.parent[x] != x {
		uf.parent[x] = uf.Find(uf.parent[x]) // 경로 압축
	}
	return uf.parent[x]
}

// Union: 두 집합 합치기 (union by rank)
func (uf *UnionFind) Union(x, y string) {
	rootX := uf.Find(x)
	rootY := uf.Find(y)
	if rootX == rootY {
		return
	}

	if uf.rank[rootX] < uf.rank[rootY] {
		uf.parent[rootX] = rootY
	} else if uf.rank[rootX] > uf.rank[rootY] {
		uf.parent[rootY] = rootX
	} else {
		uf.parent[rootY] = rootX
		uf.rank[rootX]++
	}
}

// Groups: 모든 그룹 반환 (root → members)
func (uf *UnionFind) Groups() map[string][]string {
	groups := make(map[string][]string)
	for x := range uf.parent {
		root := uf.Find(x)
		groups[root] = append(groups[root], x)
	}
	return groups
}

// BuildPodClusters: Union-Find로 Pod 그룹화
func (s *EdgeService) BuildPodClusters(ctx context.Context, cluster, groupBy string) (*edge.ClustersResponse, error) {
	start := time.Now()

	topo, err := s.repo.BuildTopology(ctx, cluster)
	if err != nil {
		return nil, err
	}

	uf := NewUnionFind()

	// Pod 노드만 MakeSet
	podLabels := make(map[string]string)
	for _, n := range topo.Nodes {
		if n.Kind == "pod" {
			uf.MakeSet(n.ID)
			podLabels[n.ID] = n.Label
		}
	}

	// 지정된 edge_type으로 Union
	var targetEdgeType string
	switch groupBy {
	case "image":
		targetEdgeType = "shares_image"
	case "cve":
		targetEdgeType = "shares_cve"
	default:
		targetEdgeType = "shares_image"
	}

	for _, e := range topo.Edges {
		if e.EdgeType != targetEdgeType {
			continue
		}
		// 양쪽 다 Pod인지 확인
		if _, ok := podLabels[e.Source]; !ok {
			continue
		}
		if _, ok := podLabels[e.Target]; !ok {
			continue
		}
		uf.Union(e.Source, e.Target)
	}

	// 그룹화 결과 정리
	rawGroups := uf.Groups()

	groups := make([]edge.PodGroup, 0, len(rawGroups))
	groupID := 1
	totalPods := 0
	largestGroup := 0
	singletonCount := 0

	for _, members := range rawGroups {
		if len(members) == 1 {
			singletonCount++
			continue // 1개짜리는 제외 (선택)
		}
		labels := make([]string, len(members))
		for i, podID := range members {
			labels[i] = podLabels[podID]
		}
		// 라벨 정렬
		sort.Strings(labels)
		sort.Strings(members)

		groups = append(groups, edge.PodGroup{
			GroupID:   groupID,
			Size:      len(members),
			PodIDs:    members,
			PodLabels: labels,
		})
		totalPods += len(members)
		if len(members) > largestGroup {
			largestGroup = len(members)
		}
		groupID++
	}

	// size 큰 순으로 정렬
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Size > groups[j].Size
	})

	// 재번호화
	for i := range groups {
		groups[i].GroupID = i + 1
	}

	return &edge.ClustersResponse{
		Cluster:        cluster,
		GroupBy:        groupBy,
		TotalGroups:    len(groups),
		TotalPods:      totalPods,
		LargestGroup:   largestGroup,
		SingletonCount: singletonCount,
		Groups:         groups,
		BuildMs:        time.Since(start).Milliseconds(),
	}, nil
}
