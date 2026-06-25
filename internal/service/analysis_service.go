package service

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vara/backend/internal/domain/edge"
	"github.com/vara/backend/internal/repository/postgres"
)

// 가독성을 위한 별칭
type edgeTopology = edge.TopologyResponse

// AnalysisService는 그래프 분석 알고리즘을 백그라운드에서 사전 계산하고
// 결과를 캐시 테이블에 저장합니다.
//
// 사전 계산 대상:
//   - BFS Blast Radius (모든 Pod)
//   - PageRank (전역)
//   - Betweenness (전역)
//   - Dijkstra (외부→critical, Phase 2d-2에서 추가)
type AnalysisService struct {
	edgeRepo  *postgres.EdgesRepo
	cacheRepo *postgres.AnalysisCacheRepo
	pool      *pgxpool.Pool
}

func NewAnalysisService(
	edgeRepo *postgres.EdgesRepo,
	cacheRepo *postgres.AnalysisCacheRepo,
	pool *pgxpool.Pool,
) *AnalysisService {
	return &AnalysisService{
		edgeRepo:  edgeRepo,
		cacheRepo: cacheRepo,
		pool:      pool,
	}
}

// PrecomputeAll은 클러스터의 모든 그래프 분석을 사전 계산하고 캐시에 저장합니다.
func (s *AnalysisService) PrecomputeAll(ctx context.Context, cluster string) error {
	start := time.Now()
	log.Printf("analysis: precompute starting for cluster=%s", cluster)

	// 0. edges 최신화 (snapshot 불일치 방지) ⭐
	if err := s.refreshEdges(ctx, cluster); err != nil {
		log.Printf("analysis: edge refresh failed: %v", err)
		// 계속 진행 (기존 edges로라도)
	}

	// 1. Topology 한 번만 로드 (모든 알고리즘이 재활용)
	topo, err := s.edgeRepo.BuildTopology(ctx, cluster)
	if err != nil {
		return fmt.Errorf("build topology: %w", err)
	}
	if len(topo.Nodes) == 0 {
		log.Printf("analysis: no nodes in cluster=%s, skip", cluster)
		return nil
	}

	// 2. BFS Blast Radius (모든 Pod)
	if err := s.precomputeBlastRadius(ctx, cluster, topo); err != nil {
		log.Printf("analysis: blast radius failed: %v", err)
	}

	// 2.5. Total Risk (blast_edges 기반 MC) — pod_blast_radius row가 있어야 UPDATE되므로 뒤에 ⭐
	if err := s.precomputeBlastPairs(ctx, cluster); err != nil {
		log.Printf("analysis: blast_pair_risk failed: %v", err)
	}

	// 3. PageRank + Betweenness (전역)
	if err := s.precomputeCentrality(ctx, cluster, topo); err != nil {
		log.Printf("analysis: centrality failed: %v", err)
	}

	// 4. Dijkstra (외부→critical) — centrality 결과 활용하므로 뒤에
	if err := s.precomputeAttackPaths(ctx, cluster, topo); err != nil {
		log.Printf("analysis: attack paths failed: %v", err)
	}

	log.Printf("analysis: precompute done for cluster=%s, duration=%v", cluster, time.Since(start))
	return nil
}

// ─────────────────────────────────────────
// BFS Blast Radius (모든 Pod)
// ─────────────────────────────────────────

func (s *AnalysisService) precomputeBlastRadius(ctx context.Context, cluster string, topo *edgeTopology) error {
	// 인접 리스트 한 번만 빌드 (모든 Pod가 공유)
	adj := buildAdjacency(topo.Edges)

	// 노드 이름/종류 매핑
	kindMap := make(map[string]string, len(topo.Nodes))
	for _, n := range topo.Nodes {
		kindMap[n.ID] = n.Kind
	}

	const maxHops = 3
	var rows []postgres.BlastRadiusRow

	for _, node := range topo.Nodes {
		// Pod 노드만 (sa, role 등 제외)
		if node.Kind != "pod" {
			continue
		}

		reachable := bfsKHop(adj, node.ID, maxHops)
		score := computeBlastScore(reachable)

		// reachable pod ID 추출 + by_layer 집계
		reachablePods := make([]string, 0, len(reachable))
		byLayer := make(map[string]int)
		for _, r := range reachable {
			reachablePods = append(reachablePods, r.NodeID)
			byLayer[r.Layer]++
		}

		rows = append(rows, postgres.BlastRadiusRow{
			PodUID:         node.ID,
			ReachableCount: len(reachable),
			ReachablePods:  reachablePods,
			BlastScore:     score,
			ByLayer:        byLayer,
		})
	}

	if err := s.cacheRepo.UpsertBlastRadiusBatch(ctx, cluster, rows); err != nil {
		return fmt.Errorf("upsert blast radius: %w", err)
	}

	log.Printf("analysis: blast radius computed for %d pods", len(rows))
	return nil
}

// ─────────────────────────────────────────
// PageRank + Betweenness (전역)
// ─────────────────────────────────────────

func (s *AnalysisService) precomputeCentrality(ctx context.Context, cluster string, topo *edgeTopology) error {
	bg := BuildBlastGraph(topo)

	pageranks := computePageRank(bg)
	betweenness := computeBetweenness(bg)

	// 두 점수를 노드별로 병합
	rows := make([]postgres.CentralityRow, 0, len(pageranks))
	for nodeID, pr := range pageranks {
		rows = append(rows, postgres.CentralityRow{
			NodeID:      nodeID,
			Label:       bg.Label(nodeID),
			Kind:        bg.Kind(nodeID),
			PageRank:    pr,
			Betweenness: betweenness[nodeID], // 없으면 0
		})
	}

	if err := s.cacheRepo.UpsertCentralityBatch(ctx, cluster, rows); err != nil {
		return fmt.Errorf("upsert centrality: %w", err)
	}

	log.Printf("analysis: centrality computed for %d nodes", len(rows))
	return nil
}

// ─────────────────────────────────────────
// Dijkstra 최단 공격 경로 (외부 → critical asset)
// ─────────────────────────────────────────

const (
	criticalAssetCount = 20 // PageRank 상위 N개를 critical asset으로
)

func (s *AnalysisService) precomputeAttackPaths(ctx context.Context, cluster string, topo *edgeTopology) error {
	// 1. critical asset 식별 (PageRank 상위 N개)
	topCritical, err := s.cacheRepo.GetTopByPageRank(ctx, cluster, criticalAssetCount)
	if err != nil {
		return fmt.Errorf("get critical assets: %w", err)
	}
	if len(topCritical) == 0 {
		log.Printf("analysis: no critical assets, skip attack paths")
		return nil
	}

	criticalIDs := make([]string, 0, len(topCritical))
	criticalSet := make(map[string]bool, len(topCritical))
	for _, c := range topCritical {
		criticalIDs = append(criticalIDs, c.NodeID)
		criticalSet[c.NodeID] = true
	}

	// 2. BlastGraph 빌드 (Dijkstra용)
	bg := BuildBlastGraph(topo)

	// 3. 각 Pod source에서 critical asset까지 최단 경로
	var rows []postgres.AttackPathRow

	for _, node := range topo.Nodes {
		if node.Kind != "pod" {
			continue
		}
		// source 자신이 critical이면 skip (자기 자신 경로 무의미)
		// dijkstraToCriticalAssets가 hop<2 필터하므로 안전

		paths := dijkstraToCriticalAssets(bg, node.ID, criticalIDs)
		for _, p := range paths {
			// source == target 제외 (이미 hop>=1 필터됨)
			if p.SourceID == p.TargetID {
				continue
			}
			rows = append(rows, postgres.AttackPathRow{
				SourceID:  p.SourceID,
				TargetID:  p.TargetID,
				Nodes:     p.Nodes,
				Labels:    p.Labels,
				Layers:    p.Layers,
				TotalCost: p.TotalCost,
				Hops:      p.Hops,
			})
		}
	}

	if err := s.cacheRepo.UpsertAttackPathBatch(ctx, cluster, rows); err != nil {
		return fmt.Errorf("upsert attack paths: %w", err)
	}

	log.Printf("analysis: attack paths computed (%d paths to %d critical assets)",
		len(rows), len(criticalIDs))
	return nil
}

// refreshEdges는 분석 전 edges를 최신 pod snapshot으로 재계산합니다.
// (snapshot 불일치로 BFS/Dijkstra가 0이 되는 문제 방지)
func (s *AnalysisService) refreshEdges(ctx context.Context, cluster string) error {
	if _, err := s.edgeRepo.ComputeIdentityEdges(ctx, cluster); err != nil {
		return fmt.Errorf("identity edges: %w", err)
	}
	if _, err := s.edgeRepo.ComputeSupplyChainEdges(ctx, cluster); err != nil {
		return fmt.Errorf("supply chain edges: %w", err)
	}
	if _, err := s.edgeRepo.ComputeNetworkEdges(ctx, cluster); err != nil {
		return fmt.Errorf("network edges: %w", err)
	}
	log.Printf("analysis: edges refreshed for cluster=%s", cluster)
	return nil
}

// PrecomputeIfStale은 새 데이터가 있을 때만 재계산합니다.
// 반환: (재계산했는지, error)
func (s *AnalysisService) PrecomputeIfStale(ctx context.Context, cluster string) (bool, error) {
	latestData, err := s.edgeRepo.LatestPodSnapshot(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("latest snapshot: %w", err)
	}
	lastComputed, err := s.cacheRepo.LastComputedAt(ctx, cluster)
	if err != nil {
		return false, fmt.Errorf("last computed: %w", err)
	}

	// 캐시가 최신 데이터를 이미 반영했으면 skip
	if lastComputed.After(latestData) {
		return false, nil
	}

	// 새 데이터 있음 → 재계산
	if err := s.PrecomputeAll(ctx, cluster); err != nil {
		return false, err
	}
	return true, nil
}

// precomputeBlastPairs는 각 소스 파드 → 도달 노드까지의 전파 위험도(reach_prob, A→B)를
// (src,dst) 쌍으로 blast_pair_risk에 저장합니다.
// orbital이 소스 1개에 대해 즉석 계산하는 reach_prob를 전체 소스에 대해 미리 계산 →
// "가장 위험한 경로 top N" 쿼리 가능.
func (s *AnalysisService) precomputeBlastPairs(ctx context.Context, cluster string) error {
	edges, err := LoadBlastEdges(ctx, s.pool, cluster)
	if err != nil {
		return fmt.Errorf("load blast_edges: %w", err)
	}
	if len(edges) == 0 {
		return nil
	}

	// 소스 파드 목록 (pod_blast_radius에 파드들이 이미 있음)
	rows, err := s.pool.Query(ctx, `SELECT pod_uid FROM pod_blast_radius WHERE cluster_name=$1`, cluster)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	var srcs []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return err
		}
		srcs = append(srcs, uid)
	}
	rows.Close()

	// src/dst uid → name (edges에서 직접; cluster_pods JOIN 불필요)
	nameByUID := make(map[string]string)
	for _, e := range edges {
		if e.SourceName != "" {
			nameByUID[e.SourceUID] = e.SourceName
		}
		if e.TargetName != "" {
			nameByUID[e.TargetUID] = e.TargetName
		}
	}

	// (src, dst, reach_prob, total_risk) 모으기 — reach_prob = MC 도달확률(닿은 시행수/전체 시행수)
	// total_risk = Σ_B reachProb(A→B) = MC 총위험도(소스 단위 동일값, 각 행에 중복 적재)
	const mcTrials = 5000
	var batch [][]any
	for i, src := range srcs {
		rng := rand.New(rand.NewSource(int64(i) + 1)) // 소스별 고정 시드 → 재현성
		reachMC := ComputeReachProbMC(edges, src, mcTrials, rng)
		var totalRisk float64
		for _, p := range reachMC {
			totalRisk += p
		}
		for dst, p := range reachMC {
			if dst == src || p <= 0 {
				continue
			}
			dstName := nameByUID[dst]
			if dstName == "" {
				dstName = shortUID(dst) // 같은 패키지(blast_graph_service.go)에 정의됨
			}
			batch = append(batch, []any{
				cluster, src, dst, p,
				nameByUID[src], // src_pod_name (없으면 "")
				dstName,        // dst_pod_name
				totalRisk,      // total_risk (소스 단위 동일값)
			})
		}
	}

	// 전체 재계산이므로 이 클러스터 행 갈아엎고 새로 적재
	if _, err := s.pool.Exec(ctx, `DELETE FROM blast_pair_risk WHERE cluster_name=$1`, cluster); err != nil {
		return fmt.Errorf("clear pairs: %w", err)
	}
	if len(batch) > 0 {
		if _, err := s.pool.CopyFrom(ctx,
			pgx.Identifier{"blast_pair_risk"},
			[]string{"cluster_name", "src_pod_uid", "dst_pod_uid", "reach_prob", "src_pod_name", "dst_pod_name", "total_risk"},
			pgx.CopyFromRows(batch),
		); err != nil {
			return fmt.Errorf("copy pairs: %w", err)
		}
	}
	log.Printf("analysis: blast_pair_risk computed (%d pairs, %d sources, cluster=%s)", len(batch), len(srcs), cluster)
	return nil
}