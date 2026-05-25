package service

import (
	"context"
	"fmt"
	"time"

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
