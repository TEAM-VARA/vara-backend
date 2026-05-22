package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ToxicService는 Toxic Combination 룰을 평가합니다.
//
// 동작:
//  1. 클러스터의 모든 Pod에 대해 신호 수집 (ToxicRepo.LoadSignalsForCluster)
//  2. 각 Pod의 신호에 대해 모든 룰을 평가 (EvaluateToxic)
//  3. 결과를 toxic_results에 저장
//  4. Final Score 재계산 시 multiplier 적용 (FinalScoringService에서)
type ToxicService struct {
	repo *postgres.ToxicRepo
}

// NewToxicService는 ToxicService를 생성합니다.
func NewToxicService(repo *postgres.ToxicRepo) *ToxicService {
	return &ToxicService{repo: repo}
}

// ComputeForCluster는 클러스터의 모든 Pod에 대해 토픽 룰을 평가합니다.
func (s *ToxicService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.ToxicComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	signalsList, err := s.repo.LoadSignalsForCluster(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("load signals: %w", err)
	}

	fmt.Printf("info: toxic evaluating %d pods (cluster=%s)\n", len(signalsList), clusterName)

	results := make([]scoring.ToxicResult, 0, len(signalsList))
	now := time.Now()
	matchedTotal, criticalHits, highHits, mediumHits := 0, 0, 0, 0

	for _, input := range signalsList {
		multiplier, matched := scoring.EvaluateToxic(input.Signals)

		result := scoring.ToxicResult{
			ClusterName:  clusterName,
			PodUID:       input.PodUID,
			PodName:      input.PodName,
			PodNamespace: input.PodNamespace,
			Multiplier:   multiplier,
			MatchedRules: matched,
			Signals:      input.Signals,
			SnapshotAt:   input.SnapshotAt,
			ComputedAt:   now,
		}
		results = append(results, result)

		if multiplier > 1.0 {
			matchedTotal++
			switch {
			case multiplier >= 1.5:
				criticalHits++
			case multiplier >= 1.3:
				highHits++
			case multiplier >= 1.2:
				mediumHits++
			}
		}
	}

	if err := s.repo.UpsertBatch(ctx, clusterName, results); err != nil {
		return nil, fmt.Errorf("save toxic results: %w", err)
	}

	snapAt := now
	if len(results) > 0 {
		snapAt = results[0].SnapshotAt
	}

	return &scoring.ToxicComputeResponse{
		ClusterName:  clusterName,
		SnapshotAt:   snapAt,
		Computed:     len(results),
		MatchedTotal: matchedTotal,
		CriticalHits: criticalHits,
		HighHits:     highHits,
		MediumHits:   mediumHits,
		Details:      results,
	}, nil
}

// ComputeForPod는 단일 Pod의 toxic combination을 계산합니다.
// 대시보드에서 Pod 클릭 시 호출되는 빠른 재계산 API.
func (s *ToxicService) ComputeForPod(ctx context.Context, clusterName, podUID string) (*scoring.ToxicResult, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}
	if podUID == "" {
		return nil, fmt.Errorf("pod_uid is required")
	}

	input, err := s.repo.LoadSignalsByPodUID(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("load signals: %w", err)
	}
	if input == nil {
		return nil, fmt.Errorf("pod not found: cluster=%s pod_uid=%s", clusterName, podUID)
	}

	multiplier, matched := scoring.EvaluateToxic(input.Signals)
	now := time.Now()

	result := scoring.ToxicResult{
		ClusterName:  clusterName,
		PodUID:       input.PodUID,
		PodName:      input.PodName,
		PodNamespace: input.PodNamespace,
		Multiplier:   multiplier,
		MatchedRules: matched,
		Signals:      input.Signals,
		SnapshotAt:   input.SnapshotAt,
		ComputedAt:   now,
	}

	fmt.Printf("info: toxic compute pod cluster=%s pod_uid=%s name=%s multiplier=%.2f matched=%d\n",
		clusterName, podUID, input.PodName, multiplier, len(matched))

	if err := s.repo.UpsertBatch(ctx, clusterName, []scoring.ToxicResult{result}); err != nil {
		return nil, fmt.Errorf("save toxic result: %w", err)
	}

	return &result, nil
}

// GetByPodUID는 단일 Pod의 결과를 반환합니다.
func (s *ToxicService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.ToxicResult, error) {
	return s.repo.GetByPodUID(ctx, clusterName, podUID)
}

// ListByCluster는 클러스터의 모든 결과를 반환합니다.
func (s *ToxicService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.ToxicResult, error) {
	return s.repo.ListByCluster(ctx, clusterName)
}

// LoadMultipliersForCluster는 클러스터의 모든 Pod에 대한 multiplier 맵을 반환합니다.
// FinalScoringService에서 사용.
func (s *ToxicService) LoadMultipliersForCluster(ctx context.Context, clusterName string) (map[string]float64, error) {
	return s.repo.LoadMultipliersForCluster(ctx, clusterName)
}

// GetMultiplierForPod는 단일 Pod의 toxic multiplier를 반환합니다.
// Final ComputeForPod에서 사용. 데이터 없으면 0 반환 (Final 쪽에서 기본값 처리).
func (s *ToxicService) GetMultiplierForPod(ctx context.Context, clusterName, podUID string) (float64, error) {
	return s.repo.GetMultiplier(ctx, clusterName, podUID)
}
