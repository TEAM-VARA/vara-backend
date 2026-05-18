package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// LocalScoringService는 Local Score 통합 계산을 담당합니다.
//
// 알고리즘:
//   1. cluster_pods 최신 snapshot 기준으로 Pod 목록 로드
//   2. 각 Pod의 exposure_scores + attack_path_scores 최신 점수 LEFT JOIN
//   3. 두 점수를 가산 공식으로 통합
//   4. local_scores에 저장
//
// 누락 처리:
//   - exposure 점수 없음 → exposure_contribution = 0
//   - attack_path 점수 없음 → attack_path_contribution = 0
//   - 둘 다 없음 → local_score = 0 (의미 없는 결과지만 row는 생성)
type LocalScoringService struct {
	repo *postgres.LocalScoringRepo
}

// NewLocalScoringService는 LocalScoringService를 생성합니다.
func NewLocalScoringService(repo *postgres.LocalScoringRepo) *LocalScoringService {
	return &LocalScoringService{repo: repo}
}

// ComputeForCluster는 클러스터의 모든 Pod에 대해 Local Score를 계산하고 저장합니다.
func (s *LocalScoringService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.LocalComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	// 1. 두 원본 점수를 한 번에 조회 (cluster_pods 기준)
	sources, err := s.repo.LoadSourceScores(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("load source scores: %w", err)
	}

	fmt.Printf("info: local computing for %d pods (cluster=%s)\n", len(sources), clusterName)

	// 2. 각 Pod에 대해 Local Score 계산
	results := make([]scoring.LocalScoreResult, 0, len(sources))
	now := time.Now()
	high, medium, low := 0, 0, 0
	missingExposure, missingAttackPath := 0, 0

	// snapshot_at 기준: 두 점수의 snapshot 중 더 최근 시점 사용
	// 둘 다 없으면 now
	for _, src := range sources {
		exposureRaw := 0
		exposed := false
		if src.HasExposure {
			exposureRaw = src.ExposureScoreRaw
			exposed = src.Exposed
		} else {
			missingExposure++
		}

		apRaw := 0
		apLevel := "Minimal"
		if src.HasAttackPath {
			apRaw = src.AttackPathScoreRaw
			apLevel = src.AttackPathLevel
			if apLevel == "" {
				apLevel = "Minimal"
			}
		} else {
			missingAttackPath++
		}

		// 점수 계산
		localScore, expContrib, apContrib := scoring.ComputeLocalScore(exposureRaw, apRaw)
		level := scoring.ClassifyLocalLevel(localScore)

		// snapshot_at: 두 원본 중 가장 늦은 시점, 없으면 now
		snapAt := now
		if src.HasExposure && src.HasAttackPath {
			snapAt = src.ExposureSnapshotAt
			if src.AttackPathSnapshotAt.After(snapAt) {
				snapAt = src.AttackPathSnapshotAt
			}
		} else if src.HasExposure {
			snapAt = src.ExposureSnapshotAt
		} else if src.HasAttackPath {
			snapAt = src.AttackPathSnapshotAt
		}

		result := scoring.LocalScoreResult{
			ClusterName:            clusterName,
			PodUID:                 src.PodUID,
			PodName:                src.PodName,
			PodNamespace:           src.PodNamespace,
			LocalScore:             localScore,
			LocalLevel:             level,
			ExposureContribution:   expContrib,
			AttackPathContribution: apContrib,
			ExposureScoreRaw:       exposureRaw,
			AttackPathScoreRaw:     apRaw,
			Exposed:                exposed,
			AttackPathLevel:        apLevel,
			SnapshotAt:             snapAt,
			ComputedAt:             now,
		}

		// 등급 카운트
		switch {
		case localScore >= 70:
			high++
		case localScore >= 40:
			medium++
		case localScore > 0:
			low++
		}

		results = append(results, result)
	}

	// 3. 저장
	if err := s.repo.UpsertBatch(ctx, results); err != nil {
		return nil, fmt.Errorf("save results: %w", err)
	}

	// 4. 누락 경고
	if missingExposure > 0 {
		fmt.Printf("warn: %d pods missing exposure score (run POST /scoring/exposure/compute first)\n", missingExposure)
	}
	if missingAttackPath > 0 {
		fmt.Printf("warn: %d pods missing attack_path score (run POST /scoring/attack-path/compute first)\n", missingAttackPath)
	}

	// snapshot_at: 가장 최근 결과의 것 사용 (없으면 now)
	resultSnapshot := now
	if len(results) > 0 {
		resultSnapshot = results[0].SnapshotAt
		for _, r := range results {
			if r.SnapshotAt.After(resultSnapshot) {
				resultSnapshot = r.SnapshotAt
			}
		}
	}

	return &scoring.LocalComputeResponse{
		ClusterName:       clusterName,
		SnapshotAt:        resultSnapshot,
		Computed:          len(results),
		HighRisk:          high,
		MediumRisk:        medium,
		LowRisk:           low,
		Details:           results,
		MissingExposure:   missingExposure,
		MissingAttackPath: missingAttackPath,
	}, nil
}

// GetByPodUID는 단일 Pod의 결과를 조회합니다.
func (s *LocalScoringService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.LocalScoreResult, error) {
	return s.repo.GetByPodUID(ctx, clusterName, podUID)
}

// ListByCluster는 클러스터 결과를 모두 반환합니다.
func (s *LocalScoringService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.LocalScoreResult, error) {
	return s.repo.ListByCluster(ctx, clusterName)
}
