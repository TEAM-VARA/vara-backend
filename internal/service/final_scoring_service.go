package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// FinalScoringService는 Final Score 통합 계산을 담당합니다.
//
// 알고리즘:
//   1. FinalScoringRepo.LoadInputsForCluster로 모든 입력 한 번에 조회
//   2. ToxicService.LoadMultipliersForCluster로 multiplier 맵 로드 (없으면 1.0)
//   3. 각 Pod에 대해:
//      a. 가장 위험한 컨테이너 이미지 채택 (max_score 최대)
//      b. Local Score 가져오기
//      c. Toxic Multiplier 적용 (없으면 1.0)
//      d. Final = (0.6 × Global + 0.4 × Local) × Toxic
//   4. final_scores에 저장
type FinalScoringService struct {
	repo         *postgres.FinalScoringRepo
	toxicService *ToxicService // 작업 B-4. nil이면 multiplier=1.0 고정.
}

// NewFinalScoringService는 FinalScoringService를 생성합니다.
// toxicSvc는 nil이어도 됩니다 (작업 B-4 비활성화 시 multiplier=1.0).
func NewFinalScoringService(repo *postgres.FinalScoringRepo, toxicSvc *ToxicService) *FinalScoringService {
	return &FinalScoringService{
		repo:         repo,
		toxicService: toxicSvc,
	}
}

// ComputeForCluster는 클러스터의 모든 Pod에 대해 Final Score를 계산합니다.
func (s *FinalScoringService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.FinalComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	inputs, err := s.repo.LoadInputsForCluster(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("load inputs: %w", err)
	}

	// Toxic multiplier 일괄 로드 (작업 B-4)
	multipliers := map[string]float64{}
	if s.toxicService != nil {
		m, err := s.toxicService.LoadMultipliersForCluster(ctx, clusterName)
		if err != nil {
			fmt.Printf("warn: load toxic multipliers failed: %v (using 1.0)\n", err)
		} else {
			multipliers = m
		}
	}

	fmt.Printf("info: final computing for %d pods (cluster=%s, toxic_loaded=%d)\n",
		len(inputs), clusterName, len(multipliers))

	results := make([]scoring.FinalScoreResult, 0, len(inputs))
	now := time.Now()
	criticalRisk, highRisk, mediumRisk, lowRisk := 0, 0, 0, 0
	missingGI, missingL, missingSBOM := 0, 0, 0

	for _, input := range inputs {
		// toxic multiplier (없으면 1.0)
		toxic, ok := multipliers[input.PodUID]
		if !ok || toxic <= 0 {
			toxic = scoring.FinalDefaultToxicMultiplier
		}

		result := s.computePod(input, clusterName, now, toxic)

		switch {
		case result.FinalScore >= 90:
			criticalRisk++
		case result.FinalScore >= 70:
			highRisk++
		case result.FinalScore >= 40:
			mediumRisk++
		case result.FinalScore > 0:
			lowRisk++
		}

		if result.MissingGlobalImage {
			missingGI++
		}
		if result.MissingLocal {
			missingL++
		}
		if result.MissingSBOM {
			missingSBOM++
		}

		results = append(results, result)
	}

	if err := s.repo.UpsertBatch(ctx, results); err != nil {
		return nil, fmt.Errorf("save results: %w", err)
	}

	if missingGI > 0 {
		fmt.Printf("warn: %d pods missing image_global_score\n", missingGI)
	}
	if missingL > 0 {
		fmt.Printf("warn: %d pods missing local_score\n", missingL)
	}
	if missingSBOM > 0 {
		fmt.Printf("warn: %d pods have containers without SBOM\n", missingSBOM)
	}

	snapAt := now
	if len(results) > 0 {
		snapAt = results[0].SnapshotAt
	}

	return &scoring.FinalComputeResponse{
		ClusterName:        clusterName,
		SnapshotAt:         snapAt,
		Computed:           len(results),
		CriticalRisk:       criticalRisk,
		HighRisk:           highRisk,
		MediumRisk:         mediumRisk,
		LowRisk:            lowRisk,
		MissingGlobalImage: missingGI,
		MissingLocal:       missingL,
		MissingSBOM:        missingSBOM,
		Details:            results,
	}, nil
}

// computePod는 단일 Pod의 Final Score를 계산합니다.
//
//	toxic: 이 Pod의 Toxic Multiplier (없으면 1.0)
func (s *FinalScoringService) computePod(input postgres.PodFinalInput, clusterName string, now time.Time, toxic float64) scoring.FinalScoreResult {
	result := scoring.FinalScoreResult{
		ClusterName:     clusterName,
		PodUID:          input.PodUID,
		PodName:         input.PodName,
		PodNamespace:    input.PodNamespace,
		ToxicMultiplier: toxic,
		SnapshotAt:      input.PodSnapshotAt,
		ComputedAt:      now,
	}

	// 1. 가장 위험한 컨테이너 채택
	var (
		hasAnyContainer bool
		hasAnySBOM      bool
		hasAnyGlobal    bool
		maxGlobalScore  float64
		usedDigest      string
		usedTag         string
		usedTopCVE      string
	)

	for _, c := range input.Containers {
		hasAnyContainer = true
		if c.HasSBOM {
			hasAnySBOM = true
		}
		if c.HasGlobal && c.MaxScore >= maxGlobalScore {
			hasAnyGlobal = true
			maxGlobalScore = c.MaxScore
			usedDigest = c.ImageDigest
			usedTag = c.ImageTag
			usedTopCVE = c.TopCVE
		}
	}

	if !hasAnyContainer || !hasAnySBOM {
		result.MissingSBOM = true
	}
	if !hasAnyGlobal {
		result.MissingGlobalImage = true
	}

	// 2. Local Score
	localScore := 0.0
	if input.HasLocal {
		localScore = input.LocalScore
	} else {
		result.MissingLocal = true
	}

	// 3. Final 계산 (Toxic 적용)
	finalScore, globalContrib, localContrib := scoring.ComputeFinalScore(
		maxGlobalScore,
		localScore,
		toxic,
	)

	result.FinalScore = finalScore
	result.RiskLevel = scoring.ClassifyFinalLevel(finalScore)
	result.GlobalContribution = globalContrib
	result.LocalContribution = localContrib
	result.GlobalImageScore = maxGlobalScore
	result.LocalScore = localScore
	result.UsedImageDigest = usedDigest
	result.UsedImageTag = usedTag
	result.UsedTopCVE = usedTopCVE

	if input.HasLocal && input.LocalSnapshotAt.After(result.SnapshotAt) {
		result.SnapshotAt = input.LocalSnapshotAt
	}

	return result
}

// GetByPodUID는 단일 Pod의 결과를 조회합니다.
func (s *FinalScoringService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.FinalScoreResult, error) {
	return s.repo.GetByPodUID(ctx, clusterName, podUID)
}

// ListByCluster는 클러스터 결과를 모두 반환합니다.
func (s *FinalScoringService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.FinalScoreResult, error) {
	return s.repo.ListByCluster(ctx, clusterName)
}
