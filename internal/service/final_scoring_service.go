package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/grc"
	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ismspAddender는 ISMS-P 미준수 가산을 FinalScore에 반영하기 위한 최소 인터페이스다.
// *GRCService가 이를 만족한다. nil이면(미주입) 가산은 건너뛴다 — 기존 동작 불변.
type ismspAddender interface {
	ComputePodISMSPAddend(ctx context.Context, companyID, clusterName, namespace, podName string) *ISMSPRiskBreakdown
	ComputePodISMSPAddendWithInherited(ctx context.Context, companyID, clusterName, namespace, podName string, inherited []grc.RuleResult) *ISMSPRiskBreakdown
	ProjectInheritedFindings(ctx context.Context, companyID, clusterName string) ([]grc.RuleResult, error)
}

// FinalScoringService는 Final Score 통합 계산을 담당합니다.
//
// 알고리즘:
//  1. FinalScoringRepo.LoadInputsForCluster로 모든 입력 한 번에 조회
//  2. ToxicService.LoadMultipliersForCluster로 multiplier 맵 로드
//  3. 각 Pod에 대해:
//     a. 가장 위험한 컨테이너 이미지 채택
//     b. Local Score 가져오기
//     c. Toxic Multiplier 적용
//     d. Final = (0.7 × Global + 0.3 × Exposure) × Toxic  (Attack Path 제외)
//     e. 4단계 분류 (emergency/warning/caution/safe)
//  4. final_scores에 저장
type FinalScoringService struct {
	repo         *postgres.FinalScoringRepo
	toxicService *ToxicService
	ismsp        ismspAddender // ISMS-P 가산 제공자(선택) — 미주입 시 가산 스킵
}

func NewFinalScoringService(repo *postgres.FinalScoringRepo, toxicSvc *ToxicService) *FinalScoringService {
	return &FinalScoringService{
		repo:         repo,
		toxicService: toxicSvc,
	}
}

// SetISMSPAddender는 ISMS-P 미준수 가산 제공자를 주입한다(server 부팅 시 grcSvc 주입).
// 주입되면 ComputeForPod/ComputeForCluster가 FinalScore에 ISMS-P 가산을 더해 저장한다.
func (s *FinalScoringService) SetISMSPAddender(a ismspAddender) {
	s.ismsp = a
}

// applyISMSPToFinalScoreResult는 FinalScore에 ISMS-P 가산을 더하고 100 상한·등급 재분류한다.
// scoring.Result용 ApplyISMSPToFinalScore의 FinalScoreResult 버전(타입이 달라 재사용 불가).
func applyISMSPToFinalScoreResult(r *scoring.FinalScoreResult, addend float64) {
	if r == nil || addend <= 0 {
		return
	}
	score := r.FinalScore + addend
	if score > 100 {
		score = 100
	}
	r.FinalScore = roundTo2(score)
	r.RiskLevel = scoring.ClassifyFinalLevel(r.FinalScore)
	r.RiskLabel = scoring.FinalLevelLabel(r.RiskLevel)
}

func (s *FinalScoringService) ComputeForCluster(ctx context.Context, clusterName string) (*scoring.FinalComputeResponse, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}

	inputs, err := s.repo.LoadInputsForCluster(ctx, clusterName)
	if err != nil {
		return nil, fmt.Errorf("load inputs: %w", err)
	}

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

	// ISMS-P 가산용 클러스터 공통(상속) 결함을 1회 투영해 pod마다 재조회하지 않는다.
	var inheritedFindings []grc.RuleResult
	if s.ismsp != nil {
		if inh, ierr := s.ismsp.ProjectInheritedFindings(ctx, "", clusterName); ierr == nil {
			inheritedFindings = inh
		}
	}

	results := make([]scoring.FinalScoreResult, 0, len(inputs))
	now := time.Now()

	// 4단계 카운트
	emergencyCount, warningCount, cautionCount, safeCount := 0, 0, 0, 0
	missingGI, missingL, missingSBOM := 0, 0, 0
	ismspApplied := 0

	for _, input := range inputs {
		toxic, ok := multipliers[input.PodUID]
		if !ok || toxic <= 0 {
			toxic = scoring.FinalDefaultToxicMultiplier
		}

		result := s.computePod(input, clusterName, now, toxic)

		// ISMS-P 미준수 가산을 저장 final_score에 반영(상속 결함은 위에서 1회 투영한 것 재사용).
		if s.ismsp != nil {
			if bd := s.ismsp.ComputePodISMSPAddendWithInherited(ctx, "", clusterName, input.PodNamespace, input.PodName, inheritedFindings); bd != nil && bd.Addend > 0 {
				applyISMSPToFinalScoreResult(&result, bd.Addend)
				ismspApplied++
			}
		}

		// 4단계 카운트 (임계값: 80/50/20)
		switch {
		case result.FinalScore >= 80:
			emergencyCount++
		case result.FinalScore >= 50:
			warningCount++
		case result.FinalScore >= 20:
			cautionCount++
		default:
			safeCount++
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

	if s.ismsp != nil {
		fmt.Printf("info: ISMS-P 가산 적용 %d/%d pods (cluster=%s)\n", ismspApplied, len(results), clusterName)
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
		EmergencyCount:     emergencyCount,
		WarningCount:       warningCount,
		CautionCount:       cautionCount,
		SafeCount:          safeCount,
		MissingGlobalImage: missingGI,
		MissingLocal:       missingL,
		MissingSBOM:        missingSBOM,
		Details:            results,
	}, nil
}

// ComputeForPod는 단일 Pod의 final score를 계산합니다.
// 대시보드에서 Pod 클릭 시 호출되는 빠른 재계산 API.
func (s *FinalScoringService) ComputeForPod(ctx context.Context, clusterName, podUID string) (*scoring.FinalScoreResult, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}
	if podUID == "" {
		return nil, fmt.Errorf("pod_uid is required")
	}

	// 1. 단일 Pod의 입력 조회
	input, err := s.repo.LoadInputByPodUID(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("load input: %w", err)
	}
	if input == nil {
		return nil, fmt.Errorf("pod not found: cluster=%s pod_uid=%s", clusterName, podUID)
	}

	// 2. Toxic multiplier 단건 조회 (없으면 기본값)
	toxic := scoring.FinalDefaultToxicMultiplier
	if s.toxicService != nil {
		m, err := s.toxicService.GetMultiplierForPod(ctx, clusterName, podUID)
		if err != nil {
			fmt.Printf("warn: load toxic multiplier failed: %v (using default %.2f)\n", err, toxic)
		} else if m > 0 {
			toxic = m
		}
	}

	// 3. 점수 계산 (기존 computePod 재활용)
	now := time.Now()
	result := s.computePod(*input, clusterName, now, toxic)

	// 3-1. ISMS-P 미준수 가산 — 저장 final_score에 박아 Risk Scoring/공격 시나리오/그래프 노드가 모두 일치하게 한다.
	// pod_name은 정규화 전 원본(grc 평가 저장 키와 동일)을 쓴다. company_id는 cluster_name만으로 통일.
	if s.ismsp != nil {
		if bd := s.ismsp.ComputePodISMSPAddend(ctx, "", clusterName, input.PodNamespace, input.PodName); bd != nil && bd.Addend > 0 {
			applyISMSPToFinalScoreResult(&result, bd.Addend)
		}
	}

	fmt.Printf("info: final compute pod cluster=%s pod_uid=%s name=%s final_score=%.2f toxic=%.2f\n",
		clusterName, podUID, input.PodName, result.FinalScore, toxic)

	// 단일 파드 재계산은 새 스냅샷을 만들지 않고 최신 배치에 그 파드 행만 upsert한다.
	// (부분 스냅샷이 MAX가 되어 읽기/retention을 깨뜨리는 문제 방지)
	if latest, ok, err := s.repo.LatestSnapshotAt(ctx, clusterName); err == nil && ok {
		result.SnapshotAt = latest
	}

	// 4. 저장
	if err := s.repo.UpsertBatch(ctx, []scoring.FinalScoreResult{result}); err != nil {
		return nil, fmt.Errorf("save result: %w", err)
	}

	return &result, nil
}

func (s *FinalScoringService) computePod(input postgres.PodFinalInput, clusterName string, now time.Time, toxic float64) scoring.FinalScoreResult {
	result := scoring.FinalScoreResult{
		ClusterName:     clusterName,
		PodUID:          input.PodUID,
		PodName:         scoring.NormalizePodName(input.PodName),
		PodNamespace:    input.PodNamespace,
		ToxicMultiplier: toxic,
		SnapshotAt:      input.PodSnapshotAt,
		ComputedAt:      now,
	}

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

	localScore := 0.0
	if input.HasLocal {
		localScore = input.LocalScore
	} else {
		result.MissingLocal = true
	}

	finalScore, globalContrib, localContrib := scoring.ComputeFinalScore(
		maxGlobalScore,
		localScore,
		toxic,
	)

	result.FinalScore = finalScore
	result.RiskLevel = scoring.ClassifyFinalLevel(finalScore)
	result.RiskLabel = scoring.FinalLevelLabel(result.RiskLevel)
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

func (s *FinalScoringService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.FinalScoreResult, error) {
	res, err := s.repo.GetByPodUID(ctx, clusterName, podUID)
	if err != nil || res == nil {
		return res, err
	}
	// DB에는 영문 식별자만 저장되어 있으므로 응답 시 한글 라벨 보강
	res.RiskLabel = scoring.FinalLevelLabel(res.RiskLevel)
	return res, nil
}

func (s *FinalScoringService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.FinalScoreResult, error) {
	results, err := s.repo.ListByCluster(ctx, clusterName)
	if err != nil {
		return nil, err
	}
	for i := range results {
		results[i].RiskLabel = scoring.FinalLevelLabel(results[i].RiskLevel)
	}
	return results, nil
}
