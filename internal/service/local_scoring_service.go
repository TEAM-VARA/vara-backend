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
//  1. cluster_pods 최신 snapshot 기준으로 Pod 목록 로드
//  2. 각 Pod에 exposure_scores + attack_path_scores 최신 점수 LEFT JOIN
//  3. 두 점수를 가중 공식으로 통합
//  4. 4단계 분류 (emergency/warning/caution/safe, 90/70/40)
//  5. local_scores에 저장
//
// 누락 처리:
//   - exposure 점수 없음 → exposure_contribution = 0
//   - attack_path 점수 없음 → attack_path_contribution = 0
//   - 둘 다 없음 → local_score = 0 (하지만 결과 row는 생성)
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

	// 4단계 카운트
	emergencyCount, warningCount, cautionCount, safeCount := 0, 0, 0, 0
	missingExposure, missingAttackPath := 0, 0

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
		label := scoring.LocalLevelLabel(level)

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
			LocalLabel:             label,
			ExposureContribution:   expContrib,
			AttackPathContribution: apContrib,
			ExposureScoreRaw:       exposureRaw,
			AttackPathScoreRaw:     apRaw,
			Exposed:                exposed,
			AttackPathLevel:        apLevel,
			SnapshotAt:             snapAt,
			ComputedAt:             now,
		}

		// 4단계 카운트
		switch {
		case localScore >= 90:
			emergencyCount++
		case localScore >= 70:
			warningCount++
		case localScore >= 40:
			cautionCount++
		default:
			safeCount++
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

	// snapshot_at: 가장 늦은 결과의 값 사용 (없으면 now)
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
		EmergencyCount:    emergencyCount,
		WarningCount:      warningCount,
		CautionCount:      cautionCount,
		SafeCount:         safeCount,
		Details:           results,
		MissingExposure:   missingExposure,
		MissingAttackPath: missingAttackPath,
	}, nil
}

// ComputeForPod는 단일 Pod의 local score를 계산합니다.
// 대시보드에서 Pod 클릭 시 호출되는 빠른 재계산 API.
func (s *LocalScoringService) ComputeForPod(ctx context.Context, clusterName, podUID string) (*scoring.LocalScoreResult, error) {
	if clusterName == "" {
		return nil, fmt.Errorf("cluster_name is required")
	}
	if podUID == "" {
		return nil, fmt.Errorf("pod_uid is required")
	}

	// 1. 단일 Pod의 두 원본 점수 조회
	src, err := s.repo.LoadSourceScoresByPodUID(ctx, clusterName, podUID)
	if err != nil {
		return nil, fmt.Errorf("load source scores: %w", err)
	}
	if src == nil {
		return nil, fmt.Errorf("pod not found: cluster=%s pod_uid=%s", clusterName, podUID)
	}

	// 2. 점수 합성 (cluster compute와 동일 로직)
	exposureRaw := 0
	exposed := false
	if src.HasExposure {
		exposureRaw = src.ExposureScoreRaw
		exposed = src.Exposed
	}

	apRaw := 0
	apLevel := "Minimal"
	if src.HasAttackPath {
		apRaw = src.AttackPathScoreRaw
		apLevel = src.AttackPathLevel
		if apLevel == "" {
			apLevel = "Minimal"
		}
	}

	localScore, expContrib, apContrib := scoring.ComputeLocalScore(exposureRaw, apRaw)
	level := scoring.ClassifyLocalLevel(localScore)
	label := scoring.LocalLevelLabel(level)

	// 3. snapshot_at: 두 원본 중 가장 늦은 시점, 없으면 now
	now := time.Now()
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
		LocalLabel:             label,
		ExposureContribution:   expContrib,
		AttackPathContribution: apContrib,
		ExposureScoreRaw:       exposureRaw,
		AttackPathScoreRaw:     apRaw,
		Exposed:                exposed,
		AttackPathLevel:        apLevel,
		SnapshotAt:             snapAt,
		ComputedAt:             now,
	}

	fmt.Printf("info: local compute pod cluster=%s pod_uid=%s name=%s local_score=%g level=%s\n",
		clusterName, podUID, src.PodName, localScore, level)

	// 단일 파드 재계산은 새 스냅샷을 만들지 않고 최신 배치에 그 파드 행만 upsert한다.
	// (부분 스냅샷이 MAX가 되어 읽기/retention을 깨뜨리는 문제 방지)
	if latest, ok, err := s.repo.LatestSnapshotAt(ctx, clusterName); err == nil && ok {
		result.SnapshotAt = latest
	}

	// 4. 저장 (batch지만 단건도 그대로 호출 가능)
	if err := s.repo.UpsertBatch(ctx, []scoring.LocalScoreResult{result}); err != nil {
		return nil, fmt.Errorf("save result: %w", err)
	}

	return &result, nil
}

// GetByPodUID는 단일 Pod의 결과를 조회하고 라벨을 보강합니다.
//
// DB에 저장된 옛 데이터(High/Medium/Low/None)는 라벨이 빈 문자열이 될 수 있으나,
// POST /scoring/local/compute 1회 호출로 모두 새 등급으로 덮어씌워집니다.
func (s *LocalScoringService) GetByPodUID(ctx context.Context, clusterName, podUID string) (*scoring.LocalScoreResult, error) {
	res, err := s.repo.GetByPodUID(ctx, clusterName, podUID)
	if err != nil || res == nil {
		return res, err
	}
	res.LocalLabel = scoring.LocalLevelLabel(res.LocalLevel)
	return res, nil
}

// ListByCluster는 클러스터 결과를 모두 반환하고 라벨을 보강합니다.
func (s *LocalScoringService) ListByCluster(ctx context.Context, clusterName string) ([]scoring.LocalScoreResult, error) {
	results, err := s.repo.ListByCluster(ctx, clusterName)
	if err != nil {
		return nil, err
	}
	for i := range results {
		results[i].LocalLabel = scoring.LocalLevelLabel(results[i].LocalLevel)
	}
	return results, nil
}
