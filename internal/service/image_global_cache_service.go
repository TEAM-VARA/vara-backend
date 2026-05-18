package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/repository/postgres"
)

// ImageGlobalCacheService는 image_global_scores 캐시를 관리합니다.
//
// 동작:
//  1. GET 요청 시 캐시 hit이면 즉시 반환
//  2. miss 또는 만료면 GlobalScoringService.ComputeImage 호출하여 재계산
//  3. 결과를 image_global_scores에 저장 후 반환
//
// 작업 B-1의 GlobalScoringService는 그대로 두고, 본 서비스가 위에서 캐시 layer를 입힙니다.
type ImageGlobalCacheService struct {
	repo      *postgres.ImageGlobalRepo
	globalSvc *GlobalScoringService
}

// NewImageGlobalCacheService는 ImageGlobalCacheService를 생성합니다.
func NewImageGlobalCacheService(repo *postgres.ImageGlobalRepo, globalSvc *GlobalScoringService) *ImageGlobalCacheService {
	return &ImageGlobalCacheService{
		repo:      repo,
		globalSvc: globalSvc,
	}
}

// ComputeAndStore는 이미지의 Global Score를 계산하고 image_global_scores에 저장합니다.
//
//	imageDigest: 대상 이미지의 sha256 digest (sboms.image_digest)
//	force: true면 캐시 무시하고 강제 재계산
func (s *ImageGlobalCacheService) ComputeAndStore(ctx context.Context, imageDigest string, force bool) (*scoring.ImageGlobalRecord, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image_digest is required")
	}

	// 1. 이미지 단위 캐시 확인
	if !force {
		cached, err := s.repo.GetByDigest(ctx, imageDigest)
		if err != nil {
			return nil, fmt.Errorf("check cache: %w", err)
		}
		if cached != nil && s.repo.IsFresh(cached) {
			fmt.Printf("info: image_global cache hit digest=%s\n", imageDigest)
			return cached, nil
		}
	}

	// 2. 캐시 miss 또는 force → 작업 B-1의 ComputeImage 호출
	fmt.Printf("info: image_global computing digest=%s force=%v\n", imageDigest, force)
	imgScore, err := s.globalSvc.ComputeImage(ctx, imageDigest, force)
	if err != nil {
		return nil, fmt.Errorf("compute image score: %w", err)
	}

	// 3. 결과를 ImageGlobalRecord로 변환
	//    작업 B-1의 ImageGlobalScore에 없는 필드는 0으로 둠.
	//    (이미지 단위 평균/severity 분포는 추후 보강 가능)
	now := time.Now()
	rec := scoring.ImageGlobalRecord{
		ImageDigest:   imgScore.ImageDigest,
		Image:         imgScore.Image,
		CVECount:      imgScore.CVECount,
		MaxScore:      imgScore.MaxScore,
		AvgScore:      0, // 작업 B-1 도메인에 없음 — 추후 보강
		TopCVE:        imgScore.TopCVE,
		CriticalCount: imgScore.CriticalCount,
		HighCount:     imgScore.HighCount,
		MediumCount:   0, // 작업 B-1 도메인에 없음
		LowCount:      0, // 작업 B-1 도메인에 없음
		ActiveCount:   imgScore.ActiveCount,
		POCCount:      0, // 작업 B-1 도메인에 없음 (필드명 mismatch 가능)
		NoneCount:     0, // 작업 B-1 도메인에 없음
		ComputedAt:    now,
		ExpiresAt:     now.Add(scoring.ImageGlobalCacheTTL),
	}

	// 4. 저장
	if err := s.repo.Upsert(ctx, rec); err != nil {
		return nil, fmt.Errorf("save image_global: %w", err)
	}

	rec.RiskLevel = scoring.ClassifyImageRiskLevel(rec.MaxScore)
	return &rec, nil
}

// GetByDigest는 캐시만 조회합니다(없으면 nil).
func (s *ImageGlobalCacheService) GetByDigest(ctx context.Context, imageDigest string) (*scoring.ImageGlobalRecord, error) {
	return s.repo.GetByDigest(ctx, imageDigest)
}
