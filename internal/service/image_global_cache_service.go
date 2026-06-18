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

	return s.persist(ctx, imgScore)
}

// RecomputeAndStore는 이미지 캐시를 무시하고 항상 재계산하되, per-CVE 점수는 캐시를 재사용한다.
// (ComputeImage force=false → 기존 CVE는 cve_global_scores 캐시 재사용, 미캐시(신규) CVE만 외부 fetch)
//
// 신규 CVE를 반영하면서도, force=true처럼 모든 CVE를 외부 재호출(KEV/NVD/EPSS)하다가
// 일부 fetch 실패로 기존 CVE 점수가 출렁(예: KEV 실패 → SSVC Active→None, -30점)이는 것을 막는다.
// 신규 CVE 감지 시 영향 이미지 Global 갱신 용도.
func (s *ImageGlobalCacheService) RecomputeAndStore(ctx context.Context, imageDigest string) (*scoring.ImageGlobalRecord, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image_digest is required")
	}
	fmt.Printf("info: image_global recompute (cve-cache 재사용) digest=%s\n", imageDigest)
	imgScore, err := s.globalSvc.ComputeImage(ctx, imageDigest, false)
	if err != nil {
		return nil, fmt.Errorf("compute image score: %w", err)
	}
	return s.persist(ctx, imgScore)
}

// persist는 ImageGlobalScore를 ImageGlobalRecord로 변환·저장하고 등급을 매겨 반환한다.
func (s *ImageGlobalCacheService) persist(ctx context.Context, imgScore *scoring.ImageGlobalScore) (*scoring.ImageGlobalRecord, error) {
	// ImageGlobalScore에 없는 필드는 0으로 둠 (이미지 단위 평균/severity 분포는 추후 보강).
	now := time.Now()
	rec := scoring.ImageGlobalRecord{
		ImageDigest:   imgScore.ImageDigest,
		Image:         imgScore.Image,
		CVECount:      imgScore.CVECount,
		MaxScore:      imgScore.MaxScore,
		AvgScore:      0,
		TopCVE:        imgScore.TopCVE,
		CriticalCount: imgScore.CriticalCount,
		HighCount:     imgScore.HighCount,
		MediumCount:   0,
		LowCount:      0,
		ActiveCount:   imgScore.ActiveCount,
		POCCount:      0,
		NoneCount:     0,
		ComputedAt:    now,
		ExpiresAt:     now.Add(scoring.ImageGlobalCacheTTL),
	}

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
