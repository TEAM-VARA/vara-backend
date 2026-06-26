package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/vara/backend/internal/domain/sbom"
	"github.com/vara/backend/internal/repository/postgres"
)

// SBOMPackageService는 sboms.raw_data에서 PURL 단위 패키지를 추출하여
// sbom_packages 테이블에 저장합니다.
//
// 두 가지 진입점:
//   1. ExtractAndStore(imageDigest)  - 특정 이미지 1개 처리
//   2. Backfill()                    - 기존 모든 sboms 일괄 처리
type SBOMPackageService struct {
	pool *pgxpool.Pool
	repo *postgres.SBOMPackageRepo
}

// NewSBOMPackageService는 SBOMPackageService를 생성합니다.
func NewSBOMPackageService(pool *pgxpool.Pool, repo *postgres.SBOMPackageRepo) *SBOMPackageService {
	return &SBOMPackageService{pool: pool, repo: repo}
}

// ExtractAndStore는 특정 image_digest의 sboms.raw_data를 읽어서
// sbom_packages에 패키지를 추출/저장합니다.
//
// SBOMService.SaveSBOM 직후 호출되거나, API/Job으로 트리거됩니다.
func (s *SBOMPackageService) ExtractAndStore(ctx context.Context, imageDigest string) (int, error) {
	if imageDigest == "" {
		return 0, fmt.Errorf("image_digest is required")
	}

	// 1. sboms.raw_data 읽기
	var rawData []byte
	err := s.pool.QueryRow(ctx,
		`SELECT raw_data FROM sboms WHERE image_digest = $1`,
		imageDigest,
	).Scan(&rawData)
	if err != nil {
		return 0, fmt.Errorf("read sbom: %w", err)
	}
	if len(rawData) == 0 {
		return 0, fmt.Errorf("sbom raw_data is empty for digest %s", imageDigest)
	}

	// 2. 추출
	packages, err := sbom.ExtractPackages(imageDigest, rawData)
	if err != nil {
		return 0, fmt.Errorf("extract packages: %w", err)
	}

	if len(packages) == 0 {
		fmt.Printf("warn: no packages extracted from digest=%s\n", imageDigest)
		return 0, nil
	}

	// 3. 저장
	if err := s.repo.UpsertBatch(ctx, packages); err != nil {
		return 0, fmt.Errorf("save packages: %w", err)
	}

	fmt.Printf("info: sbom_packages extracted digest=%s count=%d\n", imageDigest, len(packages))
	return len(packages), nil
}

// BackfillResult는 일괄 처리 결과를 요약합니다.
type BackfillResult struct {
	TotalImages       int                       `json:"total_images"`
	Succeeded         int                       `json:"succeeded"`
	Failed            int                       `json:"failed"`
	TotalPackages     int                       `json:"total_packages"`
	PerImage          []BackfillImageResult     `json:"per_image,omitempty"`
}

type BackfillImageResult struct {
	ImageDigest string `json:"image_digest"`
	Image       string `json:"image,omitempty"`
	Count       int    `json:"count"`
	Error       string `json:"error,omitempty"`
}

// Backfill은 sboms 테이블의 모든 이미지에 대해 ExtractAndStore를 수행합니다.
//
//	includeDetail: true면 per_image 상세 포함, false면 합계만
func (s *SBOMPackageService) Backfill(ctx context.Context, includeDetail bool) (*BackfillResult, error) {
	// 1. 모든 SBOM 목록 조회
	rows, err := s.pool.Query(ctx,
		`SELECT image_digest, image FROM sboms ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("list sboms: %w", err)
	}

	type imgInfo struct{ digest, image string }
	var images []imgInfo
	for rows.Next() {
		var info imgInfo
		if err := rows.Scan(&info.digest, &info.image); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan sbom: %w", err)
		}
		images = append(images, info)
	}
	rows.Close()

	result := &BackfillResult{TotalImages: len(images)}

	// 2. 각 이미지 처리
	for _, info := range images {
		count, err := s.ExtractAndStore(ctx, info.digest)

		item := BackfillImageResult{
			ImageDigest: info.digest,
			Image:       info.image,
			Count:       count,
		}
		if err != nil {
			item.Error = err.Error()
			result.Failed++
			fmt.Printf("warn: backfill failed digest=%s: %v\n", info.digest, err)
		} else {
			result.Succeeded++
			result.TotalPackages += count
		}

		if includeDetail {
			result.PerImage = append(result.PerImage, item)
		}
	}

	return result, nil
}

// ListByImageDigest는 특정 이미지의 패키지 목록을 반환합니다.
func (s *SBOMPackageService) ListByImageDigest(ctx context.Context, imageDigest string) ([]sbom.SBOMPackage, error) {
	return s.repo.ListByImageDigest(ctx, imageDigest)
}

// CountByImageDigest는 특정 이미지의 패키지 개수를 반환합니다.
// (SBOM 스캔 후 자동 보강 시 "이미 추출되었는지" 판단용 — 0일 때만 추출.)
func (s *SBOMPackageService) CountByImageDigest(ctx context.Context, imageDigest string) (int, error) {
	return s.repo.CountByImageDigest(ctx, imageDigest)
}

// SearchByName은 이름으로 모든 이미지에서 매칭되는 패키지를 찾습니다.
func (s *SBOMPackageService) SearchByName(ctx context.Context, name string) ([]sbom.SBOMPackage, error) {
	return s.repo.SearchByName(ctx, name)
}
