package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vara/backend/internal/domain/sbom"
	"github.com/vara/backend/internal/platform/osv"
	"github.com/vara/backend/internal/repository/postgres"
)

// PackageVulnService는 sbom_packages의 PURL을 osv.dev로 조회하여
// package_vulnerabilities에 저장합니다.
//
// 동작:
//   1. 이미지의 모든 PURL을 sbom_packages에서 가져옴
//   2. 각 PURL에 대해:
//      - 캐시 hit이면 skip
//      - 캐시 miss면 osv.dev 호출
//      - 결과 정규화 → package_vulnerabilities에 저장
//      - package_osv_queries에 기록 (0건이어도)
//   3. 통계 반환
type PackageVulnService struct {
	osvClient *osv.Client
	repo      *postgres.PackageVulnerabilityRepo
	pkgRepo   *postgres.SBOMPackageRepo
}

func NewPackageVulnService(
	osvClient *osv.Client,
	repo *postgres.PackageVulnerabilityRepo,
	pkgRepo *postgres.SBOMPackageRepo,
) *PackageVulnService {
	return &PackageVulnService{
		osvClient: osvClient,
		repo:      repo,
		pkgRepo:   pkgRepo,
	}
}

// ─────────────────────────────────────────
// Scan 결과 DTO
// ─────────────────────────────────────────

type ScanImageResult struct {
	ImageDigest      string                          `json:"image_digest"`
	TotalPackages    int                             `json:"total_packages"`
	QueriedPackages  int                             `json:"queried_packages"`
	CachedPackages   int                             `json:"cached_packages"`
	TotalVulns       int                             `json:"total_vulns"`
	NewVulns         int                             `json:"new_vulns"`
	SeverityCounts   map[string]int                  `json:"severity_counts"`
	Failed           int                             `json:"failed"`
	DurationSeconds  float64                         `json:"duration_seconds"`
	FailedPURLs      []string                        `json:"failed_purls,omitempty"`
}

// ─────────────────────────────────────────
// 이미지 스캔 (메인 엔트리)
// ─────────────────────────────────────────

// ScanImage는 한 이미지의 모든 패키지에 대해 osv.dev를 조회하여
// 취약점을 저장합니다.
//
//	force: true면 캐시 무시하고 모두 재조회
func (s *PackageVulnService) ScanImage(ctx context.Context, imageDigest string, force bool) (*ScanImageResult, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image_digest is required")
	}

	start := time.Now()

	// 1. 이미지의 모든 패키지 조회
	packages, err := s.pkgRepo.ListByImageDigest(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("list packages: %w", err)
	}

	result := &ScanImageResult{
		ImageDigest:    imageDigest,
		TotalPackages:  len(packages),
		SeverityCounts: map[string]int{},
	}

	if len(packages) == 0 {
		result.DurationSeconds = time.Since(start).Seconds()
		return result, nil
	}

	fmt.Printf("info: osv scan starting digest=%s packages=%d force=%v\n",
		imageDigest, len(packages), force)

	// 2. 각 패키지 처리
	for i, pkg := range packages {
		// 캐시 체크
		if !force {
			cached, err := s.repo.IsCached(ctx, pkg.PURL)
			if err != nil {
				fmt.Printf("warn: cache check failed for %s: %v\n", pkg.PURL, err)
			} else if cached {
				result.CachedPackages++
				continue
			}
		}

		// osv.dev 호출
		vulns, err := s.osvClient.QueryByPURL(ctx, pkg.PURL)
		if err != nil {
			fmt.Printf("warn: osv query failed for %s: %v\n", pkg.PURL, err)
			result.Failed++
			if len(result.FailedPURLs) < 20 {
				result.FailedPURLs = append(result.FailedPURLs, pkg.PURL)
			}
			continue
		}

		result.QueriedPackages++

		// 진행 상황 로그 (50개마다)
		if (i+1)%50 == 0 {
			fmt.Printf("info: osv progress %d/%d (queried=%d cached=%d vulns=%d)\n",
				i+1, len(packages),
				result.QueriedPackages, result.CachedPackages, result.TotalVulns)
		}

		// 결과 정규화
		now := time.Now()
		expires := now.Add(sbom.PackageVulnTTL)

		normalizedVulns := make([]sbom.PackageVulnerability, 0, len(vulns))
		for _, v := range vulns {
			score, vector := osv.ExtractCVSSScore(v)
			label := osv.ClassifySeverity(score)

			normalizedVulns = append(normalizedVulns, sbom.PackageVulnerability{
				PURL:           pkg.PURL,
				Name:           pkg.Name,
				Version:        pkg.Version,
				Ecosystem:      pkg.Ecosystem,
				VulnID:         v.ID,
				Aliases:        v.Aliases,
				Summary:        v.Summary,
				SeverityScore:  score,
				SeverityVector: vector,
				SeverityLabel:  label,
				FetchedAt:      now,
				ExpiresAt:      expires,
			})

			result.SeverityCounts[label]++
		}

		// 저장
		if len(normalizedVulns) > 0 {
			if err := s.repo.UpsertBatch(ctx, normalizedVulns); err != nil {
				fmt.Printf("warn: upsert vulns failed for %s: %v\n", pkg.PURL, err)
				result.Failed++
				continue
			}
			result.TotalVulns += len(normalizedVulns)
			result.NewVulns += len(normalizedVulns)
		}

		// 쿼리 기록 (0건이어도 기록)
		if err := s.repo.RecordQuery(ctx, pkg.PURL, len(vulns)); err != nil {
			fmt.Printf("warn: record query failed for %s: %v\n", pkg.PURL, err)
		}
	}

	result.DurationSeconds = time.Since(start).Seconds()

	fmt.Printf("info: osv scan done digest=%s queried=%d cached=%d vulns=%d failed=%d duration=%.1fs\n",
		imageDigest,
		result.QueriedPackages, result.CachedPackages,
		result.TotalVulns, result.Failed,
		result.DurationSeconds,
	)

	return result, nil
}

// ─────────────────────────────────────────
// 조회 wrapper
// ─────────────────────────────────────────

func (s *PackageVulnService) ListByImageDigest(ctx context.Context, imageDigest string) ([]sbom.PackageVulnerability, error) {
	return s.repo.ListByImageDigest(ctx, imageDigest)
}

func (s *PackageVulnService) SearchByVulnID(ctx context.Context, vulnID string) ([]sbom.PackageVulnerability, error) {
	return s.repo.SearchByVulnID(ctx, vulnID)
}

func (s *PackageVulnService) ListByPURL(ctx context.Context, purl string) ([]sbom.PackageVulnerability, error) {
	return s.repo.ListByPURL(ctx, purl)
}
