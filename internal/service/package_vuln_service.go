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

type ScanImageResult struct {
	ImageDigest     string         `json:"image_digest"`
	TotalPackages   int            `json:"total_packages"`
	QueriedPackages int            `json:"queried_packages"`
	CachedPackages  int            `json:"cached_packages"`
	TotalVulns      int            `json:"total_vulns"`
	NewVulns        int            `json:"new_vulns"`
	SeverityCounts  map[string]int `json:"severity_counts"`
	Failed          int            `json:"failed"`
	DurationSeconds float64        `json:"duration_seconds"`
	FailedPURLs     []string       `json:"failed_purls,omitempty"`
}

// ScanImage scans all packages of an image against osv.dev.
//
//	force: bypass cache and re-query everything
func (s *PackageVulnService) ScanImage(ctx context.Context, imageDigest string, force bool) (*ScanImageResult, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image_digest is required")
	}

	start := time.Now()

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

	for i, pkg := range packages {
		if !force {
			cached, err := s.repo.IsCached(ctx, pkg.PURL)
			if err != nil {
				fmt.Printf("warn: cache check failed for %s: %v\n", pkg.PURL, err)
			} else if cached {
				result.CachedPackages++
				continue
			}
		}

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

		if (i+1)%50 == 0 {
			fmt.Printf("info: osv progress %d/%d (queried=%d cached=%d vulns=%d)\n",
				i+1, len(packages),
				result.QueriedPackages, result.CachedPackages, result.TotalVulns)
		}

		now := time.Now()
		expires := now.Add(sbom.PackageVulnTTL)

		normalizedVulns := make([]sbom.PackageVulnerability, 0, len(vulns))
		for _, v := range vulns {
			score, vector := osv.ExtractCVSSScore(v)
			label := osv.ClassifySeverity(score)

			// nil 방어: osv.dev가 aliases 필드를 누락하면 nil로 옴.
			// DB의 aliases TEXT[] NOT NULL 제약을 만족시키기 위해 빈 slice로 변환.
			aliases := v.Aliases
			if aliases == nil {
				aliases = []string{}
			}

			normalizedVulns = append(normalizedVulns, sbom.PackageVulnerability{
				PURL:           pkg.PURL,
				Name:           pkg.Name,
				Version:        pkg.Version,
				Ecosystem:      pkg.Ecosystem,
				VulnID:         v.ID,
				Aliases:        aliases,
				Summary:        v.Summary,
				SeverityScore:  score,
				SeverityVector: vector,
				SeverityLabel:  label,
				FetchedAt:      now,
				ExpiresAt:      expires,
			})

			result.SeverityCounts[label]++
		}

		if len(normalizedVulns) > 0 {
			if err := s.repo.UpsertBatch(ctx, normalizedVulns); err != nil {
				fmt.Printf("warn: upsert vulns failed for %s: %v\n", pkg.PURL, err)
				result.Failed++
				continue
			}
			result.TotalVulns += len(normalizedVulns)
			result.NewVulns += len(normalizedVulns)
		}

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

func (s *PackageVulnService) ListByImageDigest(ctx context.Context, imageDigest string) ([]sbom.PackageVulnerability, error) {
	return s.repo.ListByImageDigest(ctx, imageDigest)
}

func (s *PackageVulnService) SearchByVulnID(ctx context.Context, vulnID string) ([]sbom.PackageVulnerability, error) {
	return s.repo.SearchByVulnID(ctx, vulnID)
}

func (s *PackageVulnService) ListByPURL(ctx context.Context, purl string) ([]sbom.PackageVulnerability, error) {
	return s.repo.ListByPURL(ctx, purl)
}
