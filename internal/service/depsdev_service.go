package service

import (
	"context"
	"fmt"

	"github.com/vara/backend/internal/platform/depsdev"
	"github.com/vara/backend/internal/repository/postgres"
)

// DepsDevService는 deps.dev에서 패키지 버전 릴리스 날짜를 수집·저장합니다 (3단계).
//
// 흐름: PURL → deps.dev (system, name) 매핑 → 캐시 확인 → GetPackage → 저장.
type DepsDevService struct {
	client  *depsdev.Client
	repo    *postgres.VersionReleaseRepo
	pkgRepo *postgres.SBOMPackageRepo
}

func NewDepsDevService(
	client *depsdev.Client,
	repo *postgres.VersionReleaseRepo,
	pkgRepo *postgres.SBOMPackageRepo,
) *DepsDevService {
	return &DepsDevService{client: client, repo: repo, pkgRepo: pkgRepo}
}

// FetchResult는 한 PURL 수집 결과입니다.
type FetchResult struct {
	PURL         string `json:"purl"`
	System       string `json:"system,omitempty"`
	Name         string `json:"name,omitempty"`
	Supported    bool   `json:"supported"`     // deps.dev 커버리지 (OS 패키지면 false)
	Cached       bool   `json:"cached"`        // 캐시 hit으로 skip
	VersionCount int    `json:"version_count"` // 저장된 버전 수
}

// FetchAndStore는 한 PURL의 패키지 버전 릴리스 날짜를 deps.dev에서 받아 저장합니다.
//
//	force=true면 캐시 무시.
func (s *DepsDevService) FetchAndStore(ctx context.Context, purl string, force bool) (*FetchResult, error) {
	res := &FetchResult{PURL: purl}

	system, name, ok := depsdev.PurlToDepsDev(purl)
	if !ok {
		// deps.dev 미지원(OS 패키지 등) → 조용히 skip
		return res, nil
	}
	res.System, res.Name, res.Supported = system, name, true

	if !force {
		cached, err := s.repo.IsCached(ctx, system, name)
		if err != nil {
			return nil, fmt.Errorf("cache check: %w", err)
		}
		if cached {
			res.Cached = true
			return res, nil
		}
	}

	versions, err := s.client.GetPackage(ctx, system, name)
	if err != nil {
		return nil, fmt.Errorf("deps.dev get package %s/%s: %w", system, name, err)
	}

	if err := s.repo.UpsertVersions(ctx, system, name, versions); err != nil {
		return nil, fmt.Errorf("store versions: %w", err)
	}
	res.VersionCount = len(versions)
	return res, nil
}

// ListVersions는 한 PURL의 저장된 버전 릴리스 목록을 반환합니다.
func (s *DepsDevService) ListVersions(ctx context.Context, purl string) ([]depsdev.VersionRelease, error) {
	system, name, ok := depsdev.PurlToDepsDev(purl)
	if !ok {
		return nil, nil
	}
	return s.repo.ListVersions(ctx, system, name)
}

// FetchForImage는 한 이미지의 모든 PURL에 대해 deps.dev 수집을 수행합니다 (지원 타입만).
func (s *DepsDevService) FetchForImage(ctx context.Context, imageDigest string, force bool) (int, int, error) {
	packages, err := s.pkgRepo.ListByImageDigest(ctx, imageDigest)
	if err != nil {
		return 0, 0, fmt.Errorf("list packages: %w", err)
	}
	fetched, skipped := 0, 0
	seen := make(map[string]bool)
	for _, pkg := range packages {
		if seen[pkg.PURL] {
			continue
		}
		seen[pkg.PURL] = true
		r, err := s.FetchAndStore(ctx, pkg.PURL, force)
		if err != nil {
			fmt.Printf("warn: depsdev fetch failed for %s: %v\n", pkg.PURL, err)
			continue
		}
		if r.Supported && !r.Cached {
			fetched++
		} else {
			skipped++
		}
	}
	return fetched, skipped, nil
}
