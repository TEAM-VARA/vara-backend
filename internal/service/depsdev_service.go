package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vara/backend/internal/domain/sbom"
	"github.com/vara/backend/internal/platform/depsdev"
	"github.com/vara/backend/internal/repository/postgres"
)

// DepsDevService는 deps.dev에서 패키지 버전 릴리스 날짜를 수집·저장하고,
// 그 데이터로 릴리스 주기·벤더 대응속도 지표를 계산합니다 (3단계).
//
// 흐름: PURL → deps.dev (system, name) 매핑 → 캐시 확인 → GetPackage → 저장.
type DepsDevService struct {
	client  *depsdev.Client
	repo    *postgres.VersionReleaseRepo
	pkgRepo *postgres.SBOMPackageRepo
	pvRepo  *postgres.PackageVulnerabilityRepo
}

func NewDepsDevService(
	client *depsdev.Client,
	repo *postgres.VersionReleaseRepo,
	pkgRepo *postgres.SBOMPackageRepo,
	pvRepo *postgres.PackageVulnerabilityRepo,
) *DepsDevService {
	return &DepsDevService{client: client, repo: repo, pkgRepo: pkgRepo, pvRepo: pvRepo}
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

// FetchAllInUse는 사용 중인 모든 이미지의 패키지에 대해 deps.dev 수집을 수행합니다.
// (스케줄러용) 패키지 단위 캐시로 이미 받은 건 skip됩니다.
func (s *DepsDevService) FetchAllInUse(ctx context.Context, force bool) (fetched, skipped int, err error) {
	digests, err := s.pvRepo.ListDistinctImageDigests(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("list image digests: %w", err)
	}
	for _, digest := range digests {
		f, sk, ferr := s.FetchForImage(ctx, digest, force)
		if ferr != nil {
			fmt.Printf("warn: depsdev fetch image %s failed: %v\n", digest, ferr)
			continue
		}
		fetched += f
		skipped += sk
	}
	return fetched, skipped, nil
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

// ─────────────────────────────────────────
// 지표 계산 (즉석 계산, 패키지 단위)
// ─────────────────────────────────────────

// ReleaseCadence는 패키지 릴리스 주기/건강도 지표입니다.
type ReleaseCadence struct {
	TotalVersions        int        `json:"total_versions"`
	DatedVersions        int        `json:"dated_versions"`           // published_at 있는 버전 수
	FirstRelease         *time.Time `json:"first_release,omitempty"`
	LastRelease          *time.Time `json:"last_release,omitempty"`
	AvgIntervalDays      float64    `json:"avg_interval_days"`        // 버전 간 평균 간격(일)
	DaysSinceLastRelease int        `json:"days_since_last_release"`
	Stale                bool       `json:"stale"`                    // 마지막 릴리스 1년 초과
}

// VendorResponseItem은 CVE 한 건의 벤더 대응속도입니다.
type VendorResponseItem struct {
	VulnID        string     `json:"vuln_id"`
	CVEPublished  *time.Time `json:"cve_published"`
	FixedVersion  string     `json:"fixed_version"`
	FixedReleased *time.Time `json:"fixed_released,omitempty"` // deps.dev에 그 버전 날짜 없으면 nil
	ResponseDays  *int       `json:"response_days,omitempty"`  // 계산 불가(릴리스 날짜 없음)면 nil
	PreDisclosed  bool       `json:"pre_disclosed,omitempty"`  // 패치가 CVE 공개 시점 이전/동시 (대응속도 0)
}

// VendorResponse는 패키지의 벤더 보안 대응속도 집계입니다.
type VendorResponse struct {
	ComputableCount int                  `json:"computable_count"` // response_days 계산된 CVE 수
	AvgResponseDays float64              `json:"avg_response_days"`
	Items           []VendorResponseItem `json:"items"`
}

// PackageMetrics는 패키지 단위 공급망 지표입니다.
type PackageMetrics struct {
	PURL           string         `json:"purl"`
	System         string         `json:"system,omitempty"`
	Name           string         `json:"name,omitempty"`
	Supported      bool           `json:"supported"`
	ReleaseCadence ReleaseCadence `json:"release_cadence"`
	VendorResponse VendorResponse `json:"vendor_response"`
}

// GetPackageMetrics는 한 패키지의 릴리스 주기 + 벤더 대응속도를 즉석 계산합니다.
func (s *DepsDevService) GetPackageMetrics(ctx context.Context, purl string) (*PackageMetrics, error) {
	m := &PackageMetrics{PURL: purl}

	system, name, ok := depsdev.PurlToDepsDev(purl)
	if !ok {
		return m, nil // deps.dev 미지원 패키지
	}
	m.System, m.Name, m.Supported = system, name, true

	// 1) 릴리스 주기
	versions, err := s.repo.ListVersions(ctx, system, name)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	m.ReleaseCadence = computeCadence(versions)

	// 2) 벤더 대응속도
	purlBase := purl
	if i := strings.IndexByte(purlBase, '@'); i >= 0 {
		purlBase = purlBase[:i]
	}
	if i := strings.IndexByte(purlBase, '?'); i >= 0 {
		purlBase = purlBase[:i]
	}
	fixables, err := s.pvRepo.ListFixableByPackage(ctx, purlBase)
	if err != nil {
		return nil, fmt.Errorf("list fixable cves: %w", err)
	}
	m.VendorResponse = s.computeVendorResponse(ctx, system, name, fixables)

	return m, nil
}

// computeCadence는 버전 릴리스 날짜들로 주기 지표를 계산합니다.
func computeCadence(versions []depsdev.VersionRelease) ReleaseCadence {
	c := ReleaseCadence{TotalVersions: len(versions)}

	dated := make([]time.Time, 0, len(versions))
	for _, v := range versions {
		if v.PublishedAt != nil {
			dated = append(dated, *v.PublishedAt)
		}
	}
	c.DatedVersions = len(dated)
	if len(dated) == 0 {
		return c
	}
	sort.Slice(dated, func(i, j int) bool { return dated[i].Before(dated[j]) })

	first := dated[0]
	last := dated[len(dated)-1]
	c.FirstRelease = &first
	c.LastRelease = &last

	if len(dated) >= 2 {
		span := last.Sub(first).Hours() / 24.0
		c.AvgIntervalDays = round1(span / float64(len(dated)-1))
	}
	c.DaysSinceLastRelease = int(time.Since(last).Hours() / 24.0)
	c.Stale = c.DaysSinceLastRelease > 365

	return c
}

// computeVendorResponse는 CVE published → fixed 버전 릴리스 간격을 계산합니다.
func (s *DepsDevService) computeVendorResponse(ctx context.Context, system, name string, fixables []sbom.FixableCVE) VendorResponse {
	var vr VendorResponse
	var sum, n int
	for _, f := range fixables {
		item := VendorResponseItem{
			VulnID:       f.VulnID,
			CVEPublished: f.PublishedAt,
			FixedVersion: f.FixedVersion,
		}
		released, err := s.repo.GetReleaseDate(ctx, system, name, f.FixedVersion)
		if err == nil && released != nil {
			item.FixedReleased = released
			if f.PublishedAt != nil {
				diffDays := released.Sub(*f.PublishedAt).Hours() / 24.0
				var d int
				if diffDays < 0 {
					// 패치가 CVE 공개보다 먼저/동시 = 조정 공개. 대응속도 0으로 본다.
					d = 0
					item.PreDisclosed = true
				} else {
					d = int(diffDays + 0.5)
				}
				item.ResponseDays = &d
				sum += d
				n++
			}
		}
		vr.Items = append(vr.Items, item)
	}
	vr.ComputableCount = n
	if n > 0 {
		vr.AvgResponseDays = round1(float64(sum) / float64(n))
	}
	return vr
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
