package service

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/platform/epss"
	"github.com/vara/backend/internal/platform/exploitdb"
	"github.com/vara/backend/internal/platform/kev"
	"github.com/vara/backend/internal/platform/nvd"
	"github.com/vara/backend/internal/platform/vlm"
	"github.com/vara/backend/internal/repository/postgres"
)

// GlobalScoringService는 CVE의 Global Score를 계산합니다.
//
// 점수 항목 (Phase 1):
//   - CVSS  (NVD)    : 정적 위험도
//   - EPSS  (FIRST)  : 향후 30일 공격 확률
//   - SSVC  (KEV/ExploitDB) : 실제 alleged exploitation 상태
//
// 캐시 정책:
//   - DB의 cve_global_scores 테이블이 캐시 역할
//   - 같은 CVE 24시간 내 재요청 시 외부 API 호출 안 함
//   - force=true 옵션으로 캐시 무시 가능
//
// Phase 2 추가 예정:
//   - Vulnrichment 클라이언트 통합 (SSVC 1차 소스)
//   - Redis 캐싱 (현재는 DB만 사용)
type GlobalScoringService struct {
	nvd         *nvd.Client
	epss        *epss.Client
	kev         *kev.Client
	exploitDB   *exploitdb.Client
	repo        *postgres.GlobalScoringRepo
	pkgVulnRepo *postgres.PackageVulnerabilityRepo // CVSS 결측 시 OSV severity/summary 조회
	vlm         *vlm.Client                        // CVSS 결측 시 AI 추정
}

// NewGlobalScoringService는 GlobalScoringService를 생성합니다.
// pkgVulnRepo·vlm은 CVSS 결측 보완(NVD→OSV→AI)용. nil이면 해당 단계 생략.
func NewGlobalScoringService(
	nvd *nvd.Client,
	epss *epss.Client,
	kev *kev.Client,
	exploitDB *exploitdb.Client,
	repo *postgres.GlobalScoringRepo,
	pkgVulnRepo *postgres.PackageVulnerabilityRepo,
	vlmClient *vlm.Client,
) *GlobalScoringService {
	return &GlobalScoringService{
		nvd:         nvd,
		epss:        epss,
		kev:         kev,
		exploitDB:   exploitDB,
		repo:        repo,
		pkgVulnRepo: pkgVulnRepo,
		vlm:         vlmClient,
	}
}

// ─────────────────────────────────────────
// 단일 CVE
// ─────────────────────────────────────────

// ComputeCVE는 단일 CVE의 Global Score를 계산합니다.
//
// force=false:
//   1. DB 캐시 확인 (expires_at > NOW())
//   2. 있으면 즉시 반환
//   3. 없으면 외부 API 호출 → 점수 계산 → DB 저장
//
// force=true:
//   - 캐시 무시하고 외부 API 호출
func (s *GlobalScoringService) ComputeCVE(ctx context.Context, cveID string, force bool) (*scoring.GlobalScore, error) {
	if cveID == "" {
		return nil, fmt.Errorf("cve_id is required")
	}

	// 1. 캐시 확인 (force=false인 경우)
	if !force {
		cached, err := s.repo.GetByCVEIDFresh(ctx, cveID)
		if err != nil {
			return nil, fmt.Errorf("check cache: %w", err)
		}
		if cached != nil {
			return cached, nil
		}
	}

	// 2. 외부 API 동시 호출 (4개)
	score, rawData := s.fetchAndCompute(ctx, cveID)

	// 3. DB 저장
	if err := s.repo.Upsert(ctx, score, rawData.nvd, rawData.epss, rawData.kev, rawData.exploitDB); err != nil {
		// 저장 실패해도 계산 결과는 반환 (소프트 에러)
		fmt.Printf("warn: failed to cache score for %s: %v\n", cveID, err)
	}

	return &score, nil
}

// GetCachedCVE는 캐시된 점수를 조회만 합니다 (계산 안 함).
// expires_at 검사 X (오래된 것도 반환).
func (s *GlobalScoringService) GetCachedCVE(ctx context.Context, cveID string) (*scoring.GlobalScore, error) {
	return s.repo.GetByCVEID(ctx, cveID)
}

// ─────────────────────────────────────────
// 이미지 단위
// ─────────────────────────────────────────

// ComputeImage는 이미지의 모든 CVE에 대해 Global Score를 계산합니다.
//
// 흐름:
//   1. sboms 테이블에서 이미지의 CVE 목록 추출
//   2. 각 CVE 점수 계산 (캐시 활용)
//   3. 통합 점수 (max) + 통계 산정
func (s *GlobalScoringService) ComputeImage(ctx context.Context, imageDigest string, force bool) (*scoring.ImageGlobalScore, error) {
	if imageDigest == "" {
		return nil, fmt.Errorf("image_digest is required")
	}

	// 1. CVE 목록 추출
	cves, err := s.repo.ListCVEsByImageDigest(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("list cves: %w", err)
	}
	if len(cves) == 0 {
		return nil, fmt.Errorf("no CVEs found for image_digest %s (SBOM exists?)", imageDigest)
	}

	// 이미지 이름 조회 (응답용)
	imageName, _ := s.repo.GetImageByDigest(ctx, imageDigest)

	fmt.Printf("info: computing image global score image_digest=%s cves=%d\n", imageDigest, len(cves))

	// 2. 각 CVE 점수 계산 (순차 처리 — NVD rate limit 보호)
	// 50 req/30sec 이라 50개씩 묶어서 큰 이미지엔 30초 sleep 필요할 수 있음
	// 일단 순차로 처리.
	results := make([]scoring.GlobalScore, 0, len(cves))
	for i, cve := range cves {
		// rate limit 보호: NVD API 키 있으면 50 req/30sec
		// 50번째마다 잠시 대기
		if i > 0 && i%50 == 0 {
			fmt.Printf("info: pausing for NVD rate limit i=%d\n", i)
			time.Sleep(5 * time.Second)
		}

		score, err := s.ComputeCVE(ctx, cve.CVEID, force)
		if err != nil {
			fmt.Printf("warn: cve %s scoring failed: %v\n", cve.CVEID, err)
			continue
		}
		results = append(results, *score)
	}

	// 3. 통계 + max
	result := &scoring.ImageGlobalScore{
		ImageDigest: imageDigest,
		Image:       imageName,
		CVECount:    len(results),
		ComputedAt:  time.Now(),
	}

	for _, r := range results {
		if r.GlobalScore > result.MaxScore {
			result.MaxScore = r.GlobalScore
			result.TopCVE = r.CVEID
		}
		if r.CVSSScore >= 9.0 {
			result.CriticalCount++
		} else if r.CVSSScore >= 7.0 {
			result.HighCount++
		}
		if r.SSVCExploitation == scoring.SSVCExploitationActive {
			result.ActiveCount++
		} else if r.SSVCExploitation == scoring.SSVCExploitationPoC {
			result.PoCCount++
		}
	}

	// 점수 높은 순으로 정렬
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].GlobalScore > results[j].GlobalScore
	})
	result.CVEScores = results

	return result, nil
}

// ─────────────────────────────────────────
// 외부 API 호출 (내부)
// ─────────────────────────────────────────

type rawSources struct {
	nvd       any
	epss      any
	kev       any
	exploitDB any
}

// fetchAndCompute는 외부 API 4개를 동시 호출하고 점수를 계산합니다.
func (s *GlobalScoringService) fetchAndCompute(ctx context.Context, cveID string) (scoring.GlobalScore, rawSources) {
	score := scoring.GlobalScore{
		CVEID: cveID,
	}
	raw := rawSources{}

	// 4개 API 병렬 호출 (외부 의존성 다중화)
	var wg sync.WaitGroup
	wg.Add(4)

	// 1. NVD (CVSS)
	go func() {
		defer wg.Done()
		info, err := s.nvd.FetchCVE(ctx, cveID)
		if err != nil {
			fmt.Printf("warn: nvd fetch %s failed: %v\n", cveID, err)
			return
		}
		if info != nil && info.Found {
			score.CVSSFound = true
			score.CVSSScore = info.CVSSScore
			score.CVSSSeverity = info.Severity
			score.CVSSVector = info.VectorString
			raw.nvd = info
		}
	}()

	// 2. EPSS
	go func() {
		defer wg.Done()
		info, err := s.epss.FetchEPSS(ctx, cveID)
		if err != nil {
			fmt.Printf("warn: epss fetch %s failed: %v\n", cveID, err)
			return
		}
		if info != nil && info.Found {
			score.EPSSFound = true
			score.EPSSScore = info.Score
			score.EPSSPercentile = info.Percentile
			raw.epss = info
		}
	}()

	// 3. KEV
	go func() {
		defer wg.Done()
		entry, err := s.kev.IsListed(ctx, cveID)
		if err != nil {
			fmt.Printf("warn: kev fetch %s failed: %v\n", cveID, err)
			return
		}
		if entry != nil {
			score.InKEV = true
			raw.kev = entry
		}
	}()

	// 4. ExploitDB
	go func() {
		defer wg.Done()
		hasExploit, urls, err := s.exploitDB.HasExploit(ctx, cveID)
		if err != nil {
			fmt.Printf("warn: exploitdb fetch %s failed: %v\n", cveID, err)
			return
		}
		if hasExploit {
			score.InExploitDB = true
			raw.exploitDB = urls
		}
	}()

	wg.Wait()

	// SSVC 산정 (KEV 우선 → ExploitDB → none)
	exploitation, source, ssvcValue := scoring.ComputeSSVC(score.InKEV, score.InExploitDB)
	score.SSVCExploitation = exploitation
	score.SSVCSource = source

	// CVSS 결측 보완: NVD에 없으면 OSV severity → AI 추정 순으로 채운다.
	// (AI 추정만 confidence 페널티가 점수에 반영됨 — raw 값은 CVSSScore에 보존)
	cvssForScore := score.CVSSScore
	if !score.CVSSFound {
		cvssForScore = s.imputeCVSS(ctx, &score)
	}

	// Global Score 계산
	total, cvssC, epssC, ssvcC := scoring.ComputeGlobalScore(
		cvssForScore, score.EPSSScore, ssvcValue,
	)
	score.GlobalScore = total
	score.CVSSContribution = cvssC
	score.EPSSContribution = epssC
	score.SSVCContribution = ssvcC

	now := time.Now()
	score.ComputedAt = now
	score.ExpiresAt = now.Add(scoring.CacheTTL)

	return score, raw
}

// imputeCVSS는 NVD에 CVSS가 없을 때 OSV severity → AI 추정 순으로 보완한다.
// score(raw 값/메타)를 갱신하고, 점수 계산에 쓸 "유효 CVSS"를 반환한다.
// (AI 추정은 confidence 페널티를 곱한 값을 반환 — raw 추정치는 score.CVSSScore에 보존)
func (s *GlobalScoringService) imputeCVSS(ctx context.Context, score *scoring.GlobalScore) float64 {
	if s.pkgVulnRepo == nil {
		return score.CVSSScore
	}
	sev, summary, found, err := s.pkgVulnRepo.GetSeveritySummaryByVulnID(ctx, score.CVEID)
	if err != nil {
		fmt.Printf("warn: osv severity lookup %s: %v\n", score.CVEID, err)
	}

	// 1) OSV severity_score (실제 점수 — '추정' 아님, 페널티 없음)
	if found && sev > 0 {
		score.CVSSScore = sev
		score.CVSSSeverity = severityLabelFromScore(sev)
		score.CVSSImputed = false
		score.ImputationSource = "osv"
		score.ImputationConfidence = 1.0
		fmt.Printf("info: cvss imputed from OSV for %s = %.1f\n", score.CVEID, sev)
		return sev
	}

	// 2) AI 추정 (OSV summary를 설명으로). confidence 페널티는 점수에만 적용.
	// 결측 보완 AI는 Claude 전용(UsingClaude) — Ollama 폴백은 너무 느리고 디스크 부담이라 제외.
	if s.vlm != nil && s.vlm.UsingClaude() && summary != "" {
		// Claude는 수초 내 응답 → 60초 상한이면 충분.
		aiCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		est, _ := s.vlm.EstimateCVSS(aiCtx, score.CVEID, summary)
		cancel()
		if est != nil && est.CVSS > 0 {
			score.CVSSScore = est.CVSS
			score.CVSSSeverity = severityLabelFromScore(est.CVSS)
			score.CVSSImputed = true
			score.ImputationSource = "ai"
			score.ImputationConfidence = est.Confidence
			fmt.Printf("info: cvss imputed by AI for %s = %.1f (conf=%.2f)\n", score.CVEID, est.CVSS, est.Confidence)
			return est.CVSS * est.Confidence // 점수엔 confidence 페널티
		}
	}

	// 보완 실패 → CVSS 기여 0
	return 0
}

// severityLabelFromScore는 CVSS 점수를 NVD 스타일 라벨로 변환합니다.
func severityLabelFromScore(s float64) string {
	switch {
	case s >= 9.0:
		return "CRITICAL"
	case s >= 7.0:
		return "HIGH"
	case s >= 4.0:
		return "MEDIUM"
	case s > 0:
		return "LOW"
	}
	return ""
}
