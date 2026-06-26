// GRC 보조: Trivy를 통해 컨테이너 이미지 SBOM과 CVE 취약점 데이터를 수집·저장.
// GRC Finding 이미지 취약점 평가(F-2.10.8-K8S-04, cve_vulnerability_check)의 데이터 소스를 제공한다.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/external/trivy"
	"github.com/vara/backend/internal/repository/postgres"
)

// SBOMService는 SBOM 수집을 오케스트레이션합니다.
//
// 주요 책임:
//  1. 자동 트리거 (cluster agent가 Pod 정보 보낼 때)
//  2. Lazy 로딩 (risk scoring 시점에 SBOM 없으면 즉시 스캔)
//  3. 중복 스캔 방지 (Redis 분산 락 + DB 존재 체크)
//  4. 비동기 처리 (Goroutine + 워커 풀)
//  5. trivy cache lock 충돌 대비 재시도
type SBOMService struct {
	trivy *trivy.Client
	repo  *postgres.SBOMRepo
	rdb   *redis.Client

	// 동시 스캔 수 제한.
	// trivy는 fs 캐시 lock 때문에 동시 스캔 시 충돌 위험이 있어
	// 기본값 1(직렬)로 설정합니다.
	sem chan struct{}

	// 진행 중인 스캔 추적 (같은 프로세스 내 중복 방지)
	inFlight   map[string]struct{}
	inFlightMu sync.Mutex

	// 영구성 스캔 실패 백오프 (ECR 401 등 풀 불가 이미지가 매 pod 보고마다
	// 재스캔→실패를 반복하는 루프 방지). digest별 마지막 실패 시각 기록.
	failedAt map[string]time.Time
	failedMu sync.Mutex

	// SBOM 저장(sboms) 직후 자동 보강용 (선택 주입 — SetEnrichment).
	// sboms.raw_data → sbom_packages 추출(pkgSvc) → osv 매칭(vulnSvc)까지
	// 자동으로 흘려, 이미지 교체 시 수동 backfill 없이도 공통-CVE 그래프에 반영되게 한다.
	// 둘 다 nil이면 보강을 건너뛴다(기존 동작 유지).
	pkgSvc  *SBOMPackageService
	vulnSvc *PackageVulnService

	// 프로세스 내 보강 1회 가드 (digest별). 같은 digest를 매 스냅샷마다
	// 재추출/재조회하지 않도록 함. 이미 패키지가 있는 기존 이미지는
	// count>0으로 판단되어 즉시 마킹되므로 절대 재처리되지 않는다.
	enriched   map[string]struct{}
	enrichedMu sync.Mutex
}

// scanFailureBackoff는 영구성 실패 후 재스캔을 보류하는 기간입니다.
const scanFailureBackoff = 1 * time.Hour

// SBOMServiceConfig는 서비스 생성 옵션입니다.
type SBOMServiceConfig struct {
	// MaxConcurrent는 동시 trivy 스캔의 최대 개수입니다.
	// trivy fs 캐시 lock 충돌 방지를 위해 기본값 1(직렬).
	// 0이면 기본값 1 사용.
	MaxConcurrent int
}

// NewSBOMService는 SBOMService를 생성합니다.
func NewSBOMService(
	trivyClient *trivy.Client,
	repo *postgres.SBOMRepo,
	rdb *redis.Client,
	cfg SBOMServiceConfig,
) *SBOMService {
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 1 // 기본값 1: trivy lock 충돌 방지 (직렬)
	}
	return &SBOMService{
		trivy:    trivyClient,
		repo:     repo,
		rdb:      rdb,
		sem:      make(chan struct{}, cfg.MaxConcurrent),
		inFlight: make(map[string]struct{}),
		failedAt: map[string]time.Time{},
		enriched: map[string]struct{}{},
	}
}

// SetEnrichment는 SBOM 저장 직후 자동 보강(sbom_packages 추출 + osv 매칭)에 쓸
// 서비스를 주입합니다. server.go에서 sbomPackageSvc/packageVulnSvc 생성 후 호출합니다.
// 주입하지 않으면 보강은 비활성(기존 동작) 상태로 유지됩니다.
func (s *SBOMService) SetEnrichment(pkgSvc *SBOMPackageService, vulnSvc *PackageVulnService) {
	s.pkgSvc = pkgSvc
	s.vulnSvc = vulnSvc
}

// ScanRequest는 스캔 요청 한 건입니다.
type ScanRequest struct {
	Image  string
	Digest string
}

// TriggerAsync는 여러 이미지에 대한 SBOM 스캔을 백그라운드로 트리거합니다.
//
// cluster_reader_handler.Pods()에서 호출됩니다.
// 즉시 반환하며, 실제 스캔은 goroutine에서 진행됩니다.
//
// 중복 방지 3단계:
//  1. inFlight map (같은 프로세스 내)
//  2. DB ExistsByDigest (이미 저장됨)
//  3. Redis 분산 락 (다른 인스턴스가 진행 중)
func (s *SBOMService) TriggerAsync(ctx context.Context, requests []ScanRequest) {
	for _, req := range requests {
		if req.Image == "" || req.Digest == "" {
			continue
		}
		// 새 context로 분리 (요청 context가 끝나도 스캔은 계속)
		go s.scanOne(context.Background(), req)
	}
}

// GetOrScan은 lazy 로딩 메서드입니다.
//
// scoring_service에서 호출됩니다.
// DB에 SBOM이 있으면 즉시 반환, 없으면 동기로 scan 후 반환.
func (s *SBOMService) GetOrScan(ctx context.Context, image, digest string) (*postgres.SBOM, error) {
	if digest == "" {
		return nil, errors.New("digest is required")
	}

	// 1. DB 우선 체크
	existing, err := s.repo.GetByDigest(ctx, digest)
	if err != nil {
		return nil, fmt.Errorf("check db: %w", err)
	}
	if existing != nil {
		return existing, nil
	}

	// 2. DB에 없음 → 동기 스캔
	fmt.Printf("info: SBOM not found, performing lazy scan image=%s digest=%s\n", image, digest)

	if err := s.performScan(ctx, ScanRequest{Image: image, Digest: digest}); err != nil {
		return nil, fmt.Errorf("lazy scan: %w", err)
	}

	// 2.5 보강은 비동기로 (scoring 호출 지연 방지)
	go s.enrich(context.Background(), digest)

	// 3. 스캔 직후 다시 조회
	return s.repo.GetByDigest(ctx, digest)
}

// scanOne은 단일 스캔 요청을 처리합니다 (비동기 경로).
func (s *SBOMService) scanOne(ctx context.Context, req ScanRequest) {
	// 1단계: inFlight 체크
	if !s.markInFlight(req.Digest) {
		return
	}
	defer s.unmarkInFlight(req.Digest)

	// 2단계: DB 존재 체크
	exists, err := s.repo.ExistsByDigest(ctx, req.Digest)
	if err != nil {
		fmt.Printf("warn: failed to check sbom existence digest=%s err=%v\n", req.Digest, err)
		return
	}
	if exists {
		// 이미 sboms는 있음 → 재스캔은 생략하되, 다운스트림(sbom_packages)이
		// 비어 있으면 보강한다. (이미지 교체 후 sbom만 있고 패키지가 안 뽑힌 경우 자가복구)
		s.enrich(ctx, req.Digest)
		return
	}

	// 2.5단계: 최근 영구성 실패한 digest는 백오프 기간 동안 재스캔 스킵
	// (ECR 401 등 풀 불가 이미지가 매 보고마다 실패 반복하는 루프 방지)
	if s.recentlyFailed(req.Digest) {
		fmt.Printf("debug: skipping sbom scan (recent failure backoff) image=%s digest=%s\n",
			req.Image, req.Digest)
		return
	}

	// 3단계: 실제 스캔 수행 (재시도 포함)
	if err := s.performScanWithRetry(ctx, req); err != nil {
		fmt.Printf("error: sbom scan failed after retries image=%s digest=%s err=%v\n",
			req.Image, req.Digest, err)
		// 락 충돌이 아닌 영구성 실패만 백오프 대상 (락 에러는 기존 재시도로 처리)
		if !isCacheLockError(err) {
			s.markFailed(req.Digest)
		}
		return
	}

	// 4단계: SBOM 저장 성공 → sbom_packages 추출 + osv 매칭 자동 보강
	s.enrich(ctx, req.Digest)
}

// enrich는 sboms.raw_data가 저장된 digest에 대해 sbom_packages가 비어 있으면
// 추출(ExtractAndStore) 후 osv 매칭(ScanImage)까지 수행합니다.
//
// 안전장치:
//   - pkgSvc 미주입이면 즉시 반환(기존 동작 유지).
//   - 프로세스 내 1회 가드(enriched) — 같은 digest 반복 처리 방지.
//   - sbom_packages가 이미 있으면(count>0) 추출/조회를 건너뛰어 기존 데이터를 절대 건드리지 않음.
func (s *SBOMService) enrich(ctx context.Context, digest string) {
	if s.pkgSvc == nil || digest == "" {
		return
	}

	s.enrichedMu.Lock()
	if _, done := s.enriched[digest]; done {
		s.enrichedMu.Unlock()
		return
	}
	s.enrichedMu.Unlock()

	cnt, err := s.pkgSvc.CountByImageDigest(ctx, digest)
	if err != nil {
		fmt.Printf("warn: sbom enrich count failed digest=%s err=%v\n", digest, err)
		return // 마킹 안 함 → 다음 기회에 재시도
	}
	if cnt > 0 {
		// 이미 패키지가 있는 이미지 → 기존 데이터 그대로 두고 1회 마킹만
		s.markEnriched(digest)
		return
	}

	n, err := s.pkgSvc.ExtractAndStore(ctx, digest)
	if err != nil {
		fmt.Printf("warn: sbom package extract failed digest=%s err=%v\n", digest, err)
		return // 마킹 안 함 → 다음 기회에 재시도
	}
	fmt.Printf("info: sbom packages extracted digest=%s count=%d\n", digest, n)

	if n > 0 && s.vulnSvc != nil {
		if _, err := s.vulnSvc.ScanImage(ctx, digest, false); err != nil {
			fmt.Printf("warn: osv scan failed digest=%s err=%v\n", digest, err)
		}
	}
	s.markEnriched(digest)
}

func (s *SBOMService) markEnriched(digest string) {
	s.enrichedMu.Lock()
	s.enriched[digest] = struct{}{}
	s.enrichedMu.Unlock()
}

// recentlyFailed는 digest가 scanFailureBackoff 이내에 영구성 실패했는지 반환합니다.
func (s *SBOMService) recentlyFailed(digest string) bool {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	ts, ok := s.failedAt[digest]
	if !ok {
		return false
	}
	return ts.After(time.Now().Add(-scanFailureBackoff))
}

// markFailed는 digest의 마지막 영구성 실패 시각을 기록합니다.
func (s *SBOMService) markFailed(digest string) {
	s.failedMu.Lock()
	defer s.failedMu.Unlock()
	s.failedAt[digest] = time.Now()
}

// performScanWithRetry는 trivy cache lock 충돌 대비 재시도를 합니다.
// 최대 3회, 백오프 2s → 5s → 10s.
func (s *SBOMService) performScanWithRetry(ctx context.Context, req ScanRequest) error {
	backoffs := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}

	var lastErr error
	for attempt, backoff := range backoffs {
		if attempt > 0 {
			fmt.Printf("info: retrying sbom scan (attempt %d) image=%s digest=%s after=%s\n",
				attempt+1, req.Image, req.Digest, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		err := s.performScan(ctx, req)
		if err == nil {
			return nil
		}

		lastErr = err

		// "cache may be in use" 류 락 에러만 재시도 대상
		if !isCacheLockError(err) {
			return err
		}
	}

	return fmt.Errorf("retries exhausted: %w", lastErr)
}

// isCacheLockError는 trivy fs cache 락 충돌 에러인지 판별합니다.
func isCacheLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "cache may be in use") ||
		strings.Contains(msg, "unable to initialize fs cache") ||
		strings.Contains(msg, "unable to initialize cache")
}

// performScan은 락 + 동시성 제한 + trivy 호출 + DB 저장을 수행합니다.
func (s *SBOMService) performScan(ctx context.Context, req ScanRequest) error {
	// Redis 분산 락 (Redis가 nil이면 스킵)
	lockKey := "sbom:scan:lock:" + req.Digest
	redisLocked := false
	if s.rdb != nil {
		ok, err := s.rdb.SetNX(ctx, lockKey, "1", 10*time.Minute).Result()
		if err != nil {
			fmt.Printf("warn: redis lock acquire failed digest=%s err=%v\n", req.Digest, err)
		} else if !ok {
			fmt.Printf("info: scan already in progress on another instance digest=%s\n", req.Digest)
			return nil
		} else {
			redisLocked = true
		}
	}
	defer func() {
		if redisLocked && s.rdb != nil {
			_ = s.rdb.Del(context.Background(), lockKey).Err()
		}
	}()

	// 동시성 제한 (semaphore)
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return ctx.Err()
	}

	// Trivy 실행
	fmt.Printf("info: starting trivy scan image=%s digest=%s\n", req.Image, req.Digest)

	result, err := s.trivy.ScanImage(ctx, req.Image, req.Digest)
	if err != nil {
		return fmt.Errorf("trivy scan: %w", err)
	}

	fmt.Printf("info: trivy scan complete image=%s digest=%s duration=%s\n",
		req.Image, req.Digest, result.ScanDuration)

	// DB 저장
	if err := s.repo.Upsert(ctx, req.Image, req.Digest, result.Raw); err != nil {
		return fmt.Errorf("save sbom: %w", err)
	}

	return nil
}

func (s *SBOMService) markInFlight(digest string) bool {
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	if _, ok := s.inFlight[digest]; ok {
		return false
	}
	s.inFlight[digest] = struct{}{}
	return true
}

func (s *SBOMService) unmarkInFlight(digest string) {
	s.inFlightMu.Lock()
	defer s.inFlightMu.Unlock()
	delete(s.inFlight, digest)
}
