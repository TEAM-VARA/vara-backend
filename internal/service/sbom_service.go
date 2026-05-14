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
}

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
	}
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
		return
	}

	// 3단계: 실제 스캔 수행 (재시도 포함)
	if err := s.performScanWithRetry(ctx, req); err != nil {
		fmt.Printf("error: sbom scan failed after retries image=%s digest=%s err=%v\n",
			req.Image, req.Digest, err)
	}
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
	// Redis 분산 락
	lockKey := "sbom:scan:lock:" + req.Digest
	ok, err := s.rdb.SetNX(ctx, lockKey, "1", 10*time.Minute).Result()
	if err != nil {
		fmt.Printf("warn: redis lock acquire failed digest=%s err=%v\n", req.Digest, err)
	} else if !ok {
		fmt.Printf("info: scan already in progress on another instance digest=%s\n", req.Digest)
		return nil
	}
	defer func() {
		_ = s.rdb.Del(context.Background(), lockKey).Err()
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
