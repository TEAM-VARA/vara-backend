package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/service"
)

// DepsDevScheduler는 사용 중인 패키지의 버전 릴리스 날짜를 deps.dev에서 주기적으로 수집합니다.
//
// 릴리스 날짜는 느리게 변하므로 기본 24h 주기 + 패키지 단위 7일 캐시로 외부 부하를 낮춥니다.
// 이 데이터가 채워져야 릴리스 주기·벤더 대응속도 지표가 최신으로 유지됩니다.
type DepsDevScheduler struct {
	svc      *service.DepsDevService
	interval time.Duration
	stop     chan struct{}
}

func NewDepsDevScheduler(svc *service.DepsDevService, interval time.Duration) *DepsDevScheduler {
	if interval == 0 {
		interval = 24 * time.Hour
	}
	return &DepsDevScheduler{
		svc:      svc,
		interval: interval,
		stop:     make(chan struct{}),
	}
}

// Start는 백그라운드 goroutine으로 스케줄러를 시작합니다.
func (s *DepsDevScheduler) Start(ctx context.Context) {
	log.Printf("depsdev-scheduler: started (interval=%v)", s.interval)

	go func() {
		// 서버 시작 120초 후 첫 실행 (다른 스케줄러보다 늦게 — 부하 분산)
		time.Sleep(120 * time.Second)
		s.run(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("depsdev-scheduler: stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("depsdev-scheduler: stopped (manual)")
				return
			case <-ticker.C:
				s.run(ctx)
			}
		}
	}()
}

func (s *DepsDevScheduler) Stop() {
	close(s.stop)
}

func (s *DepsDevScheduler) run(ctx context.Context) {
	start := time.Now()
	fetched, skipped, err := s.svc.FetchAllInUse(ctx, false)
	if err != nil {
		log.Printf("depsdev-scheduler: fetch failed: %v", err)
		return
	}
	log.Printf("depsdev-scheduler: done (fetched=%d skipped=%d duration=%v)", fetched, skipped, time.Since(start))
}
