package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/service"
)

// AnalysisScheduler는 그래프 분석을 주기적으로 사전 계산합니다.
// (BFS Blast Radius, PageRank, Betweenness, Dijkstra)
//
// VulnScheduler와 동일한 패턴의 백그라운드 goroutine.
type AnalysisScheduler struct {
	svc         *service.AnalysisService
	clusterName string
	interval    time.Duration
	enabled     bool
	stop        chan struct{}
}

func NewAnalysisScheduler(
	svc *service.AnalysisService,
	clusterName string,
	interval time.Duration,
) *AnalysisScheduler {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &AnalysisScheduler{
		svc:         svc,
		clusterName: clusterName,
		interval:    interval,
		enabled:     true,
		stop:        make(chan struct{}),
	}
}

// Start는 백그라운드 goroutine으로 스케줄러를 시작합니다.
func (s *AnalysisScheduler) Start(ctx context.Context) {
	if !s.enabled {
		log.Printf("analysis-scheduler: disabled")
		return
	}

	log.Printf("analysis-scheduler: started (interval=%v, cluster=%s)", s.interval, s.clusterName)

	go func() {
		// 서버 시작 45초 후 첫 실행 (VulnScheduler 30초보다 늦게 — 부하 분산)
		time.Sleep(45 * time.Second)
		s.run(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("analysis-scheduler: stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("analysis-scheduler: stopped (manual)")
				return
			case <-ticker.C:
				s.run(ctx)
			}
		}
	}()
}

func (s *AnalysisScheduler) Stop() {
	close(s.stop)
}

func (s *AnalysisScheduler) run(ctx context.Context) {
	start := time.Now()
	log.Printf("analysis-scheduler: running precompute for cluster=%s", s.clusterName)

	if err := s.svc.PrecomputeAll(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: precompute failed: %v", err)
		return
	}

	log.Printf("analysis-scheduler: precompute completed, duration=%v", time.Since(start))
}
