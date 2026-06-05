package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/service"
)

// GRCScheduler는 GRC 클러스터 컴플라이언스 평가를 주기적으로 실행합니다.
// AnalysisScheduler와 동일한 패턴의 백그라운드 goroutine.
type GRCScheduler struct {
	svc         *service.GRCService
	clusterName string
	interval    time.Duration
	stop        chan struct{}
}

func NewGRCScheduler(
	svc *service.GRCService,
	clusterName string,
	interval time.Duration,
) *GRCScheduler {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &GRCScheduler{
		svc:         svc,
		clusterName: clusterName,
		interval:    interval,
		stop:        make(chan struct{}),
	}
}

// Start는 백그라운드 goroutine으로 스케줄러를 시작합니다.
func (s *GRCScheduler) Start(ctx context.Context) {
	log.Printf("grc-scheduler: started (interval=%v, cluster=%s)", s.interval, s.clusterName)

	go func() {
		// 서버 시작 60초 후 첫 실행 (다른 스케줄러들보다 늦게 — 부하 분산)
		time.Sleep(60 * time.Second)
		s.run(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("grc-scheduler: stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("grc-scheduler: stopped (manual)")
				return
			case <-ticker.C:
				s.run(ctx)
			}
		}
	}()
}

func (s *GRCScheduler) Stop() {
	close(s.stop)
}

func (s *GRCScheduler) run(ctx context.Context) {
	start := time.Now()
	log.Printf("grc-scheduler: running cluster compliance for cluster=%s", s.clusterName)

	_, err := s.svc.EvaluateClusterCompliance(ctx, service.ClusterComplianceRequest{
		ClusterName: s.clusterName,
	})
	if err != nil {
		log.Printf("grc-scheduler: evaluation failed: %v", err)
		return
	}

	log.Printf("grc-scheduler: evaluation completed, duration=%v", time.Since(start))
}
