package scheduler

import (
	"context"
	"log"
	"runtime/debug"
	"time"

	"github.com/vara/backend/internal/service"
)

// RBACChainScheduler는 RBAC 권한상승(fixpoint) 분석을 주기적으로 실행합니다.
// GRCScheduler / VulnScheduler 와 동일한 패턴의 백그라운드 goroutine.
//
// RBAC 데이터(roles/bindings/SA)는 cluster-reader 에이전트가 채우므로,
// 이 스케줄러만 돌면 수동 POST /scoring/rbac-chain/compute 없이도
// 다음 주기에 결과가 DB에 자동 반영됩니다.
// Compute 는 클러스터 단위 DELETE+INSERT 덮어쓰기라 반복 호출에 안전합니다.
type RBACChainScheduler struct {
	svc         *service.RBACChainService
	clusterName string
	interval    time.Duration
	stop        chan struct{}
}

func NewRBACChainScheduler(
	svc *service.RBACChainService,
	clusterName string,
	interval time.Duration,
) *RBACChainScheduler {
	if interval == 0 {
		interval = 30 * time.Minute
	}
	return &RBACChainScheduler{
		svc:         svc,
		clusterName: clusterName,
		interval:    interval,
		stop:        make(chan struct{}),
	}
}

// Start는 백그라운드 goroutine으로 스케줄러를 시작합니다.
func (s *RBACChainScheduler) Start(ctx context.Context) {
	log.Printf("rbac-chain-scheduler: started (interval=%v, cluster=%s)", s.interval, s.clusterName)

	go func() {
		// 서버 시작 75초 후 첫 실행 (Vuln 30s / Analysis 45s / GRC 60s 보다 늦게 — 부하 분산)
		time.Sleep(75 * time.Second)
		s.run(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Printf("rbac-chain-scheduler: stopped (context cancelled)")
				return
			case <-s.stop:
				log.Printf("rbac-chain-scheduler: stopped (manual)")
				return
			case <-ticker.C:
				s.run(ctx)
			}
		}
	}()
}

func (s *RBACChainScheduler) Stop() {
	close(s.stop)
}

func (s *RBACChainScheduler) run(ctx context.Context) {
	start := time.Now()

	// panic 격리: fixpoint 엔진/로더에서 예기치 못한 panic 이 발생해도
	// 이 goroutine(및 백엔드 프로세스 전체)이 죽지 않도록 복구한다.
	// 빈/손상된 DB 는 Compute 가 error 로 반환하므로 정상 경로는 아래 err 분기에서 처리되고,
	// 여기서는 그 외 예상 밖 panic 만 잡아 다음 주기에 재시도하게 한다.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("rbac-chain-scheduler: PANIC recovered (cluster=%s): %v\n%s",
				s.clusterName, r, debug.Stack())
		}
	}()

	log.Printf("rbac-chain-scheduler: running fixpoint analysis for cluster=%s", s.clusterName)

	summary, err := s.svc.Compute(ctx, s.clusterName)
	if err != nil {
		log.Printf("rbac-chain-scheduler: compute failed: %v", err)
		return
	}

	log.Printf("rbac-chain-scheduler: compute completed (total_sas=%d, cluster_admin_sas=%d, changed_sas=%d), duration=%v",
		summary.TotalSAs, summary.ClusterAdminSAs, summary.ChangedSAs, time.Since(start))
}
