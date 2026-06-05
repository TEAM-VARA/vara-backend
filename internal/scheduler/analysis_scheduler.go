package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// AnalysisScheduler는 그래프 파이프라인 전체를 주기적으로 재계산합니다.
//  1. 엣지 4종 (identity → supply_chain → network → host)
//  2. 점수 체인 (exposure → attack-path → local → toxic → final)
//  3. 그래프 분석 사전계산 (BFS Blast Radius, PageRank, Betweenness, Dijkstra)
//
// 데이터(cluster_pods, eBPF)는 에이전트가 채우므로, 이 파이프라인만 돌면
// DB 정리/클러스터 재배포 후에도 다음 주기에 자동 복구됩니다.
type AnalysisScheduler struct {
	svc         *service.AnalysisService
	edgesRepo   *postgres.EdgesRepo
	exposureSvc *service.ExposureService
	attackSvc   *service.AttackPathService
	localSvc    *service.LocalScoringService
	toxicSvc    *service.ToxicService
	finalSvc    *service.FinalScoringService
	clusterName string
	interval    time.Duration
	enabled     bool
	stop        chan struct{}
}

func NewAnalysisScheduler(
	svc *service.AnalysisService,
	edgesRepo *postgres.EdgesRepo,
	exposureSvc *service.ExposureService,
	attackSvc *service.AttackPathService,
	localSvc *service.LocalScoringService,
	toxicSvc *service.ToxicService,
	finalSvc *service.FinalScoringService,
	clusterName string,
	interval time.Duration,
) *AnalysisScheduler {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &AnalysisScheduler{
		svc:         svc,
		edgesRepo:   edgesRepo,
		exposureSvc: exposureSvc,
		attackSvc:   attackSvc,
		localSvc:    localSvc,
		toxicSvc:    toxicSvc,
		finalSvc:    finalSvc,
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
	log.Printf("analysis-scheduler: pipeline start (cluster=%s)", s.clusterName)

	// ─────────────────────────────────────────────
	// Phase 1: 엣지 재계산 (실패해도 다음 단계 진행 — 이전 snapshot으로 동작)
	// ─────────────────────────────────────────────
	if _, err := s.edgesRepo.ComputeIdentityEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: identity edges failed: %v", err)
	}
	if _, err := s.edgesRepo.ComputeSupplyChainEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: supply_chain edges failed: %v", err)
	}
	if _, err := s.edgesRepo.ComputeNetworkEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: network edges failed: %v", err)
	}
	if _, err := s.edgesRepo.ComputeHostEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: host edges failed: %v", err)
	}
	log.Printf("analysis-scheduler: edges recomputed (%v)", time.Since(start))

	// ─────────────────────────────────────────────
	// Phase 2: 점수 체인 (의존성 순서: exposure/attack → local → toxic → final)
	// ─────────────────────────────────────────────
	if _, err := s.exposureSvc.ComputeForCluster(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: exposure failed: %v", err)
	}
	if _, err := s.attackSvc.ComputeForCluster(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: attack-path failed: %v", err)
	}
	if _, err := s.localSvc.ComputeForCluster(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: local failed: %v", err)
	}
	if _, err := s.toxicSvc.ComputeForCluster(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: toxic failed: %v", err)
	}
	if _, err := s.finalSvc.ComputeForCluster(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: final failed: %v", err)
	}
	log.Printf("analysis-scheduler: scoring chain done (%v)", time.Since(start))

	// ─────────────────────────────────────────────
	// Phase 3: 그래프 분석 사전계산 (최신 엣지 기준)
	// ─────────────────────────────────────────────
	if err := s.svc.PrecomputeAll(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: precompute failed: %v", err)
		return
	}
	log.Printf("analysis-scheduler: pipeline completed, total=%v", time.Since(start))

	// TODO: snapshot retention — 주기 실행으로 edges/점수 snapshot이 누적되므로
	//       오래된 snapshot 정리(예: 최근 24h 유지) 추가 예정 (작업 14번과 연계)
}
