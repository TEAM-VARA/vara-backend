package scheduler

import (
	"context"
	"log"
	"time"

	"github.com/vara/backend/internal/blastedge"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// AnalysisScheduler는 그래프 파이프라인 전체를 주기적으로 재계산합니다.
//  0. 글로벌 점수 캐시 갱신 (sboms digest 전체, 만료분만 재계산)
//  1. 엣지 4종 (identity → supply_chain → network → host)
//  2. 점수 체인 (exposure → attack-path → local → toxic → final)
//  3. 그래프 분석 사전계산 (BFS Blast Radius, PageRank, Betweenness, Dijkstra)
//  4. snapshot retention (최신만 유지)
//
// 데이터(cluster_pods, eBPF)는 에이전트가 채우므로, 이 파이프라인만 돌면
// DB 정리/클러스터 재배포 후에도 다음 주기에 자동 복구됩니다.
type AnalysisScheduler struct {
	svc            *service.AnalysisService
	edgesRepo      *postgres.EdgesRepo
	blastEdgesRepo *postgres.BlastEdgesRepo
	imgCacheSvc    *service.ImageGlobalCacheService
	sbomRepo    *postgres.SBOMRepo
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
	blastEdgesRepo *postgres.BlastEdgesRepo,
	imgCacheSvc *service.ImageGlobalCacheService,
	sbomRepo *postgres.SBOMRepo,
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
		svc:            svc,
		edgesRepo:      edgesRepo,
		blastEdgesRepo: blastEdgesRepo,
		imgCacheSvc:    imgCacheSvc,
		sbomRepo:    sbomRepo,
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
		// 서버 시작 15분 후 첫 실행, 이후 interval(기본 10분)마다
		time.Sleep(15 * time.Minute)
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
	// [긴급] blast_edges를 느린 Phase 0(VLM)보다 먼저 계산
	s.computeBlastEdges(ctx)
	start := time.Now()
	log.Printf("analysis-scheduler: pipeline start (cluster=%s)", s.clusterName)

	// ─────────────────────────────────────────────
	// Phase 1: 엣지 재계산 (먼저!) — NVD 등 외부 API와 무관(cluster_pods/서비스/RBAC/eBPF만).
	// 글로벌 캐시 갱신(Phase 0)이 NVD 503/지연으로 오래 걸려도 topology가 항상 신선하도록,
	// 엣지+retention을 파이프라인 맨 앞에 둔다. (예전엔 Phase 0가 앞을 막아 엣지가 갱신 안 됨)
	// ─────────────────────────────────────────────
	edgesOK := false
	if _, err := s.edgesRepo.ComputeIdentityEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: identity edges failed: %v", err)
	} else {
		edgesOK = true
	}
	if _, err := s.edgesRepo.ComputeSupplyChainEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: supply_chain edges failed: %v", err)
	} else {
		edgesOK = true
	}
	if _, err := s.edgesRepo.ComputeNetworkEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: network edges failed: %v", err)
	} else {
		edgesOK = true
	}
	if _, err := s.edgesRepo.ComputeHostEdges(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: host edges failed: %v", err)
	} else {
		edgesOK = true
	}
	log.Printf("analysis-scheduler: edges recomputed (%v)", time.Since(start))

	// 이번 사이클 이전(snapshot_at < start) 엣지 전부 삭제 → 이번 사이클에 재계산 안 된
	// stale 레이어가 남지 않게 함 (레이어 간 시점 불일치로 인한 topology X2 중복 방지).
	// 단, 4개 레이어 계산이 전부 실패했으면 기존 엣지 보존(빈 그래프 방지).
	if edgesOK {
		if deleted, err := s.edgesRepo.DeleteEdgesBefore(ctx, s.clusterName, start); err != nil {
			log.Printf("analysis-scheduler: edge retention failed: %v", err)
		} else if deleted > 0 {
			log.Printf("analysis-scheduler: deleted %d stale edges (before this cycle)", deleted)
		}
	} else {
		log.Printf("analysis-scheduler: all edge computes failed — keeping previous edges")
	}

	// ─────────────────────────────────────────────
	// Phase 0: 글로벌 점수 캐시 갱신 (sboms digest 전체, 만료분만 재계산)
	// NVD 503/지연으로 오래 걸릴 수 있어 엣지 뒤로 옮기고 시간 상한을 둔다.
	// 상한 초과 시 남은 digest는 다음 사이클에 처리(엣지/점수 진행을 막지 않음).
	// final 점수가 글로벌을 읽으므로 점수 체인(Phase 2)보다는 앞에 둔다.
	// ─────────────────────────────────────────────
	if s.imgCacheSvc != nil && s.sbomRepo != nil {
		digests, err := s.sbomRepo.ListDistinctDigests(ctx)
		if err != nil {
			log.Printf("analysis-scheduler: list digests failed: %v", err)
		} else {
			const phase0Budget = 10 * time.Minute
			deadline := time.Now().Add(phase0Budget)
			var refreshed, failed, skipped int
			for i, d := range digests {
				if time.Now().After(deadline) {
					skipped = len(digests) - i
					log.Printf("analysis-scheduler: global refresh budget(%v) exceeded — %d digests deferred to next cycle", phase0Budget, skipped)
					break
				}
				if _, err := s.imgCacheSvc.ComputeAndStore(ctx, d, false); err != nil {
					failed++
					log.Printf("analysis-scheduler: global refresh failed digest=%s: %v", d, err)
				} else {
					refreshed++
				}
			}
			log.Printf("analysis-scheduler: global cache refreshed (%d ok, %d failed, %d deferred, %v)",
				refreshed, failed, skipped, time.Since(start))
		}
	}

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
	// Phase 2.5: blast 엣지 재계산 (network=B.Risk가 final_scores를 읽으므로 점수 체인 이후)
	// ─────────────────────────────────────────────
	s.computeBlastEdges(ctx)

	// ─────────────────────────────────────────────
	// Phase 3: 그래프 분석 사전계산 (최신 엣지 기준)
	// ─────────────────────────────────────────────
	if err := s.svc.PrecomputeAll(ctx, s.clusterName); err != nil {
		log.Printf("analysis-scheduler: precompute failed: %v", err)
		return
	}
	log.Printf("analysis-scheduler: pipeline completed, total=%v", time.Since(start))
	// (엣지 retention은 Phase 1 직후 DeleteEdgesBefore(start)로 이미 수행됨)
}

// computeBlastEdges는 host/rbac/network 3채널을 합쳐 blast_edges 테이블을 재적재한다.
// B.Risk(network)가 final_scores를 읽으므로 반드시 Phase 2(점수 체인) 이후에 호출한다.
func (s *AnalysisScheduler) computeBlastEdges(ctx context.Context) {
	if s.blastEdgesRepo == nil {
		return
	}
	pods, snap, err := s.blastEdgesRepo.LoadPods(ctx, s.clusterName)
	if err != nil {
		log.Printf("analysis-scheduler: blast load pods failed: %v", err)
		return
	}
	if len(pods) == 0 {
		return
	}
	perms, err := s.blastEdgesRepo.LoadPerms(ctx, s.clusterName)
	if err != nil {
		log.Printf("analysis-scheduler: blast load perms failed: %v", err)
		return
	}
	// 관측 flow는 직접 탐지하지 않고 edges 테이블(connects_to/observed)에서 가져온다.
	flows, err := s.blastEdgesRepo.LoadObservedFlows(ctx, s.clusterName)
	if err != nil {
		log.Printf("analysis-scheduler: blast load flows failed: %v", err)
	}
	edges := blastedge.BuildEdges(pods, perms, flows)
	n, err := s.blastEdgesRepo.Replace(ctx, s.clusterName, snap, edges, pods)
	if err != nil {
		log.Printf("analysis-scheduler: blast edges replace failed: %v", err)
		return
	}
	log.Printf("analysis-scheduler: blast edges computed (%d edges, snapshot=%s)", n, snap.Format(time.RFC3339))
}
