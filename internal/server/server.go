package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/config"
	"github.com/vara/backend/internal/external/trivy"
	"github.com/vara/backend/internal/handler"
	"github.com/vara/backend/internal/platform/epss"
	"github.com/vara/backend/internal/platform/exploitdb"
	"github.com/vara/backend/internal/platform/kev"
	"github.com/vara/backend/internal/platform/nvd"
	"github.com/vara/backend/internal/platform/osv"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/scheduler"
	"github.com/vara/backend/internal/service"
)

type Server struct {
	cfg     *config.Config
	httpSrv *http.Server
}

func New(cfg *config.Config, pg *pgxpool.Pool, rdb *redis.Client) *Server {
	// ── Repository ──
	agentRepo := postgres.NewAgentRepo(pg)
	scoringRepo := postgres.NewScoringRepo(pg)
	clusterReaderRepo := postgres.NewClusterReaderRepo(pg)
	sbomRepo := postgres.NewSBOMRepo(pg)
	exposureRepo := postgres.NewExposureRepo(pg)
	globalScoringRepo := postgres.NewGlobalScoringRepo(pg)
	attackPathRepo := postgres.NewAttackPathRepo(pg)
	localScoringRepo := postgres.NewLocalScoringRepo(pg)
	imageGlobalRepo := postgres.NewImageGlobalRepo(pg)
	finalScoringRepo := postgres.NewFinalScoringRepo(pg)
	toxicRepo := postgres.NewToxicRepo(pg)
	sbomPackageRepo := postgres.NewSBOMPackageRepo(pg)
	packageVulnRepo := postgres.NewPackageVulnerabilityRepo(pg) // 신규 (작업 B-6)
	ebpfRepo := postgres.NewEbpfRepo(pg)                        // 신규 (dev_v2 통합)
	clusterNodesRepo := postgres.NewClusterNodesRepo(pg)
	edgesRepo := postgres.NewEdgesRepo(pg)                 // 신규 (runtime 분석)                     // 신규 (dev_v2 통합)
	notifRepo := postgres.NewNotificationRepo(pg)          // 신규 (대시보드 알림)
	analysisCacheRepo := postgres.NewAnalysisCacheRepo(pg) // 신규 (그래프 분석 캐시)

	// ── 외부 API 클라이언트 ──
	nvdAPIKey := os.Getenv("NVD_API_KEY")
	if nvdAPIKey == "" {
		fmt.Printf("warn: NVD_API_KEY is empty, rate limit 5req/30s applies\n")
	} else {
		fmt.Printf("info: NVD_API_KEY loaded (rate limit 50req/30s)\n")
	}
	nvdClient := nvd.NewClient(nvdAPIKey)
	epssClient := epss.NewClient()
	kevClient := kev.NewClient()
	exploitDBClient := exploitdb.NewClient()
	osvClient := osv.NewClient() // 신규 (작업 B-6)

	// ── Trivy ──
	trivyClient := trivy.NewClient()
	{
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := trivyClient.CheckBinary(checkCtx); err != nil {
			fmt.Printf("warn: trivy binary check failed: %v\n", err)
		} else {
			fmt.Printf("info: trivy binary check OK\n")
		}
		cancel()
	}

	// ── Service ──
	agentSvc := service.NewAgentService(agentRepo)
	scoringSvc := service.NewScoringService(nvdClient, epssClient, kevClient, exploitDBClient)
	sbomSvc := service.NewSBOMService(trivyClient, sbomRepo, rdb, service.SBOMServiceConfig{
		MaxConcurrent: 1,
	})
	exposureSvc := service.NewExposureService(exposureRepo, ebpfRepo, clusterNodesRepo)
	globalScoringSvc := service.NewGlobalScoringService(
		nvdClient, epssClient, kevClient, exploitDBClient, globalScoringRepo,
	)
	attackPathSvc := service.NewAttackPathService(attackPathRepo, ebpfRepo, clusterNodesRepo)
	localScoringSvc := service.NewLocalScoringService(localScoringRepo)
	imageGlobalCacheSvc := service.NewImageGlobalCacheService(imageGlobalRepo, globalScoringSvc)
	toxicSvc := service.NewToxicService(toxicRepo)
	finalScoringSvc := service.NewFinalScoringService(finalScoringRepo, toxicSvc)
	sbomPackageSvc := service.NewSBOMPackageService(pg, sbomPackageRepo)
	packageVulnSvc := service.NewPackageVulnService(osvClient, packageVulnRepo, sbomPackageRepo) // 신규 (B-6)
	notifSvc := service.NewNotificationService(notifRepo)                                        // 신규 (대시보드 알림)
	analysisSvc := service.NewAnalysisService(edgesRepo, analysisCacheRepo)                      // 신규 (그래프 분석)
	edgeSvc := service.NewEdgeService(edgesRepo)                                                 // 신규 (blast radius)  ← 추가

	// ── Handler ──
	healthH := handler.NewHealth(pg, rdb)
	agentH := handler.NewAgent(pg, rdb, agentSvc)
	ismspH := handler.NewISMSP(pg)
	scoringH := handler.NewScoring(scoringRepo, scoringSvc)
	clusterReaderH := handler.NewClusterReader(clusterReaderRepo, sbomSvc)
	exposureH := handler.NewExposureHandler(exposureSvc)
	globalScoringH := handler.NewGlobalScoringHandler(globalScoringSvc)
	attackPathH := handler.NewAttackPathHandler(attackPathSvc)
	localScoringH := handler.NewLocalScoringHandler(localScoringSvc)
	imageGlobalCacheH := handler.NewImageGlobalCacheHandler(imageGlobalCacheSvc)
	finalScoringH := handler.NewFinalScoringHandler(finalScoringSvc)
	toxicH := handler.NewToxicHandler(toxicSvc)
	sbomPackageH := handler.NewSBOMPackageHandler(sbomPackageSvc)
	packageVulnH := handler.NewPackageVulnHandler(packageVulnSvc) // 신규 (B-6)
	ebpfH := handler.NewEbpf(ebpfRepo, pg)                        // 신규 (dev_v2 통합)
	edgeH := handler.NewEdgeHandler(edgeSvc)
	podRefreshH := handler.NewPodRefreshHandler(exposureSvc, attackPathSvc, localScoringSvc, toxicSvc, finalScoringSvc)
	notifH := handler.NewNotificationHandler(notifSvc)
	r := newRouter(healthH, agentH, ismspH, scoringH, clusterReaderH,
		exposureH, globalScoringH, attackPathH, localScoringH, imageGlobalCacheH,
		finalScoringH, toxicH, sbomPackageH, packageVulnH, ebpfH, edgeH, podRefreshH,
		notifH)
	// ── Vuln Scheduler 시작 (자동 OSV 스캔 + 알림 + Risk 재계산) ──
	// ENV로 ON/OFF, 기본 활성
	if os.Getenv("DISABLE_VULN_SCANNER") != "true" {
		clusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
		if clusterName == "" {
			clusterName = "vara-eks-test"
		}

		scanInterval := 1 * time.Hour
		if envInterval := os.Getenv("VULN_SCAN_INTERVAL_MINUTES"); envInterval != "" {
			if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
				scanInterval = time.Duration(mins) * time.Minute
			}
		}

		vulnScheduler := scheduler.NewVulnScheduler(
			packageVulnSvc,
			notifSvc,
			finalScoringSvc,
			globalScoringRepo,
			clusterName,
			scanInterval,
		)
		vulnScheduler.Start(context.Background())
		log.Printf("server: vuln scheduler started (cluster=%s, interval=%v)", clusterName, scanInterval)
	}
	// ── Analysis Scheduler 시작 (그래프 분석 사전 계산) ──
	if os.Getenv("DISABLE_ANALYSIS_SCHEDULER") != "true" {
		clusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
		if clusterName == "" {
			clusterName = "vara-eks-test"
		}

		analysisInterval := 1 * time.Hour
		if envInterval := os.Getenv("ANALYSIS_INTERVAL_MINUTES"); envInterval != "" {
			if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
				analysisInterval = time.Duration(mins) * time.Minute
			}
		}

		analysisScheduler := scheduler.NewAnalysisScheduler(analysisSvc, clusterName, analysisInterval)
		analysisScheduler.Start(context.Background())
		log.Printf("server: analysis scheduler started (cluster=%s, interval=%v)", clusterName, analysisInterval)
	}
	return &Server{
		cfg: cfg,
		httpSrv: &http.Server{
			Addr:              ":" + cfg.ServerPort,
			Handler:           r,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

func (s *Server) Start() error {
	if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}
