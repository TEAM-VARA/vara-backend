package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/config"
	"github.com/vara/backend/internal/external/trivy"
	"github.com/vara/backend/internal/handler"
	"github.com/vara/backend/internal/platform/advisory"
	"github.com/vara/backend/internal/platform/embedding"
	"github.com/vara/backend/internal/platform/epss"
	"github.com/vara/backend/internal/platform/jwtutil"
	"github.com/vara/backend/internal/platform/exploitdb"
	"github.com/vara/backend/internal/platform/kev"
	"github.com/vara/backend/internal/platform/nvd"
	"github.com/vara/backend/internal/platform/depsdev"
	"github.com/vara/backend/internal/platform/osv"
	"github.com/vara/backend/internal/platform/vlm"
	"github.com/vara/backend/internal/rbacchain/loader"
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
	versionReleaseRepo := postgres.NewVersionReleaseRepo(pg)    // 신규 (deps.dev 버전 릴리스)
	ebpfRepo := postgres.NewEbpfRepo(pg)                        // 신규 (dev_v2 통합)
	clusterNodesRepo := postgres.NewClusterNodesRepo(pg)
	edgesRepo := postgres.NewEdgesRepo(pg)                 // 신규 (runtime 분석)                     // 신규 (dev_v2 통합)
	notifRepo := postgres.NewNotificationRepo(pg)          // 신규 (대시보드 알림)
	analysisCacheRepo := postgres.NewAnalysisCacheRepo(pg) // 신규 (그래프 분석 캐시)
	rbacChainRepo := postgres.NewRBACChainRepo(pg)         // 신규 (RBAC 권한상승 분석)

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
	osvClient := osv.NewClient()       // 신규 (작업 B-6)
	depsDevClient := depsdev.NewClient() // 신규 (deps.dev 버전 릴리스)
	advisoryClient := advisory.NewClient() // 신규 (CVE narrative enrichment — advisory fetch)

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
	vlmClient := vlm.NewClient(os.Getenv("VLM_SERVER_URL"), os.Getenv("VLM_MODEL")) // CVSS 결측 보완(AI) + GRC 공용
	globalScoringSvc := service.NewGlobalScoringService(
		nvdClient, epssClient, kevClient, exploitDBClient, globalScoringRepo,
		packageVulnRepo, vlmClient,
	)
	attackPathSvc := service.NewAttackPathService(attackPathRepo, ebpfRepo, clusterNodesRepo)
	localScoringSvc := service.NewLocalScoringService(localScoringRepo)
	imageGlobalCacheSvc := service.NewImageGlobalCacheService(imageGlobalRepo, globalScoringSvc)
	toxicSvc := service.NewToxicService(toxicRepo)
	finalScoringSvc := service.NewFinalScoringService(finalScoringRepo, toxicSvc)
	breakdownSvc := service.NewBreakdownService(finalScoringRepo, globalScoringRepo, localScoringRepo, toxicRepo)
	breakdownH := handler.NewBreakdownHandler(breakdownSvc)
	sbomPackageSvc := service.NewSBOMPackageService(pg, sbomPackageRepo)
	packageVulnSvc := service.NewPackageVulnService(osvClient, packageVulnRepo, sbomPackageRepo) // 신규 (B-6)
	// SBOM 스캔 직후 sbom_packages 추출 + osv 매칭 자동 보강 (이미지 교체 시 수동 backfill 불필요)
	sbomSvc.SetEnrichment(sbomPackageSvc, packageVulnSvc)
	depsDevSvc := service.NewDepsDevService(depsDevClient, versionReleaseRepo, sbomPackageRepo, packageVulnRepo) // 신규 (deps.dev)
	notifSvc := service.NewNotificationService(notifRepo)                                        // 신규 (대시보드 알림)
	analysisSvc := service.NewAnalysisService(edgesRepo, analysisCacheRepo, pg)                      // 신규 (그래프 분석)
	edgeSvc := service.NewEdgeService(edgesRepo)                                                 // 신규 (blast radius)  ← 추가
	// RBAC Chain: DB 직접 로더(PostgresLoader) + fixpoint 엔진
	rbacChainLoader := loader.NewPostgresLoader(pg)
	rbacChainSvc := service.NewRBACChainService(
		rbacChainLoader, rbacChainRepo, os.Getenv("RBAC_CHAIN_INCLUDE_EKS") == "true",
	)

	// ── GRC Compliance Check ──
	grcRepo := postgres.NewGRCRepo(pg)
	rulesetStore := service.NewRulesetStore("rulesets")
	embClient := embedding.NewClient(os.Getenv("EMBEDDING_SERVER_URL"))
	grcSvc := service.NewGRCService(grcRepo, clusterReaderRepo, rulesetStore, embClient, vlmClient)
	// 이전 컨테이너 재시작으로 중단된 running/queued 체크를 failed로 초기화
	{
		resetCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if n, err := grcSvc.ResetStaleChecks(resetCtx); err != nil {
			fmt.Printf("warn: failed to reset stale checks: %v\n", err)
		} else if n > 0 {
			log.Printf("server: reset %d stale running/queued checks to failed", n)
		}
		cancel()
	}

	// ── Handler ──
	healthH := handler.NewHealth(pg, rdb)
	agentH := handler.NewAgent(pg, rdb, agentSvc)
	ismspH := handler.NewISMSP(pg)
	scoringH := handler.NewScoring(scoringRepo, scoringSvc, grcSvc)
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
	depsDevH := handler.NewDepsDevHandler(depsDevSvc)             // 신규 (deps.dev)
	ebpfH := handler.NewEbpf(ebpfRepo, pg)                        // 신규 (dev_v2 통합)
	edgeH := handler.NewEdgeHandler(edgeSvc)
	podRefreshH := handler.NewPodRefreshHandler(exposureSvc, attackPathSvc, localScoringSvc, toxicSvc, finalScoringSvc)
	notifH := handler.NewNotificationHandler(notifSvc)
	analysisH := handler.NewAnalysisHandler(analysisCacheRepo, analysisSvc)
	rbacChainH := handler.NewRBACChainHandler(rbacChainSvc)
	grcH := handler.NewGRC(grcSvc, rulesetStore)
	podDetailH := handler.NewPodDetailHandler(clusterReaderRepo, grcSvc)

	// ── AWS Reader ──
	awsReaderRepo := postgres.NewAwsReaderRepo(pg)
	awsReaderH := handler.NewAwsReaderHandler(awsReaderRepo)

	// ── Scenario (공격 시나리오/보완 줄글, attack-path 신호 + blast 전파 엣지 + 노출/정밀 RBAC 기반) ──
	blastEdgesRepo := postgres.NewBlastEdgesRepo(pg)
	// CVE narrative enrichment(설계서 §4): per-CVE 추출·캐시. nil-safe(의존성 미가동 시 generic 폴백).
	cveEnrichmentRepo := postgres.NewCVEEnrichmentRepo(pg)
	cveEnrichmentSvc := service.NewCVEEnrichmentService(cveEnrichmentRepo, globalScoringRepo, nvdClient, advisoryClient, vlmClient)
	scenarioSvc := service.NewScenarioService(attackPathSvc, finalScoringSvc, globalScoringRepo, blastEdgesRepo, exposureSvc, rbacChainSvc, grcSvc, cveEnrichmentSvc)
	scenarioH := handler.NewScenarioHandler(scenarioSvc)
	blastGraph := &service.BlastGraphHandler{Pool: pg}

	// ── Auth (로그인 + TOTP MFA) ──
	authSecret := os.Getenv("AUTH_JWT_SECRET")
	if authSecret == "" {
		authSecret = os.Getenv("JWT_SECRET")
	}
	if authSecret == "" {
		authSecret = "vara-dev-insecure-secret-change-me"
		fmt.Printf("warn: AUTH_JWT_SECRET/JWT_SECRET empty, using insecure dev secret (set in prod)\n")
	}
	authIssuer := os.Getenv("AUTH_ISSUER")
	if authIssuer == "" {
		authIssuer = "VARA"
	}
	authRepo := postgres.NewAuthRepo(pg)
	jwtMgr := jwtutil.NewManager(authSecret, authIssuer)
	authSvc := service.NewAuthService(authRepo, jwtMgr, rdb, authIssuer)
	authH := handler.NewAuthHandler(authSvc)

	// ── Vuln Scheduler (자동 스캔 + 데모 트리거 공용 인스턴스) ──
	vulnClusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
	if vulnClusterName == "" {
		vulnClusterName = "vara-eks-test"
	}
	vulnScanInterval := 1 * time.Hour
	if envInterval := os.Getenv("VULN_SCAN_INTERVAL_MINUTES"); envInterval != "" {
		if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
			vulnScanInterval = time.Duration(mins) * time.Minute
		}
	}
	vulnScheduler := scheduler.NewVulnScheduler(
		packageVulnSvc, notifSvc, finalScoringSvc, globalScoringRepo, imageGlobalCacheSvc,
		vulnClusterName, vulnScanInterval,
	)

	// ── Risk Scoring 가중치 (전역 단일 설정) ──
	scoringWeightsRepo := postgres.NewScoringWeightsRepo(pg)
	weightsSvc := service.NewWeightsService(scoringWeightsRepo, finalScoringSvc, toxicSvc, vlmClient, globalScoringRepo, imageGlobalCacheSvc, sbomRepo, vulnClusterName)
	weightsH := handler.NewWeightsHandler(weightsSvc)
	{
		loadCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := weightsSvc.LoadIntoRuntime(loadCtx); err != nil {
			fmt.Printf("warn: load scoring weights failed (using defaults): %v\n", err)
		} else {
			log.Printf("server: scoring weights loaded into runtime")
		}
		cancel()
	}

	r := newRouter(healthH, agentH, ismspH, scoringH, clusterReaderH,
		exposureH, globalScoringH, attackPathH, localScoringH, imageGlobalCacheH,
		finalScoringH, toxicH, sbomPackageH, packageVulnH, depsDevH, ebpfH, edgeH, podRefreshH,
		notifH, analysisH, rbacChainH, grcH, breakdownH, podDetailH, awsReaderH, scenarioH, authH)
	r.GET("/api/v1/scoring/blast-graph", blastGraph.Handle)
	// ── blast_pair_risk 읽기 (orbital 랭킹/가중치) ──
	r.GET("/api/v1/scoring/blast-pairs", blastGraph.PairsBySource)          // ?cluster=&src=   : 소스별 도달 목록(reach_prob+total_risk)
	r.GET("/api/v1/scoring/blast-pairs/top-sources", blastGraph.TopSources) // ?cluster=&limit= : total_risk 랭킹(폭발원 top N)
	r.GET("/api/v1/scoring/blast-pairs/top-pairs", blastGraph.TopPairs)     // ?cluster=&limit= : reach_prob 랭킹(위험 쌍 top N)

	// ── 데모용: 특정 vuln_id로 신규 CVE 알림+점수변화 즉시 실행 (발표 실연, dedup 없음, 임시) ──
	r.POST("/api/v1/scoring/demo/new-cve", func(c *gin.Context) {
		vulnID := c.Query("vuln_id")
		if vulnID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "vuln_id query param required"})
			return
		}
		res, err := vulnScheduler.RunDemoForVuln(c.Request.Context(), vulnID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, res)
	})

	// ── Risk Scoring 가중치 조회/설정 (전역 단일 설정) ──
	r.GET("/api/v1/scoring/weights", weightsH.Get)
	r.PUT("/api/v1/scoring/weights", weightsH.Update)
	r.POST("/api/v1/scoring/weights/recommend", weightsH.Recommend) // AI 추천(통계+선택 운영자설명), 자동적용 X

	// ── Vuln Scheduler 시작 (자동 OSV 스캔 + 알림 + Risk 재계산) ──
	// ENV로 ON/OFF, 기본 활성
	if os.Getenv("DISABLE_VULN_SCANNER") != "true" {
		vulnScheduler.Start(context.Background())
		log.Printf("server: vuln scheduler started (cluster=%s, interval=%v)", vulnClusterName, vulnScanInterval)
	}
	// ── GRC Scheduler 시작 (클러스터 컴플라이언스 자동 평가) ──
	if os.Getenv("DISABLE_GRC_SCHEDULER") != "true" {
		grcClusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
		if grcClusterName == "" {
			grcClusterName = "vara-eks-test"
		}
		grcInterval := 1 * time.Hour
		if envInterval := os.Getenv("GRC_INTERVAL_MINUTES"); envInterval != "" {
			if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
				grcInterval = time.Duration(mins) * time.Minute
			}
		}

		grcScheduler := scheduler.NewGRCScheduler(grcSvc, grcClusterName, grcInterval)
		grcScheduler.Start(context.Background())
		log.Printf("server: grc scheduler started (cluster=%s, interval=%v)", grcClusterName, grcInterval)
	}
	// ── GL Scheduler 시작 (지침서 기반 LLM 점검 자동 실행) ──
	if os.Getenv("DISABLE_GL_SCHEDULER") != "true" {
		glInterval := 24 * time.Hour
		if h := os.Getenv("GL_INTERVAL_HOURS"); h != "" {
			if hrs, err := strconv.Atoi(h); err == nil && hrs > 0 {
				glInterval = time.Duration(hrs) * time.Hour
			}
		}
		glScheduler := scheduler.NewGLScheduler(grcSvc, glInterval)
		glScheduler.Start(context.Background())
		log.Printf("server: gl scheduler started (interval=%v)", glInterval)
	}
	// ── DepsDev Scheduler 시작 (패키지 버전 릴리스 날짜 자동 수집) ──
	if os.Getenv("DISABLE_DEPSDEV_SCHEDULER") != "true" {
		depsDevInterval := 24 * time.Hour
		if h := os.Getenv("DEPSDEV_INTERVAL_HOURS"); h != "" {
			if hrs, err := strconv.Atoi(h); err == nil && hrs > 0 {
				depsDevInterval = time.Duration(hrs) * time.Hour
			}
		}
		depsDevScheduler := scheduler.NewDepsDevScheduler(depsDevSvc, depsDevInterval)
		depsDevScheduler.Start(context.Background())
		log.Printf("server: depsdev scheduler started (interval=%v)", depsDevInterval)
	}
	// ── Analysis Scheduler 시작 (그래프 분석 사전 계산) ──
	if os.Getenv("DISABLE_ANALYSIS_SCHEDULER") != "true" {
		clusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
		if clusterName == "" {
			clusterName = "vara-eks-test"
		}

		analysisInterval := 15 * time.Minute
		if envInterval := os.Getenv("ANALYSIS_INTERVAL_MINUTES"); envInterval != "" {
			if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
				analysisInterval = time.Duration(mins) * time.Minute
			}
		}

		scoreRetentionRepo := postgres.NewScoreRetentionRepo(pg)
		analysisScheduler := scheduler.NewAnalysisScheduler(
			analysisSvc,
			edgesRepo,
			blastEdgesRepo,
			exposureSvc,
			attackPathSvc,
			localScoringSvc,
			toxicSvc,
			finalScoringSvc,
			scoreRetentionRepo,
			clusterName,
			analysisInterval,
		)
		analysisScheduler.Start(context.Background())
		log.Printf("server: analysis scheduler started (cluster=%s, interval=%v)", clusterName, analysisInterval)
	}
	// ── RBAC Chain Scheduler 시작 (권한상승 fixpoint 분석 자동 실행) ──
	if os.Getenv("DISABLE_RBAC_CHAIN_SCHEDULER") != "true" {
		clusterName := os.Getenv("DEFAULT_CLUSTER_NAME")
		if clusterName == "" {
			clusterName = "vara-eks-test"
		}

		rbacChainInterval := 30 * time.Minute
		if envInterval := os.Getenv("RBAC_CHAIN_INTERVAL_MINUTES"); envInterval != "" {
			if mins, err := strconv.Atoi(envInterval); err == nil && mins > 0 {
				rbacChainInterval = time.Duration(mins) * time.Minute
			}
		}

		rbacChainScheduler := scheduler.NewRBACChainScheduler(
			rbacChainSvc,
			clusterName,
			rbacChainInterval,
		)
		rbacChainScheduler.Start(context.Background())
		log.Printf("server: rbac-chain scheduler started (cluster=%s, interval=%v)", clusterName, rbacChainInterval)
	}
	// ── Flow Retention Scheduler 시작 (ebpf_network_flows 자동 정리) ──
	if os.Getenv("DISABLE_FLOW_RETENTION") != "true" {
		retentionInterval := 1 * time.Hour
		if v := os.Getenv("FLOW_RETENTION_INTERVAL_MINUTES"); v != "" {
			if mins, err := strconv.Atoi(v); err == nil && mins > 0 {
				retentionInterval = time.Duration(mins) * time.Minute
			}
		}
		retentionMaxAge := 2 * 24 * time.Hour
		if v := os.Getenv("FLOW_RETENTION_MAX_AGE_DAYS"); v != "" {
			if days, err := strconv.Atoi(v); err == nil && days > 0 {
				retentionMaxAge = time.Duration(days) * 24 * time.Hour
			}
		}
		retentionMaxRows := int64(5_000_000)
		if v := os.Getenv("FLOW_RETENTION_MAX_ROWS"); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				retentionMaxRows = n
			}
		}
		retentionScheduler := scheduler.NewRetentionScheduler(pg, retentionInterval, retentionMaxAge, retentionMaxRows)
		retentionScheduler.Start(context.Background())
		log.Printf("server: flow retention scheduler started (interval=%v, maxAge=%v, maxRows=%d)", retentionInterval, retentionMaxAge, retentionMaxRows)
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
