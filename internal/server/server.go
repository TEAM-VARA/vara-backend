package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
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
	"github.com/vara/backend/internal/repository/postgres"
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
	globalScoringRepo := postgres.NewGlobalScoringRepo(pg) // 신규 (작업 B-1)

	// ── 외부 API 클라이언트 (Risk Scoring용) ──
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

	// ── Trivy 클라이언트 (SBOM 스캔용) ──
	trivyClient := trivy.NewClient()
	{
		checkCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := trivyClient.CheckBinary(checkCtx); err != nil {
			fmt.Printf("warn: trivy binary check failed, SBOM scanning unavailable: %v\n", err)
		} else {
			fmt.Printf("info: trivy binary check OK\n")
		}
		cancel()
	}

	// ── Service ──
	agentSvc := service.NewAgentService(agentRepo)
	scoringSvc := service.NewScoringService(nvdClient, epssClient, kevClient, exploitDBClient)
	sbomSvc := service.NewSBOMService(trivyClient, sbomRepo, rdb, service.SBOMServiceConfig{
		MaxConcurrent: 1, // trivy fs cache lock 충돌 방지
	})
	exposureSvc := service.NewExposureService(exposureRepo)
	globalScoringSvc := service.NewGlobalScoringService( // 신규 (작업 B-1)
		nvdClient, epssClient, kevClient, exploitDBClient, globalScoringRepo,
	)

	// ── Handler ──
	healthH := handler.NewHealth(pg, rdb)
	agentH := handler.NewAgent(pg, rdb, agentSvc)
	ismspH := handler.NewISMSP(pg)
	scoringH := handler.NewScoring(scoringRepo, scoringSvc)
	clusterReaderH := handler.NewClusterReader(clusterReaderRepo, sbomSvc)
	exposureH := handler.NewExposureHandler(exposureSvc)
	globalScoringH := handler.NewGlobalScoringHandler(globalScoringSvc) // 신규 (작업 B-1)

	r := newRouter(healthH, agentH, ismspH, scoringH, clusterReaderH, exposureH, globalScoringH)

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
