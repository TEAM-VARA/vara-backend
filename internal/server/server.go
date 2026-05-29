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
	"github.com/vara/backend/internal/platform/embedding"
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
	sbomRepo := postgres.NewSBOMRepo(pg) // 신규

	// ── 외부 API 클라이언트 (Risk Scoring용) ──
	nvdAPIKey := os.Getenv("NVD_API_KEY") // 없어도 동작 (rate limit만 빡빡)
	nvdClient := nvd.NewClient(nvdAPIKey)
	epssClient := epss.NewClient()
	kevClient := kev.NewClient()
	exploitDBClient := exploitdb.NewClient()

	// ── Trivy 클라이언트 (SBOM 스캔용) ──
	trivyClient := trivy.NewClient()
	// 기동 시점 trivy 바이너리 확인 (실패 시 경고만 출력, 서버는 계속 기동)
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
		MaxConcurrent: 1, // 동시 trivy 스캔 최대 3개 (호스트 자원 보호)
	})

	// ── GRC Compliance Check ──
	grcRepo := postgres.NewGRCRepo(pg)
	rulesetStore := service.NewRulesetStore("rulesets")
	embClient := embedding.NewClient(os.Getenv("EMBEDDING_SERVER_URL"))
	grcSvc := service.NewGRCService(grcRepo, clusterReaderRepo, rulesetStore, embClient)

	// ── Handler ──
	healthH := handler.NewHealth(pg, rdb)
	agentH := handler.NewAgent(pg, rdb, agentSvc)
	scoringH := handler.NewScoring(scoringRepo, scoringSvc)
	clusterReaderH := handler.NewClusterReader(clusterReaderRepo, sbomSvc) // 수정: sbomSvc 추가
	grcH := handler.NewGRC(grcSvc, rulesetStore)

	r := newRouter(healthH, agentH, scoringH, clusterReaderH, grcH)

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
