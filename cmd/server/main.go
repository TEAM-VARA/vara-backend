package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"

	"github.com/vara/backend/internal/config"
	"github.com/vara/backend/internal/db"
	"github.com/vara/backend/internal/handler"
)

func main() {
	// .env 로드 (없으면 환경변수에서 직접 읽음)
	_ = godotenv.Load()

	cfg := config.Load()

	// PostgreSQL 연결
	pg, err := db.NewPostgres(cfg.Postgres)
	if err != nil {
		log.Fatalf("postgres 연결 실패: %v", err)
	}
	defer pg.Close()

	// Redis 연결
	rdb, err := db.NewRedis(cfg.Redis)
	if err != nil {
		log.Fatalf("redis 연결 실패: %v", err)
	}
	defer rdb.Close()

	log.Println("DB 연결 완료")

	// 라우터 설정
	r := gin.Default()
	h := handler.New(pg, rdb)

	r.GET("/healthz", h.Health)

	// Agent 엔드포인트 (TODO: 팀에서 채워가기)
	api := r.Group("/api/v1")
	{
		api.POST("/agents/cluster-reader/pod-events", h.PodEvents)
		api.POST("/agents/ebpf/traffic", h.Traffic)
		api.POST("/agents/sbom", h.SBOM)
	}

	addr := ":" + cfg.ServerPort
	log.Printf("VARA backend listening on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}
