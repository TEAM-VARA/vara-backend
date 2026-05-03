package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/vara/backend/internal/config"
	"github.com/vara/backend/internal/platform/cache"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/server"
)

func main() {
	_ = godotenv.Load()

	cfg := config.Load()

	pg, err := postgres.NewDB(cfg.Postgres)
	if err != nil {
		log.Fatalf("postgres 연결 실패: %v", err)
	}
	defer pg.Close()

	rdb, err := cache.NewRedis(cfg.Redis)
	if err != nil {
		log.Fatalf("redis 연결 실패: %v", err)
	}
	defer rdb.Close()

	log.Println("DB 연결 완료")

	srv := server.New(cfg, pg, rdb)

	go func() {
		log.Printf("VARA backend listening on :%s", cfg.ServerPort)
		if err := srv.Start(); err != nil {
			log.Fatalf("server 종료: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("graceful shutdown 시작")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("graceful shutdown 실패: %v", err)
	}
	log.Println("종료 완료")
}
