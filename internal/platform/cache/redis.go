package cache

import (
	"context"
	"crypto/tls"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/config"
)

func NewRedis(cfg config.RedisConfig) (*redis.Client, error) {
	dbNum, err := strconv.Atoi(cfg.DB)
	if err != nil {
		dbNum = 0
	}

	opts := &redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       dbNum,
	}

	// TLS 활성화 조건:
	//  1) REDIS_TLS=true 환경변수
	//  2) ElastiCache 엔드포인트 (.cache.amazonaws.com)
	useTLS := strings.EqualFold(os.Getenv("REDIS_TLS"), "true") ||
		strings.Contains(cfg.Addr, ".cache.amazonaws.com")

	if useTLS {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return rdb, nil
}
