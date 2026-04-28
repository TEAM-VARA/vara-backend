package db

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/config"
)

func NewRedis(cfg config.RedisConfig) (*redis.Client, error) {
	dbNum, err := strconv.Atoi(cfg.DB)
	if err != nil {
		dbNum = 0
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       dbNum,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return rdb, nil
}
