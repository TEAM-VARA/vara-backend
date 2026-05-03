package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type HealthHandler struct {
	pg  *pgxpool.Pool
	rdb *redis.Client
}

func NewHealth(pg *pgxpool.Pool, rdb *redis.Client) *HealthHandler {
	return &HealthHandler{pg: pg, rdb: rdb}
}

// Healthz : 서버 + DB 살아있는지 확인
func (h *HealthHandler) Healthz(c *gin.Context) {
	ctx := c.Request.Context()

	if err := h.pg.Ping(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "postgres down"})
		return
	}
	if err := h.rdb.Ping(ctx).Err(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"status": "redis down"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
