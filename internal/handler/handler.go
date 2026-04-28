package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type Handler struct {
	pg  *pgxpool.Pool
	rdb *redis.Client
}

func New(pg *pgxpool.Pool, rdb *redis.Client) *Handler {
	return &Handler{pg: pg, rdb: rdb}
}

// Health : 서버 + DB 살아있는지 확인
func (h *Handler) Health(c *gin.Context) {
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

// PodEvents : Cluster Reader Agent → Pod 생성/삭제 이벤트 수신
func (h *Handler) PodEvents(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// Traffic : eBPF Agent → 트래픽 데이터 수신
func (h *Handler) Traffic(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// SBOM : SBOM 데이터 수신
func (h *Handler) SBOM(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}
