package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type AgentHandler struct {
	pg  *pgxpool.Pool
	rdb *redis.Client
}

func NewAgent(pg *pgxpool.Pool, rdb *redis.Client) *AgentHandler {
	return &AgentHandler{pg: pg, rdb: rdb}
}

// Pods : Cluster Reader Agent → Pod 목록/이벤트 수신
func (h *AgentHandler) Pods(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// Services : Cluster Reader Agent → Service 수신
func (h *AgentHandler) Services(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// Nodes : Cluster Reader Agent → Node 수신
func (h *AgentHandler) Nodes(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// Traffic : eBPF Agent → 트래픽 데이터 수신
func (h *AgentHandler) Traffic(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}

// SBOM : SBOM 데이터 수신
func (h *AgentHandler) SBOM(c *gin.Context) {
	// TODO: 요청 파싱 후 DB 저장
	c.JSON(http.StatusOK, gin.H{"received": true})
}
