package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/vara/backend/internal/domain/agent"
	"github.com/vara/backend/internal/service"
)

type AgentHandler struct {
	pg      *pgxpool.Pool
	rdb     *redis.Client
	service *service.AgentService
}

func NewAgent(pg *pgxpool.Pool, rdb *redis.Client, svc *service.AgentService) *AgentHandler {
	return &AgentHandler{pg: pg, rdb: rdb, service: svc}
}

// Pods : POST /api/v1/agents/cluster-reader/pods
//
// Pod 생성/삭제 이벤트 batch 수신.
// Body 예시:
//
//	{
//	  "events": [
//	    {
//	      "event_type": "pod_added",
//	      "pod_uid": "abc-123",
//	      "pod_name": "checkout-7d4f",
//	      "namespace": "frontend",
//	      "node_name": "worker-1",
//	      "ip": "10.0.1.5",
//	      "image": "checkout:v1.2.3",
//	      "image_digest": "sha256:..."
//	    }
//	  ]
//	}
func (h *AgentHandler) Pods(c *gin.Context) {
	var batch agent.PodEventBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	res := h.service.IngestPodEvents(ctx, batch)

	c.JSON(http.StatusOK, res)
}

// Services : POST /api/v1/agents/cluster-reader/services
// (다른 팀원이 채울 자리 - 일단 TODO)
func (h *AgentHandler) Services(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"received": true, "todo": "service ingest 미구현"})
}

// Nodes : POST /api/v1/agents/cluster-reader/nodes
// (다른 팀원이 채울 자리 - 일단 TODO)
func (h *AgentHandler) Nodes(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"received": true, "todo": "node ingest 미구현"})
}

// Traffic : POST /api/v1/agents/ebpf/traffic
//
// Body 예시:
//
//	{
//	  "events": [
//	    { "timestamp": "...", "src_ip": "10.0.1.5", "dst_ip": "10.0.2.7",
//	      "bytes": 1024, "packets": 14 }
//	  ]
//	}
func (h *AgentHandler) Traffic(c *gin.Context) {
	var batch agent.TrafficBatch
	if err := c.ShouldBindJSON(&batch); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	saved, err := h.service.IngestTraffic(ctx, batch)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"received": len(batch.Events),
		"saved":    saved,
	})
}

// SBOM : POST /api/v1/agents/sbom
//
// Body 예시:
//
//	{
//	  "image": "paylink/payment:v2.3.0",
//	  "image_digest": "sha256:abc...",
//	  "cves": [
//	    { "cve_id": "CVE-2021-44228", "severity": "CRITICAL",
//	      "cvss_score": 10.0, "package_name": "log4j-core" }
//	  ]
//	}
func (h *AgentHandler) SBOM(c *gin.Context) {
	var req agent.SBOMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	cveCount, err := h.service.IngestSBOM(ctx, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image":        req.Image,
		"image_digest": req.ImageDigest,
		"cve_count":    cveCount,
		"message":      fmt.Sprintf("SBOM 등록 완료 — CVE %d건 저장", cveCount),
	})
}
