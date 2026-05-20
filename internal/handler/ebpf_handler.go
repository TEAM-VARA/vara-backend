package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/ebpf"
	"github.com/vara/backend/internal/repository/postgres"
)

// EbpfHandler : eBPF Agent (Tetragon) 핸들러
//
// 공통 헤더:
//   X-Customer-ID  → customer_id, cluster_name
//   X-Node-Name    → node_name (페이로드 node와 일치 검증)
type EbpfHandler struct {
	repo *postgres.EbpfRepo
}

func NewEbpf(repo *postgres.EbpfRepo) *EbpfHandler {
	return &EbpfHandler{repo: repo}
}

// extractEbpfHeaders : 공통 헤더 추출 + 검증
func extractEbpfHeaders(c *gin.Context) (string, string, bool) {
	customerID := c.GetHeader("X-Customer-ID")
	if customerID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Customer-ID header required"})
		return "", "", false
	}

	nodeName := c.GetHeader("X-Node-Name")
	if nodeName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Node-Name header required"})
		return "", "", false
	}

	return customerID, nodeName, true
}

// NetworkFlows : POST /api/v1/agents/ebpf/network-flows
func (h *EbpfHandler) NetworkFlows(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.NetworkFlowsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	saved, err := h.repo.UpsertNetworkFlows(c.Request.Context(), customerID, req)
	if err != nil {
		fmt.Printf("warn: ebpf network-flows failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":     req.Node,
		"received": len(req.Events),
		"saved":    saved,
	})
}

// DNSQueries : POST /api/v1/agents/ebpf/dns-queries
func (h *EbpfHandler) DNSQueries(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.DNSQueriesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	saved, err := h.repo.UpsertDNSQueries(c.Request.Context(), customerID, req)
	if err != nil {
		fmt.Printf("warn: ebpf dns-queries failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":     req.Node,
		"received": len(req.Events),
		"saved":    saved,
	})
}

// ProcessEvents : POST /api/v1/agents/ebpf/process-events
func (h *EbpfHandler) ProcessEvents(c *gin.Context) {
	customerID, nodeName, ok := extractEbpfHeaders(c)
	if !ok {
		return
	}

	var req ebpf.ProcessEventsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Node != nodeName {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("node mismatch: header=%s, body=%s", nodeName, req.Node),
		})
		return
	}

	saved, err := h.repo.UpsertProcessEvents(c.Request.Context(), customerID, req)
	if err != nil {
		fmt.Printf("warn: ebpf process-events failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"node":     req.Node,
		"received": len(req.Events),
		"saved":    saved,
	})
}