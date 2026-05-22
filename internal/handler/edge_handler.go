package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// ────────────────────────────────────────────────────
// EdgeHandler — Pod 통신 그래프 (Blast Radius) API
//
// 엔드포인트:
//   POST /api/v1/edges/compute
//   GET  /api/v1/edges/clusters/:cluster_name
//   GET  /api/v1/edges/pods/:pod_uid
// ────────────────────────────────────────────────────

type EdgeHandler struct {
	svc *service.EdgeService
}

func NewEdgeHandler(svc *service.EdgeService) *EdgeHandler {
	return &EdgeHandler{svc: svc}
}

// ────────────────────────────────────────────────────

// computeRequest — POST body
type computeEdgesRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// Compute — POST /api/v1/edges/compute
//
// 최근 N분의 ebpf_network_flows를 집계해서 edges 테이블 갱신.
func (h *EdgeHandler) Compute(c *gin.Context) {
	var req computeEdgesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	resp, err := h.svc.ComputeForCluster(c.Request.Context(), req.ClusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetByCluster — GET /api/v1/edges/clusters/:cluster_name
//
// 클러스터의 모든 edges (최신 snapshot).
func (h *EdgeHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name required"})
		return
	}

	resp, err := h.svc.ListByCluster(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// GetByPod — GET /api/v1/edges/pods/:pod_uid
//
// Query params:
//   cluster_name (required)
//
// 특정 Pod이 source 또는 target인 edges (최신 snapshot).
func (h *EdgeHandler) GetByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	clusterName := c.Query("cluster_name")

	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid required"})
		return
	}
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name query param required"})
		return
	}

	resp, err := h.svc.ListByPod(c.Request.Context(), clusterName, podUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}
