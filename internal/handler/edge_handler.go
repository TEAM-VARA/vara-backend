package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"

	 "strconv"
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
//
//	cluster_name (required)
//
// 특정 Pod이 source 또는 target인 edges (최신 snapshot).
func (h *EdgeHandler) GetByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	clusterName := c.Param("cluster_name")

	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid required"})
		return
	}
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name required"})
		return
	}

	resp, err := h.svc.ListByPod(c.Request.Context(), clusterName, podUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ComputeIdentity — RBAC 정보로부터 identity layer edges 적재
//
// POST /api/v1/edges/clusters/:cluster_name/identity/compute
func (h *EdgeHandler) ComputeIdentity(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name required"})
		return
	}
	result, err := h.svc.ComputeIdentity(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// ComputeSupplyChain — SBOM/CVE 정보로 supply_chain layer edges 적재
//
// POST /api/v1/edges/clusters/:cluster_name/supply-chain/compute
func (h *EdgeHandler) ComputeSupplyChain(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name required"})
		return
	}
	result, err := h.svc.ComputeSupplyChain(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// ComputeNetwork — Network layer edges 적재
// POST /api/v1/edges/clusters/:cluster_name/network/compute
func (h *EdgeHandler) ComputeNetwork(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name required"})
		return
	}
	result, err := h.svc.ComputeNetwork(c.Request.Context(), clusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetTopology — PM 명세서 B-1
// GET /api/v1/topology?cluster=<name>
func (h *EdgeHandler) GetTopology(c *gin.Context) {
	cluster := c.Query("cluster")
	if cluster == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster query param required"})
		return
	}
	result, err := h.svc.BuildTopology(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// GetBlastRadius — PM 명세서 B-2
// GET /api/v1/topology/blast-radius?cluster=<name>&source=<pod_uid>&hops=<1|2|3>
func (h *EdgeHandler) GetBlastRadius(c *gin.Context) {
	cluster := c.Query("cluster")
	source := c.Query("source")
	hopsStr := c.DefaultQuery("hops", "3")

	if cluster == "" || source == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "cluster and source query params required",
		})
		return
	}

	hops, err := strconv.Atoi(hopsStr)
	if err != nil || hops < 1 || hops > 5 {
		hops = 3
	}

	result, err := h.svc.BuildBlastRadius(c.Request.Context(), cluster, source, hops)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}
