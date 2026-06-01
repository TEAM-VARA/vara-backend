package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// RBACChainHandler는 RBAC 권한상승(fixpoint) 분석 API 입니다.
type RBACChainHandler struct {
	svc *service.RBACChainService
}

func NewRBACChainHandler(svc *service.RBACChainService) *RBACChainHandler {
	return &RBACChainHandler{svc: svc}
}

type rbacChainComputeRequest struct {
	ClusterName string `json:"cluster_name" binding:"required"`
}

// Compute — POST /scoring/rbac-chain/compute
// 한 클러스터를 분석하고 결과를 DB에 덮어쓴다.
func (h *RBACChainHandler) Compute(c *gin.Context) {
	var req rbacChainComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	summary, err := h.svc.Compute(c.Request.Context(), req.ClusterName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cluster_name": req.ClusterName,
		"summary":      summary,
	})
}

// GetByCluster — GET /scoring/rbac-chain/clusters/:cluster_name
// 분석 현황 요약 + SA 성적표 목록.
func (h *RBACChainHandler) GetByCluster(c *gin.Context) {
	cluster := c.Param("cluster_name")
	meta, reports, err := h.svc.GetCluster(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if meta == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "분석 결과 없음 (먼저 compute 실행)", "cluster_name": cluster})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"meta":        meta,
		"sa_reports":  reports,
	})
}

// GetSA — GET /scoring/rbac-chain/clusters/:cluster_name/sa/:namespace/:name
// SA 한 개의 상세(성적표 + 권한상승 경로).
func (h *RBACChainHandler) GetSA(c *gin.Context) {
	cluster := c.Param("cluster_name")
	ns := c.Param("namespace")
	name := c.Param("name")
	detail, err := h.svc.GetSA(c.Request.Context(), cluster, ns, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if detail == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SA 분석 결과 없음", "sa": ns + "/" + name})
		return
	}
	c.JSON(http.StatusOK, detail)
}
