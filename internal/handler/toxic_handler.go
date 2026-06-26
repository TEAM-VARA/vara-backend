package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// ToxicHandler는 Toxic Combination 평가 API를 담당합니다.
//
// 엔드포인트:
//
//	POST /api/v1/scoring/toxic/compute
//	  Body: { "cluster_name": "..." }
//	  → 클러스터 전체 Pod에 대해 룰 평가 + 저장
//
//	GET  /api/v1/scoring/toxic/pods/:pod_uid?cluster=<name>
//	GET  /api/v1/scoring/toxic/clusters/:cluster_name
//	GET  /api/v1/scoring/toxic/rules    (정적 룰 목록)
type ToxicHandler struct {
	service *service.ToxicService
}

// NewToxicHandler는 ToxicHandler를 생성합니다.
func NewToxicHandler(svc *service.ToxicService) *ToxicHandler {
	return &ToxicHandler{service: svc}
}

// Compute : POST /api/v1/scoring/toxic/compute
func (h *ToxicHandler) Compute(c *gin.Context) {
	var req scoring.ToxicComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	response, err := h.service.ComputeForCluster(ctx, req.ClusterName)
	if err != nil {
		fmt.Printf("warn: toxic compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ComputeForPod는 단일 Pod의 toxic combination을 즉시 재계산합니다.
func (h *ToxicHandler) ComputeForPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}

	var req scoring.ComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	result, err := h.service.ComputeForPod(ctx, req.ClusterName, podUID)
	if err != nil {
		fmt.Printf("warn: toxic compute pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByPod : GET /api/v1/scoring/toxic/pods/:pod_uid?cluster=<name>
func (h *ToxicHandler) GetByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	clusterName := c.Query("cluster")

	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster query parameter is required"})
		return
	}

	ctx := c.Request.Context()
	result, err := h.service.GetByPodUID(ctx, clusterName, podUID)
	if err != nil {
		fmt.Printf("warn: toxic get by pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "toxic result not found",
			"code":    "NOT_COMPUTED",
			"hint":    "POST /api/v1/scoring/toxic/compute first",
			"pod_uid": podUID,
			"cluster": clusterName,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByCluster : GET /api/v1/scoring/toxic/clusters/:cluster_name
func (h *ToxicHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	ctx := c.Request.Context()
	results, err := h.service.ListByCluster(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: toxic list by cluster failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	matched := 0
	for _, r := range results {
		if r.Multiplier > 1.0 {
			matched++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name":  clusterName,
		"total":         len(results),
		"matched_total": matched,
		"results":       results,
	})
}

// ListRules : GET /api/v1/scoring/toxic/rules
func (h *ToxicHandler) ListRules(c *gin.Context) {
	// 룰의 함수 필드는 JSON 직렬화 안 됨 → 메타데이터만 추출
	type ruleMeta struct {
		RuleID      string  `json:"rule_id"`
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Severity    string  `json:"severity"`
		Multiplier  float64 `json:"multiplier"`
	}
	rules := make([]ruleMeta, 0, len(scoring.AllToxicRules))
	for _, r := range scoring.AllToxicRules {
		rules = append(rules, ruleMeta{
			RuleID:      r.RuleID,
			Name:        r.Name,
			Description: r.Description,
			Severity:    r.Severity,
			Multiplier:  r.Multiplier,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"total": len(rules),
		"rules": rules,
	})
}
