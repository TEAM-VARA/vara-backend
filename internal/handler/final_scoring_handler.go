package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// FinalScoringHandler는 Final Score API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/scoring/final/compute
//     Body: { "cluster_name": "..." }
//     → 클러스터 전체 Pod의 Final Score 계산 + 저장
//     사전 조건:
//       - 작업 B-2 (local_scores) 완료
//       - 작업 B-3a (image_global_scores) 캐시 채워둠
//
//   GET /api/v1/scoring/final/pods/:pod_uid?cluster=<name>
//   GET /api/v1/scoring/final/clusters/:cluster_name
type FinalScoringHandler struct {
	service *service.FinalScoringService
}

// NewFinalScoringHandler는 FinalScoringHandler를 생성합니다.
func NewFinalScoringHandler(svc *service.FinalScoringService) *FinalScoringHandler {
	return &FinalScoringHandler{service: svc}
}

// Compute : POST /api/v1/scoring/final/compute
func (h *FinalScoringHandler) Compute(c *gin.Context) {
	var req scoring.FinalComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	response, err := h.service.ComputeForCluster(ctx, req.ClusterName)
	if err != nil {
		fmt.Printf("warn: final compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetByPod : GET /api/v1/scoring/final/pods/:pod_uid?cluster=<name>
func (h *FinalScoringHandler) GetByPod(c *gin.Context) {
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
		fmt.Printf("warn: final get by pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "final score not found",
			"hint":    "POST /api/v1/scoring/final/compute first",
			"pod_uid": podUID,
			"cluster": clusterName,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByCluster : GET /api/v1/scoring/final/clusters/:cluster_name
func (h *FinalScoringHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	ctx := c.Request.Context()
	results, err := h.service.ListByCluster(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: final list by cluster failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	critical, high, medium, low := 0, 0, 0, 0
	for _, r := range results {
		switch {
		case r.FinalScore >= 90:
			critical++
		case r.FinalScore >= 70:
			high++
		case r.FinalScore >= 40:
			medium++
		case r.FinalScore > 0:
			low++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name":  clusterName,
		"total":         len(results),
		"critical_risk": critical,
		"high_risk":     high,
		"medium_risk":   medium,
		"low_risk":      low,
		"results":       results,
	})
}
