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
//
//   GET /api/v1/scoring/final/pods/:pod_uid?cluster=<name>
//   GET /api/v1/scoring/final/clusters/:cluster_name
type FinalScoringHandler struct {
	service *service.FinalScoringService
}

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
//
// 응답:
//   - total: 전체 Pod 수
//   - emergency_count / warning_count / caution_count / safe_count
//   - results: final_score 내림차순 정렬된 모든 Pod 결과
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

	emergencyCount, warningCount, cautionCount, safeCount := 0, 0, 0, 0
	for _, r := range results {
		switch {
		case r.FinalScore >= 80:
			emergencyCount++
		case r.FinalScore >= 50:
			warningCount++
		case r.FinalScore >= 20:
			cautionCount++
		default:
			safeCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name":    clusterName,
		"total":           len(results),
		"emergency_count": emergencyCount,
		"warning_count":   warningCount,
		"caution_count":   cautionCount,
		"safe_count":      safeCount,
		"results":         results,
	})
}
