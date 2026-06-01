package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// LocalScoringHandler는 Local Score API를 담당합니다.
//
// 엔드포인트:
//
//	POST /api/v1/scoring/local/compute
//	  Body: { "cluster_name": "..." }
//	  → 클러스터 전체 Pod의 Local Score 계산 + 저장
//	  사전 조건:
//	    - POST /scoring/exposure/compute      먼저 호출
//	    - POST /scoring/attack-path/compute   먼저 호출
//
//	GET /api/v1/scoring/local/pods/:pod_uid?cluster=<name>
//	GET /api/v1/scoring/local/clusters/:cluster_name
type LocalScoringHandler struct {
	service *service.LocalScoringService
}

// NewLocalScoringHandler는 LocalScoringHandler를 생성합니다.
func NewLocalScoringHandler(svc *service.LocalScoringService) *LocalScoringHandler {
	return &LocalScoringHandler{service: svc}
}

// Compute : POST /api/v1/scoring/local/compute
func (h *LocalScoringHandler) Compute(c *gin.Context) {
	var req scoring.LocalComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	response, err := h.service.ComputeForCluster(ctx, req.ClusterName)
	if err != nil {
		fmt.Printf("warn: local compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ComputeForPod는 단일 Pod의 local score를 즉시 재계산합니다.
func (h *LocalScoringHandler) ComputeForPod(c *gin.Context) {
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
		fmt.Printf("warn: local compute pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByPod : GET /api/v1/scoring/local/pods/:pod_uid?cluster=<name>
func (h *LocalScoringHandler) GetByPod(c *gin.Context) {
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
		fmt.Printf("warn: local get by pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "local score not found",
			"hint":    "POST /api/v1/scoring/local/compute first",
			"pod_uid": podUID,
			"cluster": clusterName,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByCluster : GET /api/v1/scoring/local/clusters/:cluster_name
//
// 응답:
//   - total: 전체 Pod 수
//   - emergency_count / warning_count / caution_count / safe_count
//   - exposed_count: exposed=true 인 Pod 수 (부가 정보)
//   - results: local_score 내림차순 정렬된 모든 Pod 결과
func (h *LocalScoringHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	ctx := c.Request.Context()
	results, err := h.service.ListByCluster(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: local list by cluster failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	emergencyCount, warningCount, cautionCount, safeCount := 0, 0, 0, 0
	exposedCount := 0
	for _, r := range results {
		switch {
		case r.LocalScore >= 80:
			emergencyCount++
		case r.LocalScore >= 50:
			warningCount++
		case r.LocalScore >= 20:
			cautionCount++
		default:
			safeCount++
		}
		if r.Exposed {
			exposedCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name":    clusterName,
		"total":           len(results),
		"emergency_count": emergencyCount,
		"warning_count":   warningCount,
		"caution_count":   cautionCount,
		"safe_count":      safeCount,
		"exposed_count":   exposedCount,
		"results":         results,
	})
}
