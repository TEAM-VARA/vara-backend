package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// AttackPathHandler는 공격 경로 범위(Attack Path Scope) API를 담당합니다.
//
// 엔드포인트:
//   POST /api/v1/scoring/attack-path/compute
//     Body: { "cluster_name": "..." }
//     → 클러스터 전체 Pod 평가 + DB 저장
//
//   GET  /api/v1/scoring/attack-path/pods/:pod_uid?cluster=...
//     → 단일 Pod 결과 조회
//
//   GET  /api/v1/scoring/attack-path/clusters/:cluster_name
//     → 클러스터 전체 결과 조회 (위험도 정렬)
type AttackPathHandler struct {
	service *service.AttackPathService
}

// NewAttackPathHandler는 AttackPathHandler를 생성합니다.
func NewAttackPathHandler(svc *service.AttackPathService) *AttackPathHandler {
	return &AttackPathHandler{service: svc}
}

// Compute : POST /api/v1/scoring/attack-path/compute
func (h *AttackPathHandler) Compute(c *gin.Context) {
	var req scoring.AttackPathComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	response, err := h.service.ComputeForCluster(ctx, req.ClusterName)
	if err != nil {
		fmt.Printf("warn: attack-path compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// GetByPod : GET /api/v1/scoring/attack-path/pods/:pod_uid?cluster=<name>
func (h *AttackPathHandler) GetByPod(c *gin.Context) {
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
		fmt.Printf("warn: attack-path get by pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "attack-path result not found",
			"hint":    "POST /api/v1/scoring/attack-path/compute first",
			"pod_uid": podUID,
			"cluster": clusterName,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByCluster : GET /api/v1/scoring/attack-path/clusters/:cluster_name
func (h *AttackPathHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	ctx := c.Request.Context()
	results, err := h.service.ListByCluster(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: attack-path list by cluster failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	high, medium, low := 0, 0, 0
	for _, r := range results {
		switch {
		case r.TotalScore >= 70:
			high++
		case r.TotalScore >= 40:
			medium++
		case r.TotalScore > 0:
			low++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name": clusterName,
		"total":        len(results),
		"high_risk":    high,
		"medium_risk":  medium,
		"low_risk":     low,
		"results":      results,
	})
}
