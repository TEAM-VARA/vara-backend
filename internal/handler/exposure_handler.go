package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/domain/scoring"
	"github.com/vara/backend/internal/service"
)

// ExposureHandler는 인터넷 노출(Internet Exposure) 점수 API를 담당합니다.
//
// 엔드포인트:
//
//	GET  /api/v1/scoring/exposure/pods/:pod_uid?cluster=<name>
//	  → 단일 Pod의 최근 노출 결과 조회 (DB)
//
//	GET  /api/v1/scoring/exposure/clusters/:cluster_name
//	  → 클러스터의 최신 snapshot 결과 일괄 조회 (DB)
//
//	POST /api/v1/scoring/exposure/compute
//	  Body: { "cluster_name": "..." }
//	  → 최신 snapshot으로 계산 후 DB 저장
//	  → 응답: 요약 + 상세
type ExposureHandler struct {
	service *service.ExposureService
}

// NewExposureHandler는 ExposureHandler를 생성합니다.
func NewExposureHandler(svc *service.ExposureService) *ExposureHandler {
	return &ExposureHandler{service: svc}
}

// GetByPod : GET /api/v1/scoring/exposure/pods/:pod_uid?cluster=<name>
//
// 단일 Pod의 최근 노출 결과 조회.
// cluster 쿼리 파라미터로 클러스터 지정.
func (h *ExposureHandler) GetByPod(c *gin.Context) {
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
		fmt.Printf("warn: exposure get by pod failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if result == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "exposure result not found for the given pod",
			"hint":    "POST /api/v1/scoring/exposure/compute first",
			"pod_uid": podUID,
			"cluster": clusterName,
		})
		return
	}

	c.JSON(http.StatusOK, result)
}

// GetByCluster : GET /api/v1/scoring/exposure/clusters/:cluster_name
//
// 클러스터의 최신 snapshot 결과 일괄 조회.
// 노출된 Pod이 먼저 정렬됨 (대시보드용).
func (h *ExposureHandler) GetByCluster(c *gin.Context) {
	clusterName := c.Param("cluster_name")
	if clusterName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster_name is required"})
		return
	}

	ctx := c.Request.Context()
	results, err := h.service.ListByCluster(ctx, clusterName)
	if err != nil {
		fmt.Printf("warn: exposure list by cluster failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 요약 통계 계산
	exposedCount := 0
	for _, r := range results {
		if r.Exposed {
			exposedCount++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster_name": clusterName,
		"total":        len(results),
		"exposed":      exposedCount,
		"not_exposed":  len(results) - exposedCount,
		"results":      results,
	})
}

// Compute : POST /api/v1/scoring/exposure/compute
//
// 클러스터의 최신 snapshot 데이터로 인터넷 노출도를 계산하고 DB에 저장.
// 응답에 요약 + 각 Pod별 결과 포함.
//
// 일반적인 호출 흐름:
//  1. cluster-reader agent가 주기적으로 snapshot 수집 (자동)
//  2. 본 API 호출 → 최신 snapshot으로 노출도 재계산
//  3. 결과는 exposure_scores 테이블에 영속화
//  4. 이후 GET API로 조회 가능
//
// 본 API는 동기적으로 동작합니다. 클러스터가 크면 시간이 걸릴 수 있으므로,
// 추후 비동기/큐 기반으로 전환 검토.
func (h *ExposureHandler) Compute(c *gin.Context) {
	var req scoring.ComputeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	response, err := h.service.ComputeForCluster(ctx, req.ClusterName)
	if err != nil {
		fmt.Printf("warn: exposure compute failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, response)
}

// ComputeForPod는 단일 Pod의 exposure를 즉시 재계산합니다.
// 대시보드에서 특정 Pod 클릭 시 호출되는 빠른 API.
func (h *ExposureHandler) ComputeForPod(c *gin.Context) {
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
		fmt.Printf("warn: exposure compute pod failed: %v\n", err)
		// pod not found는 404로 응답하면 더 좋지만, 일단 500으로 처리
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}
