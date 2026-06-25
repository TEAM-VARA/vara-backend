package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vara/backend/internal/repository/postgres"
	"github.com/vara/backend/internal/service"
)

// AnalysisHandler는 사전 계산된 그래프 분석 캐시를 조회합니다.
type AnalysisHandler struct {
	cacheRepo   *postgres.AnalysisCacheRepo
	analysisSvc *service.AnalysisService
}

func NewAnalysisHandler(cacheRepo *postgres.AnalysisCacheRepo, analysisSvc *service.AnalysisService) *AnalysisHandler {
	return &AnalysisHandler{cacheRepo: cacheRepo, analysisSvc: analysisSvc}
}

// GetBlastRadius — 캐시된 Pod 영향 범위
// GET /analysis/blast-radius?cluster=&pod=
func (h *AnalysisHandler) GetBlastRadius(c *gin.Context) {
	cluster := c.DefaultQuery("cluster", "vara-eks-test")
	pod := c.Query("pod")
	if pod == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod query param required"})
		return
	}

	row, err := h.cacheRepo.GetBlastRadius(c.Request.Context(), cluster, pod)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if row == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not computed yet",
			"code":    "NOT_COMPUTED",
			"pod_uid": pod,
			"cluster": cluster,
		})
		return
	}
	c.JSON(http.StatusOK, row)
}

// GetCentrality — PageRank + Betweenness 상위 N
// GET /analysis/centrality?cluster=&top=&sort=(pagerank|betweenness)
func (h *AnalysisHandler) GetCentrality(c *gin.Context) {
	cluster := c.DefaultQuery("cluster", "vara-eks-test")

	topN := 20
	if t := c.Query("top"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 {
			topN = n
		}
	}

	var rows []postgres.CentralityRow
	var err error
	if c.Query("sort") == "betweenness" {
		rows, err = h.cacheRepo.GetTopByBetweenness(c.Request.Context(), cluster, topN)
	} else {
		rows, err = h.cacheRepo.GetTopByPageRank(c.Request.Context(), cluster, topN)
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster": cluster,
		"sort_by":  c.DefaultQuery("sort", "pagerank"),
		"count":   len(rows),
		"nodes":   rows,
	})
}

// GetAttackPaths — Dijkstra 최단 공격 경로 (cost 오름차순)
// GET /analysis/attack-paths?cluster=&limit=
func (h *AnalysisHandler) GetAttackPaths(c *gin.Context) {
	cluster := c.DefaultQuery("cluster", "vara-eks-test")

	rows, err := h.cacheRepo.GetAttackPaths(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	limit := 50
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}

	c.JSON(http.StatusOK, gin.H{
		"cluster": cluster,
		"count":   len(rows),
		"paths":   rows,
	})
}

// Refresh — 데이터 변경 시에만 재계산
// POST /api/v1/analysis/refresh?cluster=
func (h *AnalysisHandler) Refresh(c *gin.Context) {
	cluster := c.DefaultQuery("cluster", "vara-eks-test")
	recomputed, err := h.analysisSvc.PrecomputeIfStale(c.Request.Context(), cluster)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"cluster":    cluster,
		"recomputed": recomputed, // true=새로계산, false=캐시그대로
	})
}
