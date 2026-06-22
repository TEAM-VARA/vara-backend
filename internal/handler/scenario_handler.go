package handler

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/vara/backend/internal/service"
)

// ScenarioHandler — 공격 시나리오 줄글 + 보완대책 줄글 API.
//
// 엔드포인트:
//
//	GET /api/v1/scoring/scenarios/pods/:pod_uid?cluster=<name>&company_id=<id>
//	  → 단일 Pod의 공격 시나리오 줄글 + 보완대책 줄글 (pod risk 페이지용)
//	  company_id 있으면 ISMS-P 가산 차감(isms_reduction)까지 포함, 없으면 생략.
//
// 라우터 등록 (internal/server/router.go, attack-path 그룹 근처):
//
//	scenarioH := handler.NewScenarioHandler(scenarioSvc)
//	api.GET("/scoring/scenarios/pods/:pod_uid", scenarioH.GetByPod)
//
// 와이어링 (cmd/server):
//
//	scenarioSvc := service.NewScenarioService(attackPathSvc)
//	scenarioH   := handler.NewScenarioHandler(scenarioSvc)
type ScenarioHandler struct {
	service *service.ScenarioService
}

func NewScenarioHandler(svc *service.ScenarioService) *ScenarioHandler {
	return &ScenarioHandler{service: svc}
}

// GetByPod : GET /api/v1/scoring/scenarios/pods/:pod_uid?cluster=<name>
func (h *ScenarioHandler) GetByPod(c *gin.Context) {
	podUID := c.Param("pod_uid")
	cluster := c.Query("cluster")
	companyID := c.Query("company_id") // 선택: 있으면 ISMS-P 가산 차감까지 계산, 없으면 생략
	if podUID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pod_uid is required"})
		return
	}
	if cluster == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cluster query parameter is required"})
		return
	}

	res, err := h.service.BuildForPod(c.Request.Context(), companyID, cluster, podUID)
	if err != nil {
		fmt.Printf("warn: scenario build failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if res == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "scenario not available",
			"hint":    "POST /api/v1/scoring/attack-path/compute 먼저 실행",
			"pod_uid": podUID,
			"cluster": cluster,
		})
		return
	}

	c.JSON(http.StatusOK, res)
}
